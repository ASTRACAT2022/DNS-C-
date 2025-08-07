#include <iostream>
#include <unordered_map>
#include <list>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <functional>
#include <condition_variable>
#include <shared_mutex>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ldns/ldns.h>
#include <chrono>
#include <atomic>
#include <csignal>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <iomanip>

// --- Константы и глобальные переменные ---
#define MAX_EVENTS 1024
#define CACHE_SIZE 10000
#define THREAD_POOL_SIZE 8
#define PORT 5313
#define MAX_PACKET_SIZE 65536
#define CACHE_TTL 3600 // 1 час
#define CLEANUP_INTERVAL 10 // 10 секунд для фоновой очистки

static std::atomic<bool> g_stop_signal_received = false;
static std::mutex log_mutex;

// Простая функция для централизованного логирования
void log(const std::string& message, const std::string& level = "INFO") {
    if (level == "INFO" || level == "DEBUG") {
        return; // Игнорируем информационные логи
    }
    std::lock_guard<std::mutex> lock(log_mutex);
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::cerr << "[" << level << "] " << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << ": " << message << std::endl;
}

// --- RAII-обертка для файловых дескрипторов ---
class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) : fd_(fd) {}
    ~FileDescriptor() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    int get() const { return fd_; }
private:
    int fd_;
};

// --- Метрики ---
class Metrics {
public:
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    std::atomic<uint64_t> dns_errors{0};
    std::atomic<uint64_t> send_errors{0};
};

// --- LRU Cache для DNS-ответов с фоновой очисткой ---
class LRUCache {
private:
    struct CacheEntry {
        std::string key;
        std::shared_ptr<ldns_pkt> pkt;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, std::list<CacheEntry>::iterator> cache_map;
    std::list<CacheEntry> cache_list;
    size_t capacity;
    std::shared_mutex mutex;
    std::thread cleaner_thread;
    std::atomic<bool> stop_cleaner{false};
    std::condition_variable_any cleaner_cv;

    void cleanup_expired_entries() {
        while (!stop_cleaner) {
            std::unique_lock<std::shared_mutex> lock(mutex);
            cleaner_cv.wait_for(lock, std::chrono::seconds(CLEANUP_INTERVAL), [this](){ return stop_cleaner.load(); });
            if (stop_cleaner) break;
            
            auto it = cache_list.begin();
            while (it != cache_list.end()) {
                if (std::chrono::steady_clock::now() - it->timestamp > std::chrono::seconds(CACHE_TTL)) {
                    cache_map.erase(it->key);
                    it = cache_list.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

public:
    explicit LRUCache(size_t cap) : capacity(cap) {
        cleaner_thread = std::thread(&LRUCache::cleanup_expired_entries, this);
    }
    ~LRUCache() {
        stop_cleaner = true;
        cleaner_cv.notify_one();
        if (cleaner_thread.joinable()) {
            cleaner_thread.join();
        }
    }

    std::shared_ptr<ldns_pkt> get(const std::string& key) {
        std::unique_lock<std::shared_mutex> lock(mutex);
        auto it = cache_map.find(key);
        if (it == cache_map.end()) return nullptr;

        auto& entry = *(it->second);
        if (std::chrono::steady_clock::now() - entry.timestamp > std::chrono::seconds(CACHE_TTL)) {
            cache_map.erase(it);
            cache_list.erase(it->second);
            return nullptr;
        }
        
        cache_list.splice(cache_list.begin(), cache_list, it->second);
        entry.timestamp = std::chrono::steady_clock::now();
        return entry.pkt;
    }

    void put(const std::string& key, ldns_pkt* pkt) {
        std::unique_lock<std::shared_mutex> lock(mutex);
        auto it = cache_map.find(key);
        
        ldns_pkt* new_pkt_clone = ldns_pkt_clone(pkt);
        if (!new_pkt_clone) {
            log("Ошибка клонирования DNS-пакета для кеша", "ERROR");
            return;
        }

        if (it != cache_map.end()) {
            cache_map.erase(it);
            cache_list.erase(it->second);
        }

        CacheEntry entry{key, std::shared_ptr<ldns_pkt>(new_pkt_clone, ldns_pkt_free), std::chrono::steady_clock::now()};
        cache_list.push_front(entry);
        cache_map[key] = cache_list.begin();

        if (cache_list.size() > capacity) {
            auto last_it = cache_list.end();
            --last_it;
            cache_map.erase(last_it->key); 
            cache_list.pop_back();
        }
    }
};

// --- Пул потоков ---
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};

public:
    ThreadPool(size_t threads) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop) return;
            tasks.emplace(std::move(task));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
};

// --- Класс DNS-резолвера ---
class DNSResolver {
private:
    FileDescriptor sockfd;
    FileDescriptor epoll_fd;
    LRUCache cache;
    ThreadPool pool;
    std::atomic<bool> running{true};
    Metrics metrics;
    using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, decltype(&ldns_pkt_free)>;
    using ldns_resolver_ptr = std::unique_ptr<ldns_resolver, decltype(&ldns_resolver_deep_free)>;
    using c_char_ptr = std::unique_ptr<char, decltype(&free)>;

public:
    DNSResolver() : cache(CACHE_SIZE), pool(THREAD_POOL_SIZE) {
        int temp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (temp_sockfd < 0) {
            throw std::runtime_error("Не удалось создать сокет");
        }
        sockfd = FileDescriptor(temp_sockfd);

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(sockfd.get(), (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Не удалось привязать сокет");
        }

        int temp_epoll_fd = epoll_create1(0);
        if (temp_epoll_fd < 0) {
            throw std::runtime_error("Не удалось создать epoll");
        }
        epoll_fd = FileDescriptor(temp_epoll_fd);

        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = sockfd.get();
        if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_ADD, sockfd.get(), &ev) < 0) {
            throw std::runtime_error("Не удалось добавить сокет в epoll");
        }
    }

    void handle_query(int client_sock, sockaddr_in client_addr, socklen_t addr_len, const std::vector<uint8_t>& request_data) {
        thread_local ldns_resolver_ptr resolver(nullptr, &ldns_resolver_deep_free);
        if (!resolver) {
            
            // --- ИСПРАВЛЕННЫЙ БЛОК КОДА ДЛЯ ИСПОЛЬЗОВАНИЯ 1.1.1.1 ---
            ldns_resolver* res_ptr = ldns_resolver_new();
            if (!res_ptr) {
                log("Ошибка в потоке: не удалось создать ldns_resolver.", "ERROR");
                return;
            }

            ldns_rdf* nameserver_rdf = nullptr;
            ldns_status status_rdf = ldns_str2rdf_a(&nameserver_rdf, "1.1.1.1");
            if (status_rdf != LDNS_STATUS_OK || !nameserver_rdf) {
                log("Ошибка: не удалось преобразовать 1.1.1.1 в RDF", "ERROR");
                ldns_resolver_deep_free(res_ptr);
                return;
            }

            ldns_rr* nameserver_rr = ldns_rr_new();
            if (!nameserver_rr) {
                log("Ошибка: не удалось создать RR для nameserver.", "ERROR");
                ldns_rdf_free(nameserver_rdf);
                ldns_resolver_deep_free(res_ptr);
                return;
            }

            ldns_rr_set_owner(nameserver_rr, ldns_dname_new_frm_str("."));
            ldns_rr_set_type(nameserver_rr, LDNS_RR_TYPE_A);
            ldns_rr_set_class(nameserver_rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_ttl(nameserver_rr, 0);
            ldns_rr_set_rdf(nameserver_rr, nameserver_rdf, 0);

            ldns_resolver_push_nameserver_rr(res_ptr, nameserver_rr);
            ldns_rr_free(nameserver_rr);
            
            ldns_resolver_set_recursive(res_ptr, true);
            resolver.reset(res_ptr);
            // --- КОНЕЦ ИСПРАВЛЕННОГО БЛОКА ---
        }

        ldns_pkt_ptr query_pkt(nullptr, &ldns_pkt_free);
        ldns_pkt* temp_query_pkt = nullptr;
        if (ldns_wire2pkt(&temp_query_pkt, request_data.data(), request_data.size()) != LDNS_STATUS_OK) {
            log("Ошибка парсинга DNS-запроса", "ERROR");
            return;
        }
        query_pkt.reset(temp_query_pkt);

        ldns_rr_list* question = ldns_pkt_question(query_pkt.get());
        if (!question || ldns_rr_list_rr_count(question) == 0) {
            log("Пустой список вопросов в DNS-запросе", "WARN");
            return;
        }
        
        ldns_rr* rr = ldns_rr_list_rr(question, 0);
        ldns_rdf* name = ldns_rr_owner(rr);
        ldns_rr_type type = ldns_rr_get_type(rr);
        uint16_t query_id = ldns_pkt_id(query_pkt.get());

        c_char_ptr qname_str_uptr(ldns_rdf2str(name), &free);
        if (!qname_str_uptr) {
            log("Не удалось получить имя запроса", "ERROR");
            return;
        }
        std::string query_key = std::string(qname_str_uptr.get()) + "_" + std::to_string(type);

        if (auto cached_response = cache.get(query_key)) {
            metrics.cache_hits++;
            ldns_pkt_set_id(cached_response.get(), query_id);
            send_packet(client_sock, client_addr, addr_len, cached_response.get());
            return;
        }

        metrics.cache_misses++;
        ldns_pkt_ptr response_pkt(nullptr, &ldns_pkt_free);
        ldns_pkt* temp_response_pkt = nullptr;
        ldns_status status = ldns_resolver_send_pkt(&temp_response_pkt, resolver.get(), query_pkt.get());
        response_pkt.reset(temp_response_pkt);
        
        if (status == LDNS_STATUS_OK && response_pkt) {
            if (ldns_pkt_answer(response_pkt.get()) && ldns_rr_list_rr_count(ldns_pkt_answer(response_pkt.get())) > 0) {
                 cache.put(query_key, response_pkt.get());
            }
            send_packet(client_sock, client_addr, addr_len, response_pkt.get());
        } else {
            metrics.dns_errors++;
            log("Ошибка выполнения DNS-запроса: " + std::string(ldns_get_errorstr_by_id(status)), "ERROR");
        }
    }

    void send_packet(int client_sock, sockaddr_in client_addr, socklen_t addr_len, ldns_pkt* packet) {
        using wire_buf_ptr = std::unique_ptr<uint8_t, decltype(&free)>;
        uint8_t* wire_response = nullptr;
        size_t wire_len = 0;
        if (ldns_pkt2wire(&wire_response, packet, &wire_len) == LDNS_STATUS_OK) {
            wire_buf_ptr wire_response_uptr(wire_response, &free);
            ssize_t bytes_sent = sendto(client_sock, wire_response_uptr.get(), wire_len, 0, (sockaddr*)&client_addr, addr_len);
            if (bytes_sent < 0) {
                metrics.send_errors++;
                log("Ошибка отправки ответа: " + std::string(strerror(errno)), "ERROR");
            } else if ((size_t)bytes_sent != wire_len) {
                log("Отправлены не все данные: " + std::to_string(bytes_sent) + " из " + std::to_string(wire_len), "WARN");
            }
        } else {
            log("Ошибка преобразования пакета в wire-формат", "ERROR");
        }
    }

    void run() {
        epoll_event events[MAX_EVENTS];
        std::vector<uint8_t> buffer(MAX_PACKET_SIZE);
        
        while (running && !g_stop_signal_received) {
            int nfds = epoll_wait(epoll_fd.get(), events, MAX_EVENTS, 1000);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                log("Ошибка epoll: " + std::string(strerror(errno)), "ERROR");
                continue;
            }

            for (int i = 0; i < nfds; ++i) {
                if (events[i].data.fd == sockfd.get()) {
                    sockaddr_in client_addr{};
                    socklen_t addr_len = sizeof(client_addr);
                    ssize_t len = recvfrom(sockfd.get(), buffer.data(), buffer.size(), 0, (sockaddr*)&client_addr, &addr_len);
                    if (len > 0) {
                         if ((size_t)len > MAX_PACKET_SIZE) {
                            log("Получен слишком большой пакет (" + std::to_string(len) + " байт), игнорирую.", "WARN");
                            continue;
                        }
                        std::vector<uint8_t> request_data(buffer.begin(), buffer.begin() + len);
                        pool.enqueue([this, sock = sockfd.get(), client_addr, addr_len, data = std::move(request_data)]() {
                            handle_query(sock, client_addr, addr_len, data);
                        });
                    } else if (len < 0) {
                        log("Ошибка recvfrom: " + std::string(strerror(errno)), "ERROR");
                    }
                }
            }
        }

        std::cout << "---" << std::endl;
        std::cout << "Финальные метрики:" << std::endl;
        std::cout << "Кеш попаданий: " << metrics.cache_hits << std::endl;
        std::cout << "Кеш промахов: " << metrics.cache_misses << std::endl;
        std::cout << "Ошибок DNS-разрешения: " << metrics.dns_errors << std::endl;
        std::cout << "Ошибок отправки: " << metrics.send_errors << std::endl;
        std::cout << "---" << std::endl;
    }

    void stop() {
        running = false;
    }

    ~DNSResolver() {
    }
};

void signal_handler(int) {
    g_stop_signal_received = true;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        DNSResolver resolver;
        std::cout << "DNS-резолвер The ASTRAnet запущен на порту " << PORT << std::endl;
        resolver.run();
    } catch (const std::exception& e) {
        log("Критическая ошибка: " + std::string(e.what()), "FATAL");
        return 1;
    }
    
    std::cout << "DNS-резолвер The ASTRAnet штатно остановлен." << std::endl;
    return 0;
}
