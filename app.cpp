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

#define MAX_EVENTS 1024
#define CACHE_SIZE 10000
#define THREAD_POOL_SIZE 8
#define PORT 5314
#define MAX_PACKET_SIZE 65536
#define CACHE_TTL 3600

static std::atomic<bool> g_stop_signal_received = false;

// LRU Cache для DNS-ответов
class LRUCache {
private:
    struct CacheEntry {
        std::string key;
        ldns_pkt* pkt;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, std::list<CacheEntry>::iterator> cache_map;
    std::list<CacheEntry> cache_list;
    size_t capacity;
    std::mutex mutex;

public:
    explicit LRUCache(size_t cap) : capacity(cap) {}

    ldns_pkt* get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = cache_map.find(key);
        if (it == cache_map.end()) return nullptr;

        auto& entry = *(it->second);
        if (std::chrono::steady_clock::now() - entry.timestamp > std::chrono::seconds(CACHE_TTL)) {
            ldns_pkt_free(entry.pkt);
            cache_map.erase(it);
            cache_list.erase(it->second);
            return nullptr;
        }
        
        cache_list.splice(cache_list.begin(), cache_list, it->second);
        return entry.pkt;
    }

    void put(const std::string& key, ldns_pkt* pkt) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = cache_map.find(key);
        if (it != cache_map.end()) {
            ldns_pkt_free(it->second->pkt);
            cache_list.erase(it->second);
        }

        CacheEntry entry{key, pkt, std::chrono::steady_clock::now()};
        cache_list.push_front(entry);
        cache_map[key] = cache_list.begin();

        if (cache_list.size() > capacity) {
            auto last_it = cache_list.end();
            --last_it;
            
            cache_map.erase(last_it->key); 
            ldns_pkt_free(last_it->pkt);
            cache_list.pop_back();
        }
    }
};

// Пул потоков
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
            worker.join();
        }
    }
};

// Класс DNS-резолвера
class DNSResolver {
private:
    int sockfd;
    int epoll_fd;
    LRUCache cache;
    ThreadPool pool;
    std::atomic<bool> running{true};
    using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, decltype(&ldns_pkt_free)>;
    using c_char_ptr = std::unique_ptr<char, decltype(&free)>;

public:
    DNSResolver() : cache(CACHE_SIZE), pool(THREAD_POOL_SIZE) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            throw std::runtime_error("Не удалось создать сокет");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sockfd);
            throw std::runtime_error("Не удалось привязать сокет");
        }

        epoll_fd = epoll_create1(0);
        if (epoll_fd < 0) {
            close(sockfd);
            throw std::runtime_error("Не удалось создать epoll");
        }

        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = sockfd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
            close(sockfd);
            close(epoll_fd);
            throw std::runtime_error("Не удалось добавить сокет в epoll");
        }
    }

    void handle_query(int client_sock, sockaddr_in client_addr, socklen_t addr_len, const std::vector<uint8_t>& request_data) {
        thread_local std::unique_ptr<ldns_resolver, decltype(&ldns_resolver_deep_free)> resolver(nullptr, &ldns_resolver_deep_free);
        if (!resolver) {
            ldns_resolver* res_ptr = nullptr;
            ldns_status res_status = ldns_resolver_new_frm_file(&res_ptr, nullptr);
            if (res_status != LDNS_STATUS_OK) {
                std::cerr << "Ошибка в потоке: не удалось создать ldns_resolver: " << ldns_get_errorstr_by_id(res_status) << std::endl;
                return;
            }
            ldns_resolver_set_recursive(res_ptr, true);
            resolver.reset(res_ptr);
        }

        ldns_pkt_ptr query_pkt(nullptr, &ldns_pkt_free);
        ldns_pkt* temp_query_pkt = nullptr;
        if (ldns_wire2pkt(&temp_query_pkt, request_data.data(), request_data.size()) != LDNS_STATUS_OK) {
            std::cerr << "Ошибка парсинга DNS-запроса" << std::endl;
            return;
        }
        query_pkt.reset(temp_query_pkt);

        ldns_rr_list* question = ldns_pkt_question(query_pkt.get());
        if (!question || ldns_rr_list_rr_count(question) == 0) {
            std::cerr << "Пустой список вопросов в DNS-запросе" << std::endl;
            return;
        }
        
        ldns_rr* rr = ldns_rr_list_rr(question, 0);
        ldns_rdf* name = ldns_rr_owner(rr);
        ldns_rr_type type = ldns_rr_get_type(rr);
        uint16_t query_id = ldns_pkt_id(query_pkt.get());

        c_char_ptr qname_str_uptr(ldns_rdf2str(name), &free);
        if (!qname_str_uptr) {
            std::cerr << "Не удалось получить имя запроса" << std::endl;
            return;
        }
        std::string query_key = std::string(qname_str_uptr.get()) + "_" + std::to_string(type);

        if (ldns_pkt* cached_response = cache.get(query_key)) {
            ldns_pkt_set_id(cached_response, query_id);
            send_packet(client_sock, client_addr, addr_len, cached_response);
            return;
        }

        // ⚠️ ИСПРАВЛЕННАЯ СТРОКА: Убрал лишний аргумент '0'
        ldns_pkt_ptr response_pkt(nullptr, &ldns_pkt_free);
        ldns_pkt* temp_response_pkt = nullptr;
        ldns_status status = ldns_resolver_send_pkt(&temp_response_pkt, resolver.get(), query_pkt.get());
        response_pkt.reset(temp_response_pkt);
        
        if (status == LDNS_STATUS_OK && response_pkt) {
            if (ldns_pkt_answer(response_pkt.get()) && ldns_rr_list_rr_count(ldns_pkt_answer(response_pkt.get())) > 0) {
                 ldns_pkt* cloned_pkt = ldns_pkt_clone(response_pkt.get());
                 if (cloned_pkt) {
                     cache.put(query_key, cloned_pkt);
                 }
            }
            send_packet(client_sock, client_addr, addr_len, response_pkt.get());
        } else {
            std::cerr << "Ошибка выполнения DNS-запроса: " << ldns_get_errorstr_by_id(status) << std::endl;
        }
    }

    void send_packet(int client_sock, sockaddr_in client_addr, socklen_t addr_len, ldns_pkt* packet) {
        using wire_buf_ptr = std::unique_ptr<uint8_t, decltype(&free)>;
        uint8_t* wire_response = nullptr;
        size_t wire_len = 0;
        if (ldns_pkt2wire(&wire_response, packet, &wire_len) == LDNS_STATUS_OK) {
            wire_buf_ptr wire_response_uptr(wire_response, &free);
            if (sendto(client_sock, wire_response_uptr.get(), wire_len, 0, (sockaddr*)&client_addr, addr_len) < 0) {
                std::cerr << "Ошибка отправки ответа: " << strerror(errno) << std::endl;
            }
        } else {
            std::cerr << "Ошибка преобразования пакета в wire-формат" << std::endl;
        }
    }

    void run() {
        epoll_event events[MAX_EVENTS];
        uint8_t buffer[MAX_PACKET_SIZE];
        
        while (running && !g_stop_signal_received) {
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                std::cerr << "Ошибка epoll: " << strerror(errno) << std::endl;
                continue;
            }

            for (int i = 0; i < nfds; ++i) {
                if (events[i].data.fd == sockfd) {
                    sockaddr_in client_addr{};
                    socklen_t addr_len = sizeof(client_addr);
                    ssize_t len = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, (sockaddr*)&client_addr, &addr_len);
                    if (len > 0) {
                        std::vector<uint8_t> request_data(buffer, buffer + len);
                        pool.enqueue([this, sock = sockfd, client_addr, addr_len, data = std::move(request_data)]() {
                            handle_query(sock, client_addr, addr_len, data);
                        });
                    } else if (len < 0) {
                        std::cerr << "Ошибка recvfrom: " << strerror(errno) << std::endl;
                    }
                }
            }
        }
        std::cout << "Завершаю работу цикла run()..." << std::endl;
    }

    void stop() {
        running = false;
    }

    ~DNSResolver() {
        close(sockfd);
        close(epoll_fd);
        std::cout << "Ресурсы DNS-резолвера The ASTRAnet освобождены." << std::endl;
    }
};

void signal_handler(int) {
    std::cout << "\nПолучен сигнал, инициирую остановку..." << std::endl;
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
        std::cerr << "Критическая ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "DNS-резолвер The ASTRAnet штатно остановлен." << std::endl;
    return 0;
}
