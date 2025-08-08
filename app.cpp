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
#include <cstring>
#include <signal.h>

#define MAX_EVENTS 1024
#define MAX_PACKET_SIZE 65536
#define CACHE_SIZE 10000
#define CACHE_TTL 3600 // 1 час TTL
#define THREAD_POOL_SIZE 8
#define PORT 5312

// LRU Cache для DNS-ответов
class LRUCache {
private:
    struct CacheEntry {
        ldns_pkt* pkt;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, std::list<CacheEntry>::iterator> cache_map;
    std::list<CacheEntry> cache_list;
    size_t capacity;
    std::mutex mutex;
    int ttl_seconds;

public:
    LRUCache(size_t cap, int ttl) : capacity(cap), ttl_seconds(ttl) {}

    ldns_pkt* get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = cache_map.find(key);
        if (it == cache_map.end()) return nullptr;
        auto& entry = *(it->second);
        if (std::chrono::steady_clock::now() - entry.timestamp > std::chrono::seconds(ttl_seconds)) {
            cache_list.erase(it->second);
            cache_map.erase(it);
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
        CacheEntry entry{pkt, std::chrono::steady_clock::now()};
        cache_list.push_front(entry);
        cache_map[key] = cache_list.begin();
        if (cache_list.size() > capacity) {
            auto last = cache_list.end();
            --last;
            ldns_pkt_free(last->pkt);
            char* key_str = ldns_rdf2str(ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(last->pkt), 0)));
            cache_map.erase(key_str);
            free(key_str);
            cache_list.pop_back();
        }
    }
};

// Пул потоков для обработки DNS-запросов
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
            tasks.emplace(task);
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
    ldns_resolver* resolver;

public:
    DNSResolver() : cache(CACHE_SIZE, CACHE_TTL), pool(THREAD_POOL_SIZE) {
        // Инициализация сокета
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            throw std::runtime_error("Не удалось создать сокет: " + std::string(strerror(errno)));
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sockfd);
            throw std::runtime_error("Не удалось привязать сокет: " + std::string(strerror(errno)));
        }

        // Инициализация epoll
        epoll_fd = epoll_create1(0);
        if (epoll_fd < 0) {
            close(sockfd);
            throw std::runtime_error("Не удалось создать epoll: " + std::string(strerror(errno)));
        }

        epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = sockfd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
            close(sockfd);
            close(epoll_fd);
            throw std::runtime_error("Не удалось добавить сокет в epoll: " + std::string(strerror(errno)));
        }

        // Инициализация ldns резолвера
        if (ldns_resolver_new_frm_file(&resolver, nullptr) != LDNS_STATUS_OK) {
            close(sockfd);
            close(epoll_fd);
            throw std::runtime_error("Не удалось инициализировать ldns резолвер");
        }
        ldns_resolver_set_recursive(resolver, true);
    }

    void handle_query(int client_sock, const sockaddr_in& client_addr, socklen_t addr_len, const uint8_t* buffer, ssize_t len) {
        ldns_pkt* query_pkt = nullptr;
        if (ldns_wire2pkt(&query_pkt, buffer, len) != LDNS_STATUS_OK) {
            std::cerr << "Ошибка парсинга DNS-запроса" << std::endl;
            return;
        }

        std::string query_key;
        ldns_rr_list* question = ldns_pkt_question(query_pkt);
        ldns_rdf* name = nullptr;
        ldns_rr_type type = LDNS_RR_TYPE_A;
        ldns_rr_class cls = LDNS_RR_CLASS_IN;
        uint16_t query_id = ldns_pkt_id(query_pkt);

        if (question && ldns_rr_list_rr_count(question) > 0) {
            ldns_rr* rr = ldns_rr_list_rr(question, 0);
            name = ldns_rr_owner(rr);
            type = ldns_rr_get_type(rr);
            cls = ldns_rr_get_class(rr);
            char* qname = ldns_rdf2str(name);
            query_key = std::string(qname) + "_" + std::to_string(type);
            std::cerr << "Обработка запроса: " << qname << ", тип: " << type << ", ID: " << query_id << std::endl;
            free(qname);
        } else {
            ldns_pkt_free(query_pkt);
            std::cerr << "Пустой список вопросов в DNS-запросе" << std::endl;
            return;
        }

        ldns_pkt* cached_response = cache.get(query_key);
        if (cached_response) {
            ldns_pkt_set_id(cached_response, query_id);
            uint8_t* wire_response = nullptr;
            size_t wire_len = 0;
            if (ldns_pkt2wire(&wire_response, cached_response, &wire_len) == LDNS_STATUS_OK) {
                if (sendto(client_sock, wire_response, wire_len, 0, (sockaddr*)&client_addr, addr_len) < 0) {
                    std::cerr << "Ошибка отправки кэшированного ответа: " << strerror(errno) << std::endl;
                } else {
                    std::cerr << "Отправлен кэшированный ответ, ID: " << query_id << std::endl;
                }
                free(wire_response);
            }
            ldns_pkt_free(query_pkt);
            return;
        }

        ldns_pkt* response_pkt = nullptr;
        ldns_status status = ldns_resolver_send(&response_pkt, resolver, name, type, cls, 0);
        if (status == LDNS_STATUS_OK && response_pkt) {
            ldns_pkt_set_id(response_pkt, query_id);
            cache.put(query_key, ldns_pkt_clone(response_pkt));
            uint8_t* wire_response = nullptr;
            size_t wire_len = 0;
            if (ldns_pkt2wire(&wire_response, response_pkt, &wire_len) == LDNS_STATUS_OK) {
                if (sendto(client_sock, wire_response, wire_len, 0, (sockaddr*)&client_addr, addr_len) < 0) {
                    std::cerr << "Ошибка отправки нового ответа: " << strerror(errno) << std::endl;
                } else {
                    std::cerr << "Отправлен новый ответ, ID: " << query_id << std::endl;
                }
                free(wire_response);
            }
            ldns_pkt_free(response_pkt);
        } else {
            std::cerr << "Ошибка выполнения DNS-запроса: " << ldns_get_errorstr_by_id(status) << std::endl;
        }
        ldns_pkt_free(query_pkt);
    }

    void run() {
        epoll_event events[MAX_EVENTS];
        uint8_t buffer[MAX_PACKET_SIZE];
        while (running) {
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
            if (nfds < 0) {
                if (errno == EINTR) continue;
                std::cerr << "Ошибка epoll: " << strerror(errno) << std::endl;
                continue;
            }

            for (int i = 0; i < nfds; ++i) {
                if (events[i].data.fd == sockfd) {
                    sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    ssize_t len = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, (sockaddr*)&client_addr, &addr_len);
                    if (len < 0) {
                        std::cerr << "Ошибка получения данных: " << strerror(errno) << std::endl;
                        continue;
                    }
                    pool.enqueue([this, client_sock = sockfd, client_addr, addr_len, buffer, len]() {
                        handle_query(client_sock, client_addr, addr_len, buffer, len);
                    });
                }
            }
        }
    }

    void stop() {
        running = false;
        close(sockfd);
        close(epoll_fd);
        ldns_resolver_deep_free(resolver);
        std::cout << "Остановка DNS-резолвера The ASTRAnet..." << std::endl;
    }

    ~DNSResolver() {
        stop();
    }
};

// Обработчик сигналов для graceful shutdown
void signal_handler(int) {
    std::cout << "Остановка DNS-резолвера..." << std::endl;
    exit(0);
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        DNSResolver resolver;
        std::cout << "DNS-резолвер The ASTRAnet запущен на порту " << PORT << std::endl;
        resolver.run();
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
