#include <ldns/ldns.h>
#include <uv.h>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <ctime>

// Структура кэша
struct CacheEntry {
    ldns_pkt* packet;
    time_t expiry;
};

// Глобальные переменные
std::unordered_map<std::string, CacheEntry> dns_cache;
std::mutex cache_mutex;

// Конфигурация
const char* BIND_ADDRESS = "0.0.0.0";
const int BIND_PORT = 53; // Измените на нужный порт, например, 5311 для тестов
const int THREAD_COUNT = 8; // Количество потоков
const int CACHE_TTL = 3600; // TTL кэша в секундах
const int MAX_RETRIES = 3; // Максимум повторных попыток

// Список корневых серверов (упрощён, используйте полный список в продакшене)
const char* ROOT_SERVERS[] = {
    "198.41.0.4", // a.root-servers.net
    "192.228.79.201", // b.root-servers.net
};

// Генерация ключа для кэша
std::string make_cache_key(ldns_pkt* query) {
    ldns_rr* qrr = ldns_rr_list_rr(ldns_pkt_question(query), 0);
    char* owner_str = ldns_rdf2str(ldns_rr_owner(qrr));
    std::string key = std::string(owner_str) + std::to_string(ldns_rr_get_type(qrr));
    free(owner_str);
    return key;
}

// Поиск в кэше
bool cache_lookup(const std::string& key, ldns_pkt** response) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = dns_cache.find(key);
    if (it != dns_cache.end() && it->second.expiry > time(nullptr)) {
        *response = ldns_pkt_clone(it->second.packet);
        return true;
    }
    return false;
}

// Сохранение в кэш
void cache_store(const std::string& key, ldns_pkt* pkt) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    CacheEntry entry;
    entry.packet = ldns_pkt_clone(pkt);
    entry.expiry = time(nullptr) + CACHE_TTL;
    dns_cache[key] = entry;

    // Очистка устаревших записей
    for (auto it = dns_cache.begin(); it != dns_cache.end();) {
        if (it->second.expiry <= time(nullptr)) {
            ldns_pkt_free(it->second.packet);
            it = dns_cache.erase(it);
        } else {
            ++it;
        }
    }
}

// Рекурсивное разрешение
ldns_pkt* resolve_recursive(ldns_pkt* query, const char* upstream = nullptr) {
    ldns_resolver* res = nullptr;
    ldns_pkt* response = nullptr;
    ldns_status status;

    status = ldns_resolver_new_frm_file(&res, nullptr); // Используем стандартные корневые серверы
    if (status != LDNS_STATUS_OK) return nullptr;

    if (upstream) {
        ldns_rdf* addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, upstream);
        ldns_resolver_push_nameserver(res, addr);
        ldns_rdf_free(addr);
    }

    ldns_rr* qrr = ldns_rr_list_rr(ldns_pkt_question(query), 0);
    for (int i = 0; i < MAX_RETRIES; ++i) {
        response = ldns_resolver_query(res, ldns_rr_owner(qrr),
                                      ldns_rr_get_type(qrr),
                                      ldns_rr_get_class(qrr),
                                      LDNS_RD);
        if (response) break;
        std::cerr << "Retry " << i + 1 << " for query\n";
    }

    ldns_resolver_deep_free(res);
    return response;
}

// Обработка запроса клиента
void handle_query(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                  const struct sockaddr* addr, unsigned flags) {
    if (nread <= 0) return;

    ldns_pkt* query = nullptr;
    ldns_buffer* pkt_buf = ldns_buffer_new(nread);
    ldns_buffer_write(pkt_buf, (uint8_t*)buf->base, nread);
    ldns_buffer_flip(pkt_buf);

    if (ldns_buffer2pkt_wire(&query, pkt_buf) != LDNS_STATUS_OK) {
        ldns_buffer_free(pkt_buf);
        return;
    }
    ldns_buffer_free(pkt_buf);

    uint16_t query_id = ldns_pkt_id(query); // Сохраняем ID запроса
    std::string cache_key = make_cache_key(query);
    ldns_pkt* response = nullptr;

    if (cache_lookup(cache_key, &response)) {
        // Кэш найден
        ldns_pkt_set_id(response, query_id); // Устанавливаем правильный ID
    } else {
        // Рекурсивное разрешение
        response = resolve_recursive(query);
        if (response) {
            ldns_pkt_set_id(response, query_id); // Устанавливаем правильный ID
            cache_store(cache_key, response);
        }
    }

    if (response) {
        ldns_buffer* out_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
        if (ldns_pkt2buffer_wire(out_buf, response) == LDNS_STATUS_OK) {
            uv_buf_t send_buf = uv_buf_init((char*)ldns_buffer_begin(out_buf), ldns_buffer_position(out_buf));
            uv_udp_send_t* req = new uv_udp_send_t;
            req->data = out_buf;
            uv_udp_send(req, handle, &send_buf, 1, addr, [](uv_udp_send_t* req, int status) {
                ldns_buffer_free((ldns_buffer*)req->data);
                delete req;
            });
        } else {
            ldns_buffer_free(out_buf);
        }
        ldns_pkt_free(response);
    }

    ldns_pkt_free(query);
    delete[] buf->base; // Освобождаем буфер
}

// Выделение буфера
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

// Рабочий поток
void worker_thread(uv_loop_t* loop) {
    uv_run(loop, UV_RUN_DEFAULT);
}

int main() {
    uv_loop_t* main_loop = uv_default_loop();

    // Инициализация UDP-сервера
    uv_udp_t server;
    uv_udp_init(main_loop, &server);

    struct sockaddr_in bind_addr;
    uv_ip4_addr(BIND_ADDRESS, BIND_PORT, &bind_addr);
    uv_udp_bind(&server, (const struct sockaddr*)&bind_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&server, alloc_buffer, handle_query);

    // Создание пула потоков
    std::vector<std::thread> threads;
    for (int i = 0; i < THREAD_COUNT - 1; ++i) {
        uv_loop_t* worker_loop = uv_loop_new();
        uv_udp_t* worker_server = new uv_udp_t;
        uv_udp_init(worker_loop, worker_server);
        uv_udp_bind(worker_server, (const struct sockaddr*)&bind_addr, UV_UDP_REUSEADDR);
        uv_udp_recv_start(worker_server, alloc_buffer, handle_query);
        threads.emplace_back(worker_thread, worker_loop);
    }

    // Запуск основного цикла
    uv_run(main_loop, UV_RUN_DEFAULT);

    // Очистка
    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
