#include <ldns/ldns.h>
#include <uv.h>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <ctime>
#include <xxhash.h>
#include <algorithm> // Для std::remove_if

// --------------------------------------------------------------------------------------
// Глобальные структуры и константы
// --------------------------------------------------------------------------------------

// Структура для кэширования RR
struct CacheEntry {
    ldns_rr* rr;
    time_t expiry;
};

// Кастомный хеш для unordered_map
struct XXHash {
    size_t operator()(const std::string& key) const {
        return XXH64(key.data(), key.size(), 0);
    }
};

// Глобальный кэш, защищенный мьютексом
std::unordered_map<std::string, std::vector<CacheEntry>, XXHash> global_cache;
std::mutex cache_mutex;

// Конфигурация
const char* BIND_ADDRESS = "0.0.0.0";
const int BIND_PORT = 5311; // Изменено для безопасности
const size_t UDP_BUFFER_SIZE = 4096;

// Полный список корневых серверов (для ldns_resolver)
const char* ROOT_SERVERS[] = {
    "198.41.0.4",      // a.root-servers.net
    "192.228.79.201",  // b.root-servers.net
    "192.33.4.12",     // c.root-servers.net
    "199.7.91.13",     // d.root-servers.net
    "192.203.230.10",  // e.root-servers.net
    "192.5.5.241",     // f.root-servers.net
    "192.112.36.4",    // g.root-servers.net
    "198.97.190.53",   // h.root-servers.net
    "192.36.148.17",   // i.root-servers.net
    "192.58.128.30",   // j.root-servers.net
    "193.0.14.129",    // k.root-servers.net
    "199.7.83.42",     // l.root-servers.net
    "202.12.27.33"     // m.root-servers.net
};

// Структура для передачи данных между потоками
struct WorkRequest {
    uv_udp_t* handle;
    struct sockaddr_storage addr;
    ldns_pkt* query;
    uv_buf_t buf;
};

// --------------------------------------------------------------------------------------
// Функции для работы с кэшем
// --------------------------------------------------------------------------------------

std::string make_cache_key(ldns_rr* rr) {
    char* owner_str = ldns_rdf2str(ldns_rr_owner(rr));
    if (!owner_str) return "";
    std::string key = std::string(owner_str) + std::to_string(ldns_rr_get_type(rr));
    free(owner_str);
    return key;
}

bool cache_lookup(const std::string& key, std::vector<CacheEntry>& entries) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = global_cache.find(key);
    if (it != global_cache.end()) {
        entries = it->second;
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [](const CacheEntry& e) { return e.expiry <= time(nullptr); }), entries.end());
        if (!entries.empty()) {
            it->second = entries;
            return true;
        }
        global_cache.erase(it);
    }
    return false;
}

void cache_store(const std::string& key, ldns_rr* rr) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    CacheEntry entry;
    entry.rr = ldns_rr_clone(rr);
    entry.expiry = time(nullptr) + ldns_rr_ttl(rr);
    global_cache[key].push_back(entry);
}

// --------------------------------------------------------------------------------------
// Функции для разрешения DNS
// --------------------------------------------------------------------------------------

ldns_pkt* resolve_iterative(ldns_pkt* query) {
    ldns_resolver* res = nullptr;
    ldns_status status = ldns_resolver_new_frm_file(&res, nullptr);
    if (status != LDNS_STATUS_OK) {
        return nullptr;
    }
    
    // Включение рекурсии для ldns_resolver
    ldns_resolver_set_recursive(res, true);

    ldns_rr_list* question_list = ldns_pkt_question(query);
    if (!question_list || ldns_rr_list_rr_count(question_list) == 0) {
        ldns_resolver_deep_free(res);
        return nullptr;
    }

    ldns_rr* qrr = ldns_rr_list_rr(question_list, 0);

    // ldns_resolver сам выполнит всю рекурсивную работу,
    // начиная с корневых серверов.
    ldns_pkt* answer = ldns_resolver_query(res, ldns_rr_owner(qrr),
                                            ldns_rr_get_type(qrr),
                                            ldns_rr_get_class(qrr),
                                            LDNS_RD);

    ldns_resolver_deep_free(res);
    return answer;
}

// --------------------------------------------------------------------------------------
// Функции для libuv
// --------------------------------------------------------------------------------------

// Рабочая функция в отдельном потоке
void work_cb(uv_work_t* req) {
    WorkRequest* work_req = static_cast<WorkRequest*>(req->data);
    ldns_pkt* response = nullptr;
    ldns_rr_list* question_list = ldns_pkt_question(work_req->query);

    if (question_list && ldns_rr_list_rr_count(question_list) > 0) {
        ldns_rr* qrr = ldns_rr_list_rr(question_list, 0);
        std::string cache_key = make_cache_key(qrr);
        std::vector<CacheEntry> cached_entries;

        // Сначала ищем в кэше
        if (cache_lookup(cache_key, cached_entries)) {
            response = ldns_pkt_new();
            ldns_pkt_set_id(response, ldns_pkt_id(work_req->query));
            ldns_pkt_set_qr(response, true);
            ldns_pkt_set_aa(response, false);
            ldns_rr_list* answer_list = ldns_rr_list_new();
            for (const auto& entry : cached_entries) {
                ldns_rr_list_push_rr(answer_list, ldns_rr_clone(entry.rr));
            }
            ldns_pkt_set_answer(response, answer_list);
        } else {
            // Если нет в кэше, выполняем итеративное разрешение
            response = resolve_iterative(work_req->query);
            if (response) {
                ldns_pkt_set_id(response, ldns_pkt_id(work_req->query));
                // Сохраняем в кэш
                ldns_rr_list* answers = ldns_pkt_answer(response);
                if (answers) {
                    for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {
                        ldns_rr* rr = ldns_rr_list_rr(answers, i);
                        cache_store(make_cache_key(rr), rr);
                    }
                }
            }
        }
    }
    
    // Освобождаем исходный запрос
    ldns_pkt_free(work_req->query);
    work_req->query = response; // Передаем ответ обратно в главный поток
}

// Вызывается после завершения work_cb
void after_work_cb(uv_work_t* req, int status) {
    WorkRequest* work_req = static_cast<WorkRequest*>(req->data);

    if (work_req->query) {
        ldns_buffer* out_buf = ldns_buffer_new(UDP_BUFFER_SIZE);
        if (ldns_pkt2buffer_wire(out_buf, work_req->query) == LDNS_STATUS_OK) {
            uv_buf_t send_buf = uv_buf_init((char*)ldns_buffer_begin(out_buf), ldns_buffer_position(out_buf));
            uv_udp_send_t* send_req = new uv_udp_send_t;
            send_req->data = out_buf;
            uv_udp_send(send_req, work_req->handle, &send_buf, 1, (const struct sockaddr*)&work_req->addr,
                        [](uv_udp_send_t* req, int status) {
                            ldns_buffer_free((ldns_buffer*)req->data);
                            delete req;
                        });
        } else {
            ldns_buffer_free(out_buf);
        }
        ldns_pkt_free(work_req->query);
    }
    
    delete[] work_req->buf.base;
    delete work_req;
    delete req;
}

// Обработка запроса клиента
void handle_query(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    if (nread <= 0) {
        delete[] buf->base;
        return;
    }

    ldns_pkt* query = nullptr;
    ldns_buffer* pkt_buf = ldns_buffer_new(nread);
    ldns_buffer_write(pkt_buf, (uint8_t*)buf->base, nread);
    ldns_buffer_flip(pkt_buf);

    if (ldns_buffer2pkt_wire(&query, pkt_buf) != LDNS_STATUS_OK) {
        ldns_buffer_free(pkt_buf);
        delete[] buf->base;
        return;
    }
    ldns_buffer_free(pkt_buf);

    uv_work_t* req = new uv_work_t;
    WorkRequest* work_req = new WorkRequest;
    
    work_req->handle = handle;
    work_req->query = query;
    memcpy(&work_req->addr, addr, sizeof(struct sockaddr_storage));
    work_req->buf = *buf;
    
    req->data = work_req;
    uv_queue_work(uv_default_loop(), req, work_cb, after_work_cb);
}

// Выделение буфера
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = new char[UDP_BUFFER_SIZE];
    buf->len = UDP_BUFFER_SIZE;
}

// --------------------------------------------------------------------------------------
// Основная функция
// --------------------------------------------------------------------------------------

int main() {
    uv_loop_t* main_loop = uv_default_loop();

    uv_udp_t server;
    uv_udp_init(main_loop, &server);

    struct sockaddr_in bind_addr;
    uv_ip4_addr(BIND_ADDRESS, BIND_PORT, &bind_addr);
    if (uv_udp_bind(&server, (const struct sockaddr*)&bind_addr, UV_UDP_REUSEADDR) != 0) {
        std::cerr << "Failed to bind to port " << BIND_PORT << std::endl;
        return 1;
    }
    uv_udp_recv_start(&server, alloc_buffer, handle_query);

    std::cout << "DNS server listening on " << BIND_ADDRESS << ":" << BIND_PORT << std::endl;

    uv_run(main_loop, UV_RUN_DEFAULT);
    uv_loop_close(main_loop);

    return 0;
}
