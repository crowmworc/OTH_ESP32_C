/* OTH-AT socket engine -- see oth_sock.h. Built only for the OTH-AT command
 * set; mirrors net_link.c (M2M-AT) wherever the two models agree. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"

#include "oth_sock.h"
#include "at_commands_oth.h"
#include "at_cmdset.h"
#include "at_event.h"
#include "at_uart.h"
#include "at_response.h"
#include "fs_store.h"

static const char *TAG = "oth_sock";

#define MAX_CLIENTS          4      /* accepted clients per listening TCP socket */
#define CONNECT_TIMEOUT_US   (9LL * 1000 * 1000) /* doc: ~9 s (3 s RTO x 3) */
#define SSL_TIMEOUT_MS       10000
#define HANDSHAKE_TIMEOUT_US (10LL * 1000 * 1000)
#define SEND_TIMEOUT_US      (5LL * 1000 * 1000)
#define SVR_CLIENTS          2      /* TLS server client descriptors 1..2 */

typedef enum { S_FREE = 0, S_OPEN, S_CONNECTING, S_CONNECTED, S_LISTENING, S_SSL_HANDSHAKE } sock_state_t;

typedef struct {
    int fd;
    char ip[16];
    uint16_t port;
} client_t;

typedef struct {
    sock_state_t st;
    int type;            /* OTH_SOCK_TCP / UDP / SSL */
    int fd;
    uint16_t lport;
    char rip[16];        /* connected peer; UDP data mode: default peer */
    uint16_t rport;
    int64_t deadline_us; /* S_CONNECTING */
    client_t cl[MAX_CLIENTS];
    esp_tls_t *tls;
} sock_t;

typedef struct {
    bool used;
    bool handshaking;
    int fd;
    esp_tls_t *tls;
    int64_t deadline_us;
} svr_client_t;

static sock_t s_sock[OTH_SD_MAX];
static SemaphoreHandle_t s_mutex;

static int s_svr_fd = -1;
static char *s_svr_pem;
static size_t s_svr_pem_len;
static svr_client_t s_svr[SVR_CLIENTS + 1]; /* index = client descriptor, 0 unused */

static int s_keep_idle; /* TCPKEEP, seconds; 0 = off */
static int s_keep_cnt;

/* data mode */
static volatile int s_data_sd = -1;
static volatile int s_data_opening = -1; /* DATA_SOCKET connecting: no CONNECTED/TIMEOUT line */
static int s_data_type;
static int s_data_interval_ms = 200;
static uint8_t s_tx_buf[1460];
static size_t s_tx_len;
static SemaphoreHandle_t s_tx_mutex;
static esp_timer_handle_t s_tx_timer;

static void lock(void)   { xSemaphoreTake(s_mutex, portMAX_DELAY); }
static void unlock(void) { xSemaphoreGive(s_mutex); }

static void client_init(client_t *c)
{
    c->fd = -1;
    c->ip[0] = '\0';
    c->port = 0;
}

static void slot_reset_locked(int sd)
{
    sock_t *s = &s_sock[sd];
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_init(&s->cl[i]);
    }
}

static void slot_close_locked(int sd)
{
    sock_t *s = &s_sock[sd];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s->cl[i].fd >= 0) {
            lwip_close(s->cl[i].fd);
        }
    }
    if (s->tls) {
        esp_tls_conn_destroy(s->tls); /* owns its fd */
    } else if (s->fd >= 0) {
        lwip_close(s->fd);
    }
    slot_reset_locked(sd);
}

static void set_nonblock(int fd)
{
    int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void apply_keepalive(int fd)
{
    if (s_keep_idle <= 0) {
        return;
    }
    int on = 1, idle = s_keep_idle, cnt = s_keep_cnt > 0 ? s_keep_cnt : 3;
    lwip_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &idle, sizeof(idle));
    lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

static bool resolve_ipv4(const char *host, struct in_addr *out)
{
    if (lwip_inet_pton(AF_INET, host, out) == 1) {
        return true;
    }
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    if (lwip_getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        return false;
    }
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    lwip_freeaddrinfo(res);
    return true;
}

/* "<tag><head><data>\r\n" with raw payload bytes, written in one piece so
 * other output cannot land inside it. Dropped while EVTDEL=1. */
static void post_data(const char *head, const uint8_t *data, size_t len)
{
    if (!at_event_enabled()) {
        return;
    }
    char line[96];
    int n = snprintf(line, sizeof(line), AT_TAG "%s", head);
    if (n <= 0 || (size_t)n >= sizeof(line)) {
        return;
    }
    at_uart_write_atomic2(line, (size_t)n, (const char *)data, len);
    at_uart_write("\r\n", 2);
}

/* ---- data mode transmit (UART -> socket), aggregated per DATA_INTERVAL -- */

static void data_tx_flush(void)
{
    xSemaphoreTake(s_tx_mutex, portMAX_DELAY);
    size_t len = s_tx_len;
    s_tx_len = 0;
    int sd = s_data_sd;
    if (len && sd >= 0) {
        lock();
        sock_t *s = &s_sock[sd];
        int fd = s->fd;
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(s->rport)};
        lwip_inet_pton(AF_INET, s->rip, &to.sin_addr);
        if (s_data_type == 4) {
            fd = s->cl[0].fd;
        }
        unlock();
        if (fd >= 0) {
            if (s_data_type == 2 || s_data_type == 8) {
                if (to.sin_port) {
                    lwip_sendto(fd, s_tx_buf, len, 0, (struct sockaddr *)&to, sizeof(to));
                }
            } else {
                lwip_send(fd, s_tx_buf, len, 0);
            }
        }
    }
    xSemaphoreGive(s_tx_mutex);
}

static void data_tx_timer_cb(void *arg)
{
    (void)arg;
    data_tx_flush();
}

static void data_sink(const uint8_t *data, size_t len)
{
    xSemaphoreTake(s_tx_mutex, portMAX_DELAY);
    bool first = (s_tx_len == 0);
    bool full = false;
    for (size_t i = 0; i < len; i++) {
        s_tx_buf[s_tx_len++] = data[i];
        if (s_tx_len == sizeof(s_tx_buf)) {
            full = true;
            break;
        }
    }
    xSemaphoreGive(s_tx_mutex);
    if (full) {
        esp_timer_stop(s_tx_timer);
        data_tx_flush();
    } else if (first) {
        esp_timer_start_once(s_tx_timer, (uint64_t)s_data_interval_ms * 1000);
    }
}

static void data_leave_locked_closed(int sd)
{
    /* socket already closed by the caller; just leave transparent mode */
    if (s_data_sd == sd) {
        s_data_sd = -1;
        at_uart_set_passthrough(NULL, NULL);
    }
}

/* "+++": close the data socket and return to command mode (silently,
 * as the guide's example shows). */
static void data_on_escape(void)
{
    esp_timer_stop(s_tx_timer);
    data_tx_flush();
    int sd = s_data_sd;
    s_data_sd = -1;
    if (sd >= 0) {
        lock();
        slot_close_locked(sd);
        unlock();
    }
}

void oth_sock_set_data_interval(int ms)
{
    s_data_interval_ms = (ms >= 10 && ms <= 1000) ? ms : 200;
}

int oth_sock_data_interval(void)
{
    return s_data_interval_ms;
}

/* ---- socket commands ------------------------------------------------------ */

int oth_sock_create(int type, int *sd_out)
{
    int first, last;
    if (type == OTH_SOCK_TCP) {
        first = 0, last = 2;
    } else if (type == OTH_SOCK_UDP) {
        first = 3, last = 5;
    } else if (type == OTH_SOCK_SSL) {
        first = last = OTH_SD_SSL;
    } else {
        return OTH_ERR_GENERAL_PARAM;
    }
    lock();
    int sd = -1;
    for (int i = first; i <= last; i++) {
        if (s_sock[i].st == S_FREE) {
            sd = i;
            break;
        }
    }
    if (sd < 0) {
        unlock();
        return OTH_ERR_SOCKET_NOT_AVAIL;
    }
    int fd = -1;
    if (type != OTH_SOCK_SSL) {
        fd = lwip_socket(AF_INET, type == OTH_SOCK_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (fd < 0) {
            unlock();
            return OTH_ERR_SOCKET_NOT_AVAIL;
        }
        set_nonblock(fd);
        if (type == OTH_SOCK_TCP) {
            apply_keepalive(fd);
        }
    }
    slot_reset_locked(sd);
    s_sock[sd].st = S_OPEN;
    s_sock[sd].type = type;
    s_sock[sd].fd = fd;
    unlock();
    *sd_out = sd;
    return 0;
}

static bool sd_valid(int sd)
{
    return sd >= 0 && sd < OTH_SD_MAX;
}

int oth_sock_close(int sd)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    if (s_sock[sd].st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s_sock[sd].st == S_SSL_HANDSHAKE) {
        s_sock[sd].st = S_FREE; /* the handshake task sees this and discards its result */
        unlock();
        return 0;
    }
    slot_close_locked(sd);
    unlock();
    if (s_data_sd == sd) {
        data_leave_locked_closed(sd);
    }
    return 0;
}

int oth_sock_connect(int sd, const char *host, uint16_t port)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (port == 0 || !resolve_ipv4(host, &to.sin_addr)) {
        return OTH_ERR_TCPIP_PARAM;
    }
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s->type != OTH_SOCK_TCP || s->st != S_OPEN) {
        unlock();
        return OTH_ERR_SOCKET_INVALID;
    }
    int r = lwip_connect(s->fd, (struct sockaddr *)&to, sizeof(to));
    if (r < 0 && errno != EINPROGRESS) {
        unlock();
        return OTH_ERR_CONNECTION_ESTABLISHMENT;
    }
    lwip_inet_ntop(AF_INET, &to.sin_addr, s->rip, sizeof(s->rip));
    s->rport = port;
    s->st = S_CONNECTING;
    s->deadline_us = esp_timer_get_time() + CONNECT_TIMEOUT_US;
    unlock();
    return 0;
}

int oth_sock_bind(int sd, uint16_t port)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    if (port == 0) {
        return OTH_ERR_TCPIP_PARAM;
    }
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s->type == OTH_SOCK_SSL || s->st != S_OPEN || s->lport) {
        unlock();
        return OTH_ERR_SOCKET_INVALID;
    }
    int reuse = 1;
    lwip_setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    if (lwip_bind(s->fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        unlock();
        return OTH_ERR_ADDRESS_IN_USE;
    }
    s->lport = port;
    unlock();
    return 0;
}

int oth_sock_listen(int sd)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s->type != OTH_SOCK_TCP || s->st != S_OPEN || !s->lport) {
        unlock();
        return OTH_ERR_SOCKET_INVALID; /* TCP, bound with BIND first */
    }
    if (lwip_listen(s->fd, MAX_CLIENTS) < 0) {
        unlock();
        return OTH_ERR_TCPIP_PARAM;
    }
    s->st = S_LISTENING;
    unlock();
    return 0;
}

static int find_client_locked(sock_t *s, const char *ip, uint16_t port)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s->cl[i].fd >= 0 && s->cl[i].port == port && strcmp(s->cl[i].ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

int oth_sock_drop_client(int sd, const char *ip, uint16_t port)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    int i = s->st == S_LISTENING ? find_client_locked(s, ip, port) : -1;
    if (i < 0) {
        unlock();
        return OTH_ERR_TCPIP_PARAM;
    }
    lwip_close(s->cl[i].fd);
    client_init(&s->cl[i]);
    unlock();
    return 0;
}

int oth_sock_list_clients(int sd, char *out, size_t cap)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s->st != S_LISTENING) {
        unlock();
        return OTH_ERR_SOCKET_INVALID;
    }
    size_t n = (size_t)snprintf(out, cap, "%d", sd);
    for (int i = 0; i < MAX_CLIENTS && n < cap; i++) {
        if (s->cl[i].fd >= 0) {
            n += (size_t)snprintf(out + n, cap - n, " %s %u", s->cl[i].ip, s->cl[i].port);
        }
    }
    unlock();
    return 0;
}

/* Non-blocking socket: retries a full send buffer for up to SEND_TIMEOUT_US. */
static bool send_all(int fd, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    int64_t deadline = esp_timer_get_time() + SEND_TIMEOUT_US;
    while (sent < len) {
        ssize_t n = lwip_send(fd, data + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && esp_timer_get_time() < deadline) {
            vTaskDelay(1);
            continue;
        }
        return false;
    }
    return true;
}

int oth_sock_send(int sd, const char *ip, uint16_t port, const uint8_t *data, size_t len)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    sock_t *s = &s_sock[sd];
    int fd = -1;
    if (s->st == S_FREE) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (s->type == OTH_SOCK_TCP && s->st == S_CONNECTED) {
        fd = s->fd;
    } else if (s->type == OTH_SOCK_TCP && s->st == S_LISTENING) {
        int i = find_client_locked(s, ip, port);
        fd = i >= 0 ? s->cl[i].fd : -1;
    }
    unlock();
    if (fd < 0) {
        return OTH_ERR_SOCKET_INVALID;
    }
    return send_all(fd, data, len) ? 0 : OTH_ERR_CONNECTION_ESTABLISHMENT;
}

int oth_sock_sendto(int sd, const char *ip, uint16_t port, const uint8_t *data, size_t len)
{
    if (!sd_valid(sd)) {
        return OTH_ERR_SOCKET_INVALID;
    }
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (port == 0 || !resolve_ipv4(ip, &to.sin_addr)) {
        return OTH_ERR_TCPIP_PARAM;
    }
    lock();
    sock_t *s = &s_sock[sd];
    int fd = (s->st == S_OPEN && s->type == OTH_SOCK_UDP) ? s->fd : -1;
    sock_state_t st = s->st;
    unlock();
    if (st == S_FREE) {
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (fd < 0) {
        return OTH_ERR_SOCKET_INVALID;
    }
    ssize_t n = lwip_sendto(fd, data, len, 0, (struct sockaddr *)&to, sizeof(to));
    return n == (ssize_t)len ? 0 : OTH_ERR_TCPIP_PARAM;
}

int oth_sock_connected_sd(void)
{
    int found = -1;
    lock();
    for (int sd = 0; sd < OTH_SD_MAX && found < 0; sd++) {
        sock_t *s = &s_sock[sd];
        if (s->st == S_CONNECTED) {
            found = sd;
        } else if (s->st == S_LISTENING) {
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (s->cl[i].fd >= 0) {
                    found = sd;
                    break;
                }
            }
        }
    }
    unlock();
    return found;
}

void oth_sock_set_keepalive(int idle_s, int count)
{
    s_keep_idle = idle_s;
    s_keep_cnt = count;
    lock();
    for (int sd = 0; sd < OTH_SD_MAX; sd++) {
        sock_t *s = &s_sock[sd];
        if (s->st != S_FREE && s->type == OTH_SOCK_TCP && s->fd >= 0) {
            if (idle_s > 0) {
                apply_keepalive(s->fd);
            } else {
                int off = 0;
                lwip_setsockopt(s->fd, SOL_SOCKET, SO_KEEPALIVE, &off, sizeof(off));
            }
        }
    }
    unlock();
}

/* ---- SSL client ------------------------------------------------------------- */

typedef struct {
    int sd;
    uint32_t gen;
    uint16_t port;
    char host[64];
} ssl_job_t;

/* Bumped by every SSL_CONNECT, so a handshake task whose socket was closed
 * and reopened meanwhile cannot claim the new one. */
static uint32_t s_ssl_gen;

/* The handshake runs in its own short-lived task so SSL_CONNECT can answer
 * OK at once (result: *OTH*SSL_IND:<sd> 0 OK|ERROR). The server is verified
 * against a stored ca.pem when there is one (the same CA file the web UI
 * uploads), otherwise against the public CA bundle. */
static void ssl_connect_task(void *arg)
{
    ssl_job_t *job = arg;
    esp_tls_cfg_t cfg = {0};
    cfg.timeout_ms = SSL_TIMEOUT_MS;
    cfg.non_block = true;
    size_t ca_len = 0;
    char *ca = fs_store_exists("ca.pem") ? fs_store_read_alloc("ca.pem", &ca_len) : NULL;
    if (ca) {
        cfg.cacert_buf = (const unsigned char *)ca;
        cfg.cacert_bytes = (unsigned int)ca_len + 1;
    } else {
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
    }
    esp_tls_t *tls = esp_tls_init();
    bool ok = tls && esp_tls_conn_new_sync(job->host, (int)strlen(job->host), job->port, &cfg, tls) == 1;
    free(ca);

    lock();
    sock_t *s = &s_sock[job->sd];
    if (s->st != S_SSL_HANDSHAKE || job->gen != s_ssl_gen) {
        /* closed meanwhile */
        unlock();
        if (tls) {
            esp_tls_conn_destroy(tls);
        }
    } else if (ok) {
        int fd = -1;
        esp_tls_get_conn_sockfd(tls, &fd);
        s->tls = tls;
        s->fd = fd;
        s->st = S_CONNECTED;
        strlcpy(s->rip, job->host, sizeof(s->rip));
        s->rport = job->port;
        unlock();
        at_event_post("SSL_IND:%d 0 OK", job->sd);
    } else {
        s->st = S_OPEN;
        unlock();
        if (tls) {
            esp_tls_conn_destroy(tls);
        }
        at_event_post("SSL_IND:%d 0 ERROR", job->sd);
    }
    free(job);
    vTaskDelete(NULL);
}

int oth_ssl_connect(int sd, const char *host, uint16_t port)
{
    if (sd != OTH_SD_SSL) {
        return OTH_ERR_SOCKET_INVALID;
    }
    if (port == 0 || strlen(host) >= sizeof(((ssl_job_t *)0)->host)) {
        return OTH_ERR_TCPIP_PARAM;
    }
    ssl_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        return OTH_ERR_OUT_OF_MEMORY;
    }
    job->sd = sd;
    job->port = port;
    strlcpy(job->host, host, sizeof(job->host));
    lock();
    sock_t *s = &s_sock[sd];
    int err = s->st == S_FREE ? OTH_ERR_SOCKET_NOT_EXIST : s->st != S_OPEN ? OTH_ERR_SOCKET_INVALID : 0;
    if (!err) {
        s->st = S_SSL_HANDSHAKE;
        job->gen = ++s_ssl_gen;
    }
    unlock();
    if (err) {
        free(job);
        return err;
    }
    if (xTaskCreate(ssl_connect_task, "oth_ssl", 6144, job, 5, NULL) != pdPASS) {
        lock();
        s->st = S_OPEN;
        unlock();
        free(job);
        return OTH_ERR_OUT_OF_MEMORY;
    }
    return 0;
}

static bool tls_write_all(esp_tls_t *tls, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    int64_t deadline = esp_timer_get_time() + SEND_TIMEOUT_US;
    while (sent < len) {
        int n = esp_tls_conn_write(tls, data + sent, len - sent);
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            if (esp_timer_get_time() > deadline) {
                return false;
            }
            vTaskDelay(1);
            continue;
        }
        if (n <= 0) {
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

int oth_ssl_send(int sd, const uint8_t *data, size_t len)
{
    if (sd != OTH_SD_SSL) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    sock_t *s = &s_sock[sd];
    esp_tls_t *tls = s->st == S_CONNECTED ? s->tls : NULL;
    sock_state_t st = s->st;
    unlock();
    if (st == S_FREE) {
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    if (!tls) {
        return OTH_ERR_SOCKET_INVALID;
    }
    return tls_write_all(tls, data, len) ? 0 : OTH_ERR_CONNECTION_ESTABLISHMENT;
}

/* ---- SSL server --------------------------------------------------------------- */

int oth_ssl_svr_start(uint16_t port)
{
    if (s_svr_fd >= 0) {
        return OTH_ERR_ADDRESS_IN_USE;
    }
    if (port < 1025 || port > 65000) {
        return OTH_ERR_TCPIP_PARAM;
    }
    size_t len = 0;
    char *pem = fs_store_read_alloc(OTH_SSL_SERVER_CERT, &len);
    if (!pem) {
        return OTH_ERR_GENERAL_PARAM; /* no server certificate stored */
    }
    int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    if (fd < 0 || lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        lwip_bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || lwip_listen(fd, SVR_CLIENTS) < 0) {
        if (fd >= 0) {
            lwip_close(fd);
        }
        free(pem);
        return OTH_ERR_ADDRESS_IN_USE;
    }
    set_nonblock(fd);
    lock();
    s_svr_pem = pem;
    s_svr_pem_len = len;
    s_svr_fd = fd;
    unlock();
    return 0;
}

static void svr_client_close_locked(int csd)
{
    if (s_svr[csd].tls) {
        esp_tls_conn_destroy(s_svr[csd].tls);
    } else if (s_svr[csd].fd >= 0) {
        lwip_close(s_svr[csd].fd);
    }
    memset(&s_svr[csd], 0, sizeof(s_svr[csd]));
    s_svr[csd].fd = -1;
}

int oth_ssl_svr_send(int csd, const uint8_t *data, size_t len)
{
    if (csd < 1 || csd > SVR_CLIENTS) {
        return OTH_ERR_SOCKET_INVALID;
    }
    lock();
    esp_tls_t *tls = (s_svr[csd].used && !s_svr[csd].handshaking) ? s_svr[csd].tls : NULL;
    unlock();
    if (!tls) {
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    return tls_write_all(tls, data, len) ? 0 : OTH_ERR_CONNECTION_ESTABLISHMENT;
}

int oth_ssl_svr_close(void)
{
    lock();
    if (s_svr_fd < 0) {
        unlock();
        return OTH_ERR_SOCKET_NOT_EXIST;
    }
    for (int i = 1; i <= SVR_CLIENTS; i++) {
        if (s_svr[i].used) {
            svr_client_close_locked(i);
        }
    }
    lwip_close(s_svr_fd);
    s_svr_fd = -1;
    free(s_svr_pem);
    s_svr_pem = NULL;
    unlock();
    return 0;
}

static void svr_accept(void)
{
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = lwip_accept(s_svr_fd, (struct sockaddr *)&peer, &plen);
    if (fd < 0) {
        return;
    }
    lock();
    int csd = -1;
    for (int i = 1; i <= SVR_CLIENTS; i++) {
        if (!s_svr[i].used) {
            csd = i;
            break;
        }
    }
    unlock();
    if (csd < 0) {
        lwip_close(fd); /* both client descriptors busy */
        return;
    }
    set_nonblock(fd);
    esp_tls_cfg_server_t cfg = {0};
    cfg.servercert_buf = (const unsigned char *)s_svr_pem;
    cfg.servercert_bytes = (unsigned int)s_svr_pem_len + 1;
    cfg.serverkey_buf = (const unsigned char *)s_svr_pem;
    cfg.serverkey_bytes = (unsigned int)s_svr_pem_len + 1;
    esp_tls_t *tls = esp_tls_init();
    if (!tls || esp_tls_server_session_init(&cfg, fd, tls) != ESP_OK) {
        if (tls) {
            esp_tls_conn_destroy(tls);
        } else {
            lwip_close(fd);
        }
        at_event_post("SSL_SVR_IND:%d 0 ERROR", csd);
        return;
    }
    lock();
    s_svr[csd].used = true;
    s_svr[csd].handshaking = true;
    s_svr[csd].fd = fd;
    s_svr[csd].tls = tls;
    s_svr[csd].deadline_us = esp_timer_get_time() + HANDSHAKE_TIMEOUT_US;
    unlock();
}

/* Drives a TLS server handshake one step per tick (like net_link.c). */
static void svr_handshake_step(int csd)
{
    int ret = esp_tls_server_session_continue_async(s_svr[csd].tls);
    if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
        if (esp_timer_get_time() < s_svr[csd].deadline_us) {
            return;
        }
        ret = -1;
    }
    if (ret != 0) {
        lock();
        svr_client_close_locked(csd);
        unlock();
        at_event_post("SSL_SVR_IND:%d 0 ERROR", csd);
        return;
    }
    lock();
    s_svr[csd].handshaking = false;
    unlock();
    at_event_post("SSL_SVR_ACCEPTED:%d", csd);
}

/* ---- background task -------------------------------------------------------- */

static uint8_t s_rx[1460];

static void on_connecting(int sd, bool writable)
{
    lock();
    sock_t *s = &s_sock[sd];
    if (s->st != S_CONNECTING) {
        unlock();
        return;
    }
    const char *ev = NULL;
    if (writable) {
        int err = 0;
        socklen_t l = sizeof(err);
        lwip_getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err == 0) {
            s->st = S_CONNECTED;
            ev = "CONNECTED";
        } else {
            ev = (err == ECONNREFUSED || err == ECONNRESET) ? "REJECTED" : "TIMEOUT";
        }
    } else if (esp_timer_get_time() > s->deadline_us) {
        ev = "TIMEOUT";
    }
    if (ev && strcmp(ev, "CONNECTED") != 0) {
        slot_close_locked(sd); /* auto-closed */
    }
    unlock();
    if (ev && sd != s_data_opening) {
        at_event_post("%s:%d", ev, sd);
    }
}

static void on_tcp_readable(int sd)
{
    lock();
    sock_t *s = &s_sock[sd];
    int fd = s->fd;
    esp_tls_t *tls = s->tls;
    char ip[16];
    strlcpy(ip, s->rip, sizeof(ip));
    uint16_t port = s->rport;
    unlock();

    ssize_t n;
    if (tls) {
        n = esp_tls_conn_read(tls, s_rx, sizeof(s_rx));
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            return;
        }
    } else {
        n = lwip_recv(fd, s_rx, sizeof(s_rx), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
    }
    if (n <= 0) {
        bool reset = !tls && n < 0 && errno == ECONNRESET;
        lock();
        if (tls) {
            /* the SSL descriptor stays allocated until SSL_CLOSE */
            esp_tls_conn_destroy(s->tls);
            s->tls = NULL;
            s->fd = -1;
            s->st = S_OPEN;
        } else {
            slot_close_locked(sd);
        }
        unlock();
        if (s_data_sd == sd) {
            data_leave_locked_closed(sd);
        } else if (tls) {
            at_event_post("SSL_IND:%d 2 ERROR", sd);
        } else {
            at_event_post("%s:%d", reset ? "REJECTED" : "CLOSED", sd);
        }
        return;
    }
    if (s_data_sd == sd) {
        at_uart_write((const char *)s_rx, (size_t)n);
        return;
    }
    char head[64];
    if (tls) {
        snprintf(head, sizeof(head), "SSL_RECV:%d %d ", sd, (int)n);
    } else {
        snprintf(head, sizeof(head), "RECV:%d %s %u %d ", sd, ip, port, (int)n);
    }
    post_data(head, s_rx, (size_t)n);
}

static void on_udp_readable(int sd)
{
    lock();
    int fd = s_sock[sd].fd;
    unlock();
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t n = lwip_recvfrom(fd, s_rx, sizeof(s_rx), 0, (struct sockaddr *)&from, &fl);
    if (n <= 0) {
        return;
    }
    char ip[16];
    lwip_inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
    uint16_t port = ntohs(from.sin_port);
    if (s_data_sd == sd) {
        if (s_data_type == 8) { /* UDP server: answer the last sender */
            lock();
            strlcpy(s_sock[sd].rip, ip, sizeof(s_sock[sd].rip));
            s_sock[sd].rport = port;
            unlock();
        }
        at_uart_write((const char *)s_rx, (size_t)n);
        return;
    }
    char head[64];
    snprintf(head, sizeof(head), "RECVFROM:%d %s %u %d ", sd, ip, port, (int)n);
    post_data(head, s_rx, (size_t)n);
}

static void on_listen_readable(int sd)
{
    lock();
    int lfd = s_sock[sd].fd;
    unlock();
    struct sockaddr_in peer;
    socklen_t pl = sizeof(peer);
    int fd = lwip_accept(lfd, (struct sockaddr *)&peer, &pl);
    if (fd < 0) {
        return;
    }
    lock();
    sock_t *s = &s_sock[sd];
    int slot = -1;
    int limit = (s_data_sd == sd) ? 1 : MAX_CLIENTS; /* data mode: one client */
    for (int i = 0; i < limit; i++) {
        if (s->cl[i].fd < 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        unlock();
        lwip_close(fd);
        return;
    }
    set_nonblock(fd);
    apply_keepalive(fd);
    s->cl[slot].fd = fd;
    lwip_inet_ntop(AF_INET, &peer.sin_addr, s->cl[slot].ip, sizeof(s->cl[slot].ip));
    s->cl[slot].port = ntohs(peer.sin_port);
    char ip[16];
    strlcpy(ip, s->cl[slot].ip, sizeof(ip));
    uint16_t port = s->cl[slot].port;
    unlock();
    if (s_data_sd != sd) {
        at_event_post("ACCEPTED:%d %s %u", sd, ip, port);
    }
}

static void on_client_readable(int sd, int i)
{
    lock();
    client_t c = s_sock[sd].cl[i];
    unlock();
    ssize_t n = lwip_recv(c.fd, s_rx, sizeof(s_rx), 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return;
    }
    if (n <= 0) {
        lock();
        if (s_sock[sd].cl[i].fd == c.fd) {
            lwip_close(c.fd);
            client_init(&s_sock[sd].cl[i]);
        }
        unlock();
        if (s_data_sd == sd) {
            lock();
            slot_close_locked(sd);
            unlock();
            data_leave_locked_closed(sd);
        } else {
            at_event_post("DISCONNECTED:%d %s %u", sd, c.ip, c.port);
        }
        return;
    }
    if (s_data_sd == sd) {
        at_uart_write((const char *)s_rx, (size_t)n);
        return;
    }
    char head[64];
    snprintf(head, sizeof(head), "RECV:%d %s %u %d ", sd, c.ip, c.port, (int)n);
    post_data(head, s_rx, (size_t)n);
}

static void on_svr_client_readable(int csd)
{
    lock();
    esp_tls_t *tls = s_svr[csd].tls;
    unlock();
    int n = esp_tls_conn_read(tls, s_rx, sizeof(s_rx));
    if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        return;
    }
    if (n <= 0) {
        lock();
        svr_client_close_locked(csd);
        unlock();
        at_event_post("SSL_SVR_CLOSED:%d", csd);
        return;
    }
    char head[48];
    snprintf(head, sizeof(head), "SSL_SVR_RECV:%d %d ", csd, n);
    post_data(head, s_rx, (size_t)n);
}

static void oth_sock_task(void *arg)
{
    (void)arg;
    for (;;) {
        sock_t snap[OTH_SD_MAX];
        svr_client_t svr[SVR_CLIENTS + 1];
        lock();
        memcpy(snap, s_sock, sizeof(snap));
        memcpy(svr, s_svr, sizeof(svr));
        int svr_fd = s_svr_fd;
        unlock();

        for (int i = 1; i <= SVR_CLIENTS; i++) {
            if (svr[i].used && svr[i].handshaking) {
                svr_handshake_step(i);
            }
        }

        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        int maxfd = -1;
#define WATCH(set, f) do { FD_SET((f), (set)); if ((f) > maxfd) maxfd = (f); } while (0)
        for (int sd = 0; sd < OTH_SD_MAX; sd++) {
            sock_t *s = &snap[sd];
            if (s->fd < 0) {
                continue;
            }
            if (s->st == S_CONNECTING) {
                WATCH(&wfds, s->fd);
            } else if (s->st == S_CONNECTED || s->st == S_LISTENING ||
                       (s->st == S_OPEN && s->type == OTH_SOCK_UDP)) {
                WATCH(&rfds, s->fd);
            }
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (s->cl[i].fd >= 0) {
                    WATCH(&rfds, s->cl[i].fd);
                }
            }
        }
        if (svr_fd >= 0) {
            WATCH(&rfds, svr_fd);
        }
        for (int i = 1; i <= SVR_CLIENTS; i++) {
            if (svr[i].used && !svr[i].handshaking && svr[i].fd >= 0) {
                WATCH(&rfds, svr[i].fd);
            }
        }
#undef WATCH
        if (maxfd < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        int ready = lwip_select(maxfd + 1, &rfds, &wfds, NULL, &tv);

        for (int sd = 0; sd < OTH_SD_MAX; sd++) {
            sock_t *s = &snap[sd];
            if (s->st == S_CONNECTING) {
                on_connecting(sd, ready > 0 && FD_ISSET(s->fd, &wfds));
                continue;
            }
            if (ready <= 0 || s->fd < 0) {
                continue;
            }
            if (FD_ISSET(s->fd, &rfds)) {
                if (s->st == S_LISTENING) {
                    on_listen_readable(sd);
                } else if (s->type == OTH_SOCK_UDP) {
                    on_udp_readable(sd);
                } else {
                    on_tcp_readable(sd);
                }
            }
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (s->cl[i].fd >= 0 && FD_ISSET(s->cl[i].fd, &rfds)) {
                    on_client_readable(sd, i);
                }
            }
        }
        if (ready > 0 && svr_fd >= 0 && FD_ISSET(svr_fd, &rfds)) {
            svr_accept();
        }
        for (int i = 1; ready > 0 && i <= SVR_CLIENTS; i++) {
            if (svr[i].used && !svr[i].handshaking && svr[i].fd >= 0 && FD_ISSET(svr[i].fd, &rfds)) {
                on_svr_client_readable(i);
            }
        }
    }
}

/* ---- data mode ------------------------------------------------------------------ */

static bool any_socket_open(void)
{
    bool open = s_svr_fd >= 0;
    lock();
    for (int sd = 0; sd < OTH_SD_MAX && !open; sd++) {
        open = s_sock[sd].st != S_FREE;
    }
    unlock();
    return open;
}

int oth_sock_data_open(int type, const char *rip, uint16_t rport, uint16_t lport, int *sd_out)
{
    if (type != 1 && type != 2 && type != 4 && type != 8) {
        return OTH_ERR_GENERAL_PARAM;
    }
    if (any_socket_open()) {
        return OTH_ERR_SOCKET_NOT_AVAIL; /* data mode needs every other socket closed */
    }
    bool udp = (type == 2 || type == 8);
    int sd;
    int err = oth_sock_create(udp ? OTH_SOCK_UDP : OTH_SOCK_TCP, &sd);
    if (err) {
        return err;
    }
    if (type == 4 || type == 8) {
        err = oth_sock_bind(sd, lport);
        if (!err && type == 4) {
            err = oth_sock_listen(sd);
        }
    } else {
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(rport)};
        if (rport == 0 || !resolve_ipv4(rip, &to.sin_addr)) {
            err = OTH_ERR_TCPIP_PARAM;
        } else if (type == 2) {
            lock();
            lwip_inet_ntop(AF_INET, &to.sin_addr, s_sock[sd].rip, sizeof(s_sock[sd].rip));
            s_sock[sd].rport = rport;
            unlock();
        } else {
            /* TCP client: connect before answering, bounded like a CONNECT */
            s_data_opening = sd;
            err = oth_sock_connect(sd, rip, rport);
            int64_t deadline = esp_timer_get_time() + CONNECT_TIMEOUT_US + 500000;
            while (!err) {
                lock();
                sock_state_t st = s_sock[sd].st;
                unlock();
                if (st == S_CONNECTED) {
                    break;
                }
                if (st == S_FREE || esp_timer_get_time() > deadline) {
                    err = OTH_ERR_CONNECTION_ESTABLISHMENT;
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            s_data_opening = -1;
        }
    }
    if (err) {
        lock();
        if (s_sock[sd].st != S_FREE) {
            slot_close_locked(sd);
        }
        unlock();
        return err;
    }
    s_data_type = type;
    s_tx_len = 0;
    s_data_sd = sd;
    *sd_out = sd;
    return 0;
}

/* Called by DATA_SOCKET right after its OK: announce and switch over. */
void oth_sock_data_start(void)
{
    at_reply_line("DATAMODE");
    at_uart_set_passthrough(data_sink, data_on_escape);
}

void oth_sock_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_tx_mutex = xSemaphoreCreateMutex();
    for (int sd = 0; sd < OTH_SD_MAX; sd++) {
        slot_reset_locked(sd);
    }
    for (int i = 0; i <= SVR_CLIENTS; i++) {
        s_svr[i].fd = -1;
    }
    const esp_timer_create_args_t targs = {.callback = data_tx_timer_cb, .name = "oth_dtx"};
    esp_timer_create(&targs, &s_tx_timer);
    xTaskCreate(oth_sock_task, "oth_sock", 4096, NULL, 8, NULL);
    ESP_LOGI(TAG, "socket engine ready");
}
