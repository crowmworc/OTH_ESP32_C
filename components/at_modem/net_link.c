#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"

#include "net_link.h"
#include "at_uart.h"
#include "at_event.h"
#include "fs_store.h"
#include "at_pem_scratch.h"

static const char *TAG = "net_link";

static net_link_t s_links[NET_MAX_LINKS];
static SemaphoreHandle_t s_mutex;
static volatile int s_passthrough_link = -1;

/* Server cert+key PEM, one slot per listener link_id -- must outlive the
 * listener itself since each newly accepted client's handshake (started
 * from handle_accept(), possibly long after NET_SERVER=1 ssl ran) needs it.
 * Doc: one cert_name file supplies both PEM blocks (see net_link.h). */
static char s_ssl_server_pem[NET_MAX_LINKS][2200];

static bool load_cert_file(const char *filename, char *out, size_t out_cap)
{
    return fs_store_read(filename, out, out_cap, NULL);
}

void net_link_set_passthrough(int link_id)
{
    s_passthrough_link = link_id;
}

static void links_lock(void)   { xSemaphoreTake(s_mutex, portMAX_DELAY); }
static void links_unlock(void) { xSemaphoreGive(s_mutex); }

static int find_free_slot_locked(void)
{
    for (int i = 0; i < NET_MAX_LINKS; i++) {
        if (!s_links[i].in_use) {
            return i;
        }
    }
    return -1;
}

static void close_slot_locked(int id)
{
    /* An SSL child link's tls context owns its fd (esp_tls_conn_destroy()
     * closes it internally) -- closing the fd separately would double-close
     * it. The listener fd itself is plain (only accepted children are
     * wrapped in TLS), so it always takes the lwip_close() path. */
    if (s_links[id].type == NET_LINK_SSL && !s_links[id].is_listener && s_links[id].tls) {
        esp_tls_conn_destroy(s_links[id].tls);
    } else if (s_links[id].fd >= 0) {
        lwip_close(s_links[id].fd);
    }
    memset(&s_links[id], 0, sizeof(s_links[id]));
    s_links[id].fd = -1;
}

#define NET_CONNECT_TIMEOUT_MS 10000

/* lwip's default blocking connect() can take ~75s to time out against an
 * unreachable host, which would freeze the whole (single-threaded) AT
 * command dispatcher for that long. Connect non-blocking with a bounded
 * wait instead, and leave the socket non-blocking afterward -- fine for
 * this component's select()-driven recv/accept model. */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (lwip_connect(fd, addr, addrlen) == 0) {
        return 0; /* connected immediately, e.g. loopback */
    }
    if (errno != EINPROGRESS) {
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = {.tv_sec = NET_CONNECT_TIMEOUT_MS / 1000,
                          .tv_usec = (NET_CONNECT_TIMEOUT_MS % 1000) * 1000};
    if (lwip_select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
        return -1; /* timeout, or select error */
    }

    int so_err = 0;
    socklen_t so_err_len = sizeof(so_err);
    lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len);
    return (so_err == 0) ? 0 : -1;
}

/* Accepts either a literal IPv4 address or a hostname -- doc's NET_CONN/
 * NET_SERVER <remote_ip> parameter historically only worked with literal
 * IPs because this used lwip_inet_pton() directly, which doesn't resolve
 * names. Same lwip_getaddrinfo() DNS path AT*M2M*NET_DNS already uses
 * (cmd_net_svc.c); tried as a literal address first since that's the
 * common case and avoids a DNS round trip for it. */
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

static int connect_tcp_udp(int link_id, net_link_type_t type, const char *ip, uint16_t port, uint16_t local_port)
{
    int fd = lwip_socket(AF_INET, type == NET_LINK_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) {
        return -2;
    }

    if (local_port != 0) {
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_port = htons(local_port);
        local.sin_addr.s_addr = INADDR_ANY;
        int reuse = 1;
        lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (lwip_bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
            lwip_close(fd);
            return -2;
        }
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (!resolve_ipv4(ip, &remote.sin_addr)) {
        lwip_close(fd);
        return -2;
    }
    if (type == NET_LINK_TCP) {
        if (connect_with_timeout(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            lwip_close(fd);
            return -2;
        }
    } else {
        /* UDP "connect" just latches the default destination for send();
         * it doesn't touch the wire, so no timeout concern. */
        if (lwip_connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            lwip_close(fd);
            return -2;
        }
    }

    links_lock();
    if (s_links[link_id].in_use) {
        /* raced with another connect to the same link_id between the check
         * above and now -- extremely unlikely (AT commands are processed
         * one at a time by the single dispatcher task) but stay correct. */
        links_unlock();
        lwip_close(fd);
        return -1;
    }
    if (local_port == 0) {
        /* Report the OS-assigned ephemeral port in NET_STATUS instead of
         * the "0 = auto" request value. */
        struct sockaddr_in bound = {0};
        socklen_t bound_len = sizeof(bound);
        if (lwip_getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0) {
            local_port = ntohs(bound.sin_port);
        }
    }

    s_links[link_id].in_use = true;
    s_links[link_id].type = type;
    s_links[link_id].is_listener = false;
    s_links[link_id].is_server_role = false;
    s_links[link_id].fd = fd;
    strlcpy(s_links[link_id].remote_ip, ip, sizeof(s_links[link_id].remote_ip));
    s_links[link_id].remote_port = port;
    s_links[link_id].local_port = local_port;
    links_unlock();
    return 0;
}

/* AT*M2M*NET_CONN type=ssl. Runs the whole connect+handshake synchronously
 * (bounded by cfg.timeout_ms) on the calling (AT dispatcher) thread, same
 * as connect_tcp_udp()'s connect_with_timeout() -- required by NET_CONN's
 * synchronous OK/ERROR contract (doc Ch.1.3), and the only sane choice for
 * the connect step regardless: a link-table state machine driven by the
 * shared task's 200ms select() ticks would only make the handshake slower,
 * not simpler, since the dispatcher would still have to block waiting for
 * it to resolve either way. Server-accepted SSL children are different --
 * see handle_accept()/handle_ssl_handshake_progress() -- because posting
 * NET_CLI_ACCEPTED was never a synchronous response to begin with. */
static int connect_ssl(int link_id, const char *ip, uint16_t port, const char *cert_name)
{
    char *cert_pem = g_at_pem_scratch; /* shared scratch, see at_pem_scratch.h */

    esp_tls_cfg_t cfg = {0};
    cfg.timeout_ms = NET_CONNECT_TIMEOUT_MS;
    cfg.non_block = true; /* leaves the fd non-blocking after handshake, for
                            * the shared task's select()-driven read/write */
    if (cert_name && cert_name[0] != '\0') {
        if (!load_cert_file(cert_name, cert_pem, AT_PEM_SCRATCH_LEN)) {
            return -2;
        }
        /* doc: one cert_name file supplies every PEM block that applies --
         * mbedtls finds each by its own "BEGIN CERTIFICATE"/"BEGIN ...
         * PRIVATE KEY" header, so the same buffer serves all of them
         * untouched. cacert is always taken from it too (a private CA the
         * public bundle doesn't carry, e.g. an in-house broker) -- without
         * this the client-cert branch was leaving the server completely
         * unverified. */
        size_t cert_len = strlen(cert_pem) + 1;
        cfg.cacert_buf = (const unsigned char *)cert_pem;
        cfg.cacert_bytes = (unsigned int)cert_len;
        if (strstr(cert_pem, "PRIVATE KEY")) {
            cfg.clientcert_buf = (const unsigned char *)cert_pem;
            cfg.clientcert_bytes = (unsigned int)cert_len;
            cfg.clientkey_buf = (const unsigned char *)cert_pem;
            cfg.clientkey_bytes = (unsigned int)cert_len;
        }
    } else {
        /* doc's "server-only validation" case -- still validate the peer,
         * against the same public CA bundle this project's HTTP/MQTT/OTA
         * clients already use, rather than skipping verification. */
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
    }

    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        return -2;
    }
    int ret = esp_tls_conn_new_sync(ip, (int)strlen(ip), port, &cfg, tls);
    if (ret != 1) {
        esp_tls_conn_destroy(tls);
        return -2;
    }

    int fd = -1;
    esp_tls_get_conn_sockfd(tls, &fd);

    links_lock();
    if (s_links[link_id].in_use) {
        /* same extremely-unlikely race noted in connect_tcp_udp(). */
        links_unlock();
        esp_tls_conn_destroy(tls);
        return -1;
    }
    s_links[link_id].in_use = true;
    s_links[link_id].type = NET_LINK_SSL;
    s_links[link_id].is_listener = false;
    s_links[link_id].is_server_role = false;
    s_links[link_id].fd = fd;
    s_links[link_id].tls = tls;
    s_links[link_id].tls_handshaking = false; /* client handshake already done above */
    strlcpy(s_links[link_id].remote_ip, ip, sizeof(s_links[link_id].remote_ip));
    s_links[link_id].remote_port = port;
    s_links[link_id].local_port = 0; /* esp_tls_conn_new_sync() has no bind step */
    links_unlock();
    return 0;
}

int net_link_connect(int link_id, net_link_type_t type, const char *ip, uint16_t port,
                      uint16_t local_port, const char *cert_name)
{
    if (type != NET_LINK_TCP && type != NET_LINK_UDP && type != NET_LINK_SSL) {
        return -3;
    }
    if (link_id < 0 || link_id >= NET_MAX_LINKS) {
        return -3;
    }
    links_lock();
    bool busy = s_links[link_id].in_use;
    links_unlock();
    if (busy) {
        return -1;
    }

    if (type == NET_LINK_SSL) {
        return connect_ssl(link_id, ip, port, cert_name);
    }
    return connect_tcp_udp(link_id, type, ip, port, local_port);
}

int net_link_listen_tcp(uint16_t local_port)
{
    int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -2;
    }
    int reuse = 1;
    lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (lwip_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || lwip_listen(fd, 4) < 0) {
        lwip_close(fd);
        return -2;
    }

    links_lock();
    int id = find_free_slot_locked();
    if (id < 0) {
        links_unlock();
        lwip_close(fd);
        return -1;
    }
    s_links[id].in_use = true;
    s_links[id].type = NET_LINK_TCP;
    s_links[id].is_listener = true;
    s_links[id].is_server_role = true;
    s_links[id].fd = fd;
    s_links[id].local_port = local_port;
    links_unlock();
    return id;
}

int net_link_listen_ssl(uint16_t local_port, const char *cert_name)
{
    if (!cert_name || cert_name[0] == '\0') {
        return -4;
    }
    char *cert_pem = g_at_pem_scratch; /* shared scratch, copied into the per-slot array below */
    if (!load_cert_file(cert_name, cert_pem, AT_PEM_SCRATCH_LEN)) {
        return -4;
    }

    /* The listener socket itself is plain TCP -- only accepted children get
     * wrapped in TLS (see handle_accept()) -- so plain listen setup applies
     * unchanged; just relabel the slot's type afterward. */
    int id = net_link_listen_tcp(local_port);
    if (id < 0) {
        return id;
    }
    links_lock();
    s_links[id].type = NET_LINK_SSL;
    links_unlock();
    strlcpy(s_ssl_server_pem[id], cert_pem, sizeof(s_ssl_server_pem[id]));
    return id;
}

int net_link_listen_udp(uint16_t local_port)
{
    int fd = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -2;
    }
    int reuse = 1;
    lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (lwip_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        lwip_close(fd);
        return -2;
    }

    links_lock();
    int id = find_free_slot_locked();
    if (id < 0) {
        links_unlock();
        lwip_close(fd);
        return -1;
    }
    s_links[id].in_use = true;
    s_links[id].type = NET_LINK_UDP;
    s_links[id].is_listener = false; /* UDP has no accept step -- this slot IS the link */
    s_links[id].is_server_role = true;
    s_links[id].fd = fd;
    s_links[id].local_port = local_port;
    strlcpy(s_links[id].remote_ip, "0.0.0.0", sizeof(s_links[id].remote_ip)); /* no peer learned yet */
    links_unlock();
    return id;
}

int net_link_find_server(net_link_type_t type, uint16_t local_port)
{
    links_lock();
    int found = -1;
    for (int i = 0; i < NET_MAX_LINKS; i++) {
        if (s_links[i].in_use && s_links[i].is_server_role && s_links[i].type == type &&
            s_links[i].local_port == local_port) {
            found = i;
            break;
        }
    }
    links_unlock();
    return found;
}

esp_err_t net_link_send(int link_id, const uint8_t *data, size_t len)
{
    if (link_id < 0 || link_id >= NET_MAX_LINKS) {
        return ESP_ERR_INVALID_ARG;
    }

    links_lock();
    if (!s_links[link_id].in_use || s_links[link_id].is_listener || s_links[link_id].tls_handshaking) {
        links_unlock();
        return ESP_ERR_INVALID_STATE;
    }
    int fd = s_links[link_id].fd;
    net_link_type_t type = s_links[link_id].type;
    esp_tls_t *tls = s_links[link_id].tls;
    char remote_ip[16];
    uint16_t remote_port = s_links[link_id].remote_port;
    strlcpy(remote_ip, s_links[link_id].remote_ip, sizeof(remote_ip));
    links_unlock();

    if (type == NET_LINK_SSL) {
        /* WANT_READ/WRITE during write is normally transient (peer just
         * hasn't drained its receive buffer yet) -- retry with a short
         * yield instead of busy-spinning the single AT dispatcher thread,
         * bounded so a genuinely stuck peer can't hang the command
         * interface (same NET_CONNECT_TIMEOUT_MS budget as a connect). */
        size_t sent = 0;
        int64_t deadline = esp_timer_get_time() + (int64_t)NET_CONNECT_TIMEOUT_MS * 1000;
        while (sent < len) {
            int n = esp_tls_conn_write(tls, data + sent, len - sent);
            if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
                if (esp_timer_get_time() > deadline) {
                    return ESP_FAIL;
                }
                vTaskDelay(1);
                continue;
            }
            if (n <= 0) {
                return ESP_FAIL;
            }
            sent += (size_t)n;
        }
        return ESP_OK;
    }

    ssize_t n;
    if (type == NET_LINK_UDP) {
        if (remote_port == 0) {
            /* A UDP server link that hasn't received anything yet has no
             * peer to reply to (doc's UDP examples always recv first). */
            return ESP_ERR_INVALID_STATE;
        }
        struct sockaddr_in remote = {0};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(remote_port);
        lwip_inet_pton(AF_INET, remote_ip, &remote.sin_addr);
        n = lwip_sendto(fd, data, len, 0, (struct sockaddr *)&remote, sizeof(remote));
    } else {
        n = lwip_send(fd, data, len, 0);
    }
    return (n == (ssize_t)len) ? ESP_OK : ESP_FAIL;
}

void net_link_close(int link_id)
{
    if (link_id < 0 || link_id >= NET_MAX_LINKS) {
        return;
    }
    links_lock();
    if (s_links[link_id].in_use) {
        close_slot_locked(link_id);
    }
    links_unlock();
}

void net_link_close_all(void)
{
    links_lock();
    for (int i = 0; i < NET_MAX_LINKS; i++) {
        if (s_links[i].in_use) {
            close_slot_locked(i);
        }
    }
    links_unlock();
}

void net_link_snapshot(net_link_t out[NET_MAX_LINKS])
{
    links_lock();
    memcpy(out, s_links, sizeof(s_links));
    links_unlock();
}

/* --- background RX/accept task ------------------------------------------
 * A short (200ms) select() timeout is used instead of a wake-pipe so a
 * freshly-opened link (added to s_links by one of the functions above,
 * running on the AT command dispatcher task) gets picked up promptly
 * without needing cross-task fd-set signaling. */

#define NET_SSL_HANDSHAKE_TIMEOUT_US (10LL * 1000 * 1000)

static void handle_accept(int listener_id)
{
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int fd = lwip_accept(s_links[listener_id].fd, (struct sockaddr *)&peer, &peer_len);
    if (fd < 0) {
        return;
    }
    net_link_type_t listener_type = s_links[listener_id].type; /* TCP or SSL */

    /* EN 18031-1 RLM-1: with every slot busy, drop the client before
     * spending a TLS context (~20 KB of heap) on it. The slot is re-checked
     * below in case NET_CONN took one meanwhile. */
    links_lock();
    bool full = find_free_slot_locked() < 0;
    links_unlock();
    if (full) {
        lwip_close(fd);
        return;
    }

    esp_tls_t *tls = NULL;
    if (listener_type == NET_LINK_SSL) {
        /* Non-blocking so the shared task's later handshake/read/write calls
         * never stall servicing the other links. */
        int flags = lwip_fcntl(fd, F_GETFL, 0);
        lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        esp_tls_cfg_server_t cfg = {0};
        cfg.servercert_buf = (const unsigned char *)s_ssl_server_pem[listener_id];
        cfg.servercert_bytes = (unsigned int)strlen(s_ssl_server_pem[listener_id]) + 1;
        cfg.serverkey_buf = (const unsigned char *)s_ssl_server_pem[listener_id];
        cfg.serverkey_bytes = (unsigned int)strlen(s_ssl_server_pem[listener_id]) + 1;

        tls = esp_tls_init();
        if (!tls || esp_tls_server_session_init(&cfg, fd, tls) != ESP_OK) {
            /* Doc has no "TLS setup failed" code for an inbound client --
             * just drop it, same treatment as "all 4 slots busy" below. */
            if (tls) {
                esp_tls_conn_destroy(tls);
            } else {
                lwip_close(fd);
            }
            return;
        }
        /* esp_tls_server_session_init() only starts the handshake --
         * handle_ssl_handshake_progress() drives it to completion across
         * later shared-task ticks via esp_tls_server_session_continue_async(). */
    }

    links_lock();
    int id = find_free_slot_locked();
    if (id < 0) {
        links_unlock();
        if (tls) {
            esp_tls_conn_destroy(tls);
        } else {
            lwip_close(fd); /* all 4 slots busy -- doc has no "server full" code, just drop */
        }
        return;
    }
    s_links[id].in_use = true;
    s_links[id].type = listener_type;
    s_links[id].is_listener = false;
    s_links[id].is_server_role = false;
    s_links[id].fd = fd;
    s_links[id].tls = tls;
    s_links[id].tls_handshaking = (listener_type == NET_LINK_SSL);
    s_links[id].handshake_deadline_us = esp_timer_get_time() + NET_SSL_HANDSHAKE_TIMEOUT_US;
    s_links[id].local_port = s_links[listener_id].local_port;
    lwip_inet_ntop(AF_INET, &peer.sin_addr, s_links[id].remote_ip, sizeof(s_links[id].remote_ip));
    s_links[id].remote_port = ntohs(peer.sin_port);
    char ip[16];
    strlcpy(ip, s_links[id].remote_ip, sizeof(ip));
    uint16_t port = s_links[id].remote_port;
    links_unlock();

    /* Doc Ch.8.4: notification flow is identical to plain TCP -- accepted
     * is reported at the TCP accept() point regardless of TLS, same as
     * plain TCP; a handshake that later fails surfaces as NET_CLI_CLOSED,
     * same as any other link death (see handle_ssl_handshake_progress()). */
    at_event_post("NET_CLI_ACCEPTED:%d %s %d", id, ip, port);
}

/* Drives one server-accepted SSL child's handshake forward by one step.
 * Called from the shared task instead of handle_readable_data_link() while
 * tls_handshaking is set -- see net_link.h's top comment for why this has
 * to be a multi-tick state machine here (unlike the client CONNECT side). */
static void handle_ssl_handshake_progress(int id)
{
    links_lock();
    esp_tls_t *tls = s_links[id].tls;
    int64_t deadline = s_links[id].handshake_deadline_us;
    links_unlock();

    int ret = esp_tls_server_session_continue_async(tls);
    if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
        if (esp_timer_get_time() < deadline) {
            return; /* not done yet, retry on a later tick */
        }
        /* EN 18031-1 RLM-1: a client that connects and never finishes the
         * handshake would otherwise hold one of the NET_MAX_LINKS slots
         * (shared with NET_CONN) forever -- treat it as a failed handshake. */
        ret = -1;
    }
    if (ret != 0) {
        /* Handshake failed -- the client never reached a usable state, so
         * this is the first and only notice it existed at all beyond
         * NET_CLI_ACCEPTED, same as a plain TCP link dying before any data. */
        char ip[16];
        uint16_t port;
        links_lock();
        strlcpy(ip, s_links[id].remote_ip, sizeof(ip));
        port = s_links[id].remote_port;
        close_slot_locked(id);
        links_unlock();
        at_event_post("NET_CLI_CLOSED:%d %s %d", id, ip, port);
        return;
    }

    links_lock();
    s_links[id].tls_handshaking = false;
    links_unlock();
}

static void handle_readable_data_link(int id)
{
    links_lock();
    int fd = s_links[id].fd;
    net_link_type_t type = s_links[id].type;
    esp_tls_t *tls = s_links[id].tls;
    uint16_t local_port = s_links[id].local_port;
    links_unlock();

    static uint8_t buf[1500]; /* one Ethernet-MTU-ish chunk per wakeup; large
                                * transfers just arrive as several RECV:IND
                                * lines, which the doc doesn't forbid. */
    struct sockaddr_in from = {0};
    socklen_t from_len = sizeof(from);
    ssize_t n;

    if (type == NET_LINK_SSL) {
        n = esp_tls_conn_read(tls, buf, sizeof(buf));
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            return; /* not a close, just nothing ready this tick */
        }
    } else if (type == NET_LINK_UDP) {
        n = lwip_recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
    } else {
        n = lwip_recv(fd, buf, sizeof(buf), 0);
    }

    if (n <= 0) {
        if (type == NET_LINK_TCP || type == NET_LINK_SSL) {
            char ip[16];
            uint16_t port;
            links_lock();
            strlcpy(ip, s_links[id].remote_ip, sizeof(ip));
            port = s_links[id].remote_port;
            close_slot_locked(id);
            links_unlock();
            if (s_passthrough_link == id) {
                s_passthrough_link = -1; /* link died mid-passthrough */
            }
            at_event_post("NET_CLI_CLOSED:%d %s %d", id, ip, port);
        }
        /* UDP recv error: nothing to report, the "link" (a bound local
         * socket) stays open regardless. */
        return;
    }

    if (s_passthrough_link == id) {
        /* doc Ch.8.5: passthrough data is relayed raw, no NET_RECV:IND
         * framing at all. */
        at_uart_write((const char *)buf, (size_t)n);
        return;
    }

    char ip[16] = "0.0.0.0";
    uint16_t port = local_port;
    if (type == NET_LINK_UDP) {
        lwip_inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        port = ntohs(from.sin_port);
        links_lock();
        strlcpy(s_links[id].remote_ip, ip, sizeof(s_links[id].remote_ip));
        s_links[id].remote_port = port; /* learn the peer so NET_SEND can reply */
        links_unlock();
    } else {
        links_lock();
        strlcpy(ip, s_links[id].remote_ip, sizeof(ip));
        port = s_links[id].remote_port;
        links_unlock();
    }

    char header[64];
    int hlen = snprintf(header, sizeof(header), "*M2M*NET_RECV:IND %d %s %d %d ",
                         id, ip, port, (int)n);
    char crlf[2] = {'\r', '\n'};
    /* Payload is raw, un-stuffed bytes per doc Ch.1.4 -- write it verbatim,
     * not through a %s/printf path that would stop at an embedded NUL. */
    if (hlen > 0 && (size_t)hlen < sizeof(header)) {
        at_uart_write_atomic2(header, (size_t)hlen, (const char *)buf, (size_t)n);
        at_uart_write(crlf, sizeof(crlf));
    }
}

static void net_link_task(void *arg)
{
    (void)arg;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        net_link_t snap[NET_MAX_LINKS];
        net_link_snapshot(snap);

        /* SSL handshakes-in-progress are retried every tick unconditionally
         * (not gated on select() readability below) -- continue_async() can
         * legitimately want to write (e.g. the server's own Certificate
         * flight), and this loop's select() only ever watches for read
         * readiness, so waiting for FD_ISSET here could stall a handshake
         * that's actually blocked on a write. A wasted call once per 200ms
         * tick per handshaking link is cheap enough not to bother tracking
         * which direction it's actually waiting on. */
        for (int i = 0; i < NET_MAX_LINKS; i++) {
            if (snap[i].in_use && snap[i].tls_handshaking) {
                handle_ssl_handshake_progress(i);
            }
        }

        for (int i = 0; i < NET_MAX_LINKS; i++) {
            if (snap[i].in_use && snap[i].fd >= 0 && !snap[i].tls_handshaking) {
                FD_SET(snap[i].fd, &rfds);
                if (snap[i].fd > maxfd) {
                    maxfd = snap[i].fd;
                }
            }
        }

        if (maxfd < 0) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        int ready = lwip_select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready <= 0) {
            continue;
        }

        for (int i = 0; i < NET_MAX_LINKS; i++) {
            if (!snap[i].in_use || snap[i].fd < 0 || snap[i].tls_handshaking || !FD_ISSET(snap[i].fd, &rfds)) {
                continue;
            }
            /* Re-check in_use under the lock inline via the handlers below
             * (they re-read s_links themselves) -- snap[] is only used to
             * decide which fds to poll this iteration. */
            if (snap[i].is_listener) {
                handle_accept(i);
            } else {
                handle_readable_data_link(i);
            }
        }
    }
}

void net_link_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    for (int i = 0; i < NET_MAX_LINKS; i++) {
        s_links[i].fd = -1;
    }
    xTaskCreate(net_link_task, "net_link", 4096, NULL, 8, NULL);
    ESP_LOGI(TAG, "socket engine ready (%d links)", NET_MAX_LINKS);
}
