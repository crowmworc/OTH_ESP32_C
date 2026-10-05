#pragma once
/* Socket engine backing AT*M2M*NET_* (doc Ch.4): up to NET_MAX_LINKS
 * concurrent TCP/UDP/SSL links, numbered 0-3 exactly like the doc's
 * <link_id>.
 *
 * A TCP or SSL listener started by NET_SERVER occupies a slot of its own
 * (shown in NET_STATUS as role=server, remote 0.0.0.0:0) -- accepted client
 * connections are handed their OWN separate slot on accept(), reported via
 * *M2M*NET_CLI_ACCEPTED. A UDP "server" has no accept() step, so its
 * NET_SERVER-started socket occupies the slot directly and both sends and
 * receives happen on that one link_id (doc Ch.8.3's UDP server example:
 * link 3 throughout).
 *
 * SSL/TLS (doc Ch.8.4: "notification flow is identical to the plain TCP
 * case") reuses this same link table and the shared background task rather
 * than a separate code path -- see net_link.c's top comment for how. A
 * client link's handshake completes synchronously inside net_link_connect()
 * (same bounded-blocking-with-timeout precedent as plain TCP connect, and
 * required by NET_CONN's synchronous OK/ERROR contract, doc Ch.1.3); a
 * server link's per-accepted-client handshake instead progresses across
 * several shared-task ticks via tls_handshaking below, since blocking the
 * one shared task would stall every other link.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NET_MAX_LINKS 4

/* Forward declaration matching esp_tls.h's own "typedef struct esp_tls
 * esp_tls_t;" -- kept opaque here so plain TCP/UDP-only consumers of this
 * header (cmd_net.c et al) don't need to pull in esp_tls.h just to see
 * net_link_t's layout. */
typedef struct esp_tls esp_tls_t;

typedef enum {
    NET_LINK_NONE = 0,
    NET_LINK_TCP,
    NET_LINK_UDP,
    NET_LINK_SSL,
} net_link_type_t;

typedef struct {
    bool in_use;
    net_link_type_t type;
    bool is_listener;   /* TCP/SSL listen socket -- doesn't itself carry data */
    bool is_server_role; /* doc's NET_STATUS "role" field: listener or a
                           * UDP server link report role=1(server); an
                           * outbound client connection or an
                           * accepted-from-listener link report role=0. */
    int fd;
    char remote_ip[16];
    uint16_t remote_port;
    uint16_t local_port;
    esp_tls_t *tls;          /* NULL unless type==NET_LINK_SSL */
    bool tls_handshaking;    /* server-accepted SSL child only, see above */
    int64_t handshake_deadline_us; /* esp_timer time the handshake must finish by */
} net_link_t;

/** Starts the shared select()-based RX/accept background task. */
void net_link_init(void);

/**
 * AT*M2M*NET_CONN: outbound TCP, UDP or SSL on the host-chosen `link_id`
 * (doc Ch.4.2 -- unlike NET_SERVER, NET_CONN's link_id is a parameter the
 * host picks, not one the module assigns). `local_port`==0 lets the OS pick
 * one (SSL links always auto-pick -- esp_tls_conn_new_sync() has no bind
 * step, same "accepted but not applied" tier as the doc's `keep_alive`
 * param). `cert_name` (may be NULL/empty) is a client cert+key file for
 * mutual TLS, previously stored via NET_HTTPDOWNLOAD (doc Ch.6.2); ignored
 * for TCP/UDP. Without it, an SSL connect still validates the server's
 * certificate against the default public CA bundle (esp_crt_bundle_attach,
 * same as this project's HTTP/MQTT/OTA clients) -- doc's "server-only
 * validation" case. Returns 0 on success, or -1 (link_id already in use) /
 * -2 (connect, cert-load, or TLS handshake failed) / -3 (unsupported type
 * or out-of-range link_id).
 */
int net_link_connect(int link_id, net_link_type_t type, const char *ip, uint16_t port,
                      uint16_t local_port, const char *cert_name);

/** NET_SERVER=1 tcp: start listening. Accepted clients get their own link_id
 * later (async *M2M*NET_CLI_ACCEPTED). Returns the listener's link_id, or
 * the same negative codes as net_link_connect(). */
int net_link_listen_tcp(uint16_t local_port);

/** NET_SERVER=1 udp: bind a socket that IS the link (no accept step). */
int net_link_listen_udp(uint16_t local_port);

/** NET_SERVER=1 ssl: like net_link_listen_tcp(), but each accepted
 * connection is wrapped in TLS using the server cert+key loaded from
 * `cert_name` (required, doc: "required when <type> is ssl" -- a single
 * file supplying both PEM blocks, same convention NET_CONN's client
 * cert_name uses). Handshakes run asynchronously per accepted client, see
 * net_link.h's top comment. Returns the listener's link_id, the same
 * negative codes as net_link_listen_tcp(), or -4 if cert_name couldn't be
 * loaded. */
int net_link_listen_ssl(uint16_t local_port, const char *cert_name);

/** Find an in-use TCP listener or UDP server link by (type, local_port) --
 * used by NET_SERVER's disable form and its Query form. -1 if none. */
int net_link_find_server(net_link_type_t type, uint16_t local_port);

/** NET_SEND: raw bytes, no byte-(un)stuffing here -- callers already
 * decoded the wire payload per doc Ch.1.4 before calling this. For a UDP
 * link with no prior traffic (remote_port==0), sends nowhere and returns
 * ESP_ERR_INVALID_STATE -- doc's UDP examples always recv (learn the peer)
 * before they send. */
esp_err_t net_link_send(int link_id, const uint8_t *data, size_t len);

/** NET_DISCONN: close one link (listener or data link) and free its slot. */
void net_link_close(int link_id);

/** NET_DISCONN with no argument: close every in-use link. */
void net_link_close_all(void);

/** Thread-safe snapshot of the whole table for NET_STATUS/introspection. */
void net_link_snapshot(net_link_t out[NET_MAX_LINKS]);

/**
 * AT*M2M*NET_DTMODE=1 <link_id>: while `link_id` is the passthrough link,
 * bytes it receives are written straight to the AT UART with no
 * "*M2M*NET_RECV:IND" framing (doc Ch.8.5) -- pairs with
 * at_uart_set_passthrough() on the host->link direction. Pass -1 to return
 * to normal NET_RECV:IND framing for every link.
 */
void net_link_set_passthrough(int link_id);

#ifdef __cplusplus
}
#endif
