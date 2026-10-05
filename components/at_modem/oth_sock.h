#pragma once
/* Socket engine behind the OTH-AT TCP/IP and SSL commands (Essentials
 * Ch.4/5). Same design as net_link.c (one select()-driven background task,
 * a mutex-guarded table), but with OTH-AT's BSD-style model:
 *   - AT*OTH*SOCKET creates a socket and hands out its descriptor: TCP 0-2,
 *     UDP 3-5, the SSL client 6.
 *   - CONNECT returns at once; the handshake ends in *OTH*CONNECTED,
 *     *OTH*TIMEOUT (9 s) or *OTH*REJECTED, the last two closing the socket.
 *   - a listening TCP socket keeps its descriptor for every client it
 *     accepts (ACCEPTED/RECV/DISCONNECTED carry the client's address, SEND
 *     names it), instead of one link per client as in M2M-AT.
 *   - one TLS server (descriptor 0) whose clients get descriptors 1-2.
 * Every function returns 0 or an OTH Appendix A error code. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OTH_SOCK_TCP   1
#define OTH_SOCK_UDP   2
#define OTH_SOCK_SSL   4

#define OTH_SD_SSL     6
#define OTH_SD_MAX     7

void oth_sock_init(void);

int oth_sock_create(int type, int *sd_out);
int oth_sock_close(int sd);
int oth_sock_connect(int sd, const char *host, uint16_t port);
int oth_sock_bind(int sd, uint16_t port);
int oth_sock_listen(int sd);
int oth_sock_drop_client(int sd, const char *ip, uint16_t port);
/* "<sd> [ip port] ..." for LSTATUS */
int oth_sock_list_clients(int sd, char *out, size_t cap);
/* TCP: ip "0" / port 0 = the connected peer, else one accepted client. */
int oth_sock_send(int sd, const char *ip, uint16_t port, const uint8_t *data, size_t len);
int oth_sock_sendto(int sd, const char *ip, uint16_t port, const uint8_t *data, size_t len);
/* NW_CONN: a socket with an established remote connection, or -1. */
int oth_sock_connected_sd(void);
void oth_sock_set_keepalive(int idle_s, int count);

/* SSL client (descriptor 6): handshake result follows as SSL_IND:<sd> 0. */
int oth_ssl_connect(int sd, const char *host, uint16_t port);
int oth_ssl_send(int sd, const uint8_t *data, size_t len);
/* SSL server: cert+key PEM from the stored file OTH_SSL_SERVER_CERT. */
#define OTH_SSL_SERVER_CERT "server.pem"
int oth_ssl_svr_start(uint16_t port);
int oth_ssl_svr_send(int csd, const uint8_t *data, size_t len);
int oth_ssl_svr_close(void);

/* DATA_SOCKET: type 1 TCP client, 2 UDP client, 4 TCP server, 8 UDP
 * server. Opens the socket and switches the UART to transparent mode. */
int oth_sock_data_open(int type, const char *rip, uint16_t rport, uint16_t lport, int *sd_out);
/* After DATA_SOCKET's OK: *OTH*DATAMODE, then transparent mode until
 * "+++" (followed by 500 ms of silence) or the peer is lost. */
void oth_sock_data_start(void);
void oth_sock_set_data_interval(int ms);
int oth_sock_data_interval(void);

#ifdef __cplusplus
}
#endif
