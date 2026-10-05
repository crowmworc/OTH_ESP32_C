/* AT*OTH* TCP/IP and SSL AT Commands (OTH-AT Essentials Ch.4/5), on the
 * oth_sock.c engine. Payloads of SEND/SENDTO/SSL_SEND/SSL_SVR_SEND are
 * byte-stuffed (Ch.1.4) and limited to 1460 bytes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/ip_addr.h"
#include "esp_netif.h"

#include "at_commands.h"
#include "at_commands_oth.h"
#include "at_response.h"
#include "at_byte_stuffing.h"
#include "at_nvs_kv.h"
#include "at_wifi.h"
#include "oth_sock.h"

#define OTH_PAYLOAD_MAX 1460

static bool parse_port(const char *s, uint16_t *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 65535) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

static bool parse_sd(const char *s, int *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || end == s) {
        return false;
    }
    *out = (int)v;
    return true;
}

static void reply(const at_command_t *cmd, int err)
{
    if (err) {
        at_reply_error(cmd->name, err);
    } else {
        at_reply_ok(cmd->name, NULL);
    }
}

/* Splits raw_params into `nfields` space-separated fields followed by the
 * byte-stuffed payload (which may itself contain spaces), checks the
 * <size> field (the last of the fields) against the decoded payload, and
 * returns the decoded length, or -1. */
static int split_payload(const at_command_t *cmd, char *fields[], int nfields, const uint8_t **data)
{
    static uint8_t decoded[OTH_PAYLOAD_MAX];
    char *p = cmd->raw_params;
    if (!p) {
        return -1;
    }
    for (int i = 0; i < nfields; i++) {
        while (*p == ' ') {
            p++;
        }
        if (!*p) {
            return -1;
        }
        fields[i] = p;
        while (*p && *p != ' ') {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
    }
    char *end;
    long size = strtol(fields[nfields - 1], &end, 10);
    if (*end != '\0' || size <= 0 || size > OTH_PAYLOAD_MAX) {
        return -1;
    }
    size_t n = at_byte_stuff_decode(p, strlen(p), decoded, sizeof(decoded));
    if ((long)n != size) {
        return -1;
    }
    *data = decoded;
    return (int)n;
}

/* ---- IPCONFIG -------------------------------------------------------------- */

/* AT*OTH*IPCONFIG=<dhcp_mode> [ip] [subnet] [gateway] / =? -- station. */
void cmd_oth_ipconfig(const at_command_t *cmd)
{
    esp_netif_t *sta = at_wifi_get_sta_netif();
    if (at_is_query(cmd) || cmd->argc == 0) {
        esp_netif_ip_info_t ip = {0};
        esp_netif_dns_info_t dns = {0};
        esp_netif_dhcp_status_t st = ESP_NETIF_DHCP_INIT;
        esp_netif_get_ip_info(sta, &ip);
        esp_netif_get_dns_info(sta, ESP_NETIF_DNS_MAIN, &dns);
        esp_netif_dhcpc_get_status(sta, &st);
        at_reply_ok(cmd->name, "%d " IPSTR " " IPSTR " " IPSTR " " IPSTR, st == ESP_NETIF_DHCP_STOPPED ? 0 : 1,
                    IP2STR(&ip.ip), IP2STR(&ip.netmask), IP2STR(&ip.gw), IP2STR(&dns.ip.u_addr.ip4));
        return;
    }
    bool ok;
    if (strcmp(cmd->argv[0], "1") == 0) {
        ok = at_wifi_set_station_ip(true, NULL, NULL, NULL);
    } else if (strcmp(cmd->argv[0], "0") == 0 && cmd->argc >= 4) {
        ok = at_wifi_set_station_ip(false, cmd->argv[1], cmd->argv[2], cmd->argv[3]);
    } else {
        ok = false;
    }
    reply(cmd, ok ? 0 : OTH_ERR_TCPIP_PARAM);
}

/* ---- sockets ---------------------------------------------------------------- */

/* AT*OTH*SOCKET=<type> -- 1: TCP, 2: UDP, 4: SSL client. */
void cmd_oth_socket(const at_command_t *cmd)
{
    int sd;
    int err = cmd->argc >= 1 ? oth_sock_create(atoi(cmd->argv[0]), &sd) : OTH_ERR_GENERAL_PARAM;
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, "%d", sd);
}

void cmd_oth_close(const at_command_t *cmd)
{
    int sd;
    reply(cmd, cmd->argc >= 1 && parse_sd(cmd->argv[0], &sd) ? oth_sock_close(sd) : OTH_ERR_SOCKET_INVALID);
}

/* AT*OTH*CONNECT=<sd> <ip> <port> -- OK, then *OTH*CONNECTED:<sd> (or
 * TIMEOUT / REJECTED). */
void cmd_oth_connect(const at_command_t *cmd)
{
    int sd;
    uint16_t port;
    if (cmd->argc < 3 || !parse_sd(cmd->argv[0], &sd) || !parse_port(cmd->argv[2], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_sock_connect(sd, cmd->argv[1], port));
}

/* AT*OTH*DISCONNECT=<sd> <ip> <port> -- drop one client of a TCP server. */
void cmd_oth_disconnect(const at_command_t *cmd)
{
    int sd;
    uint16_t port;
    if (cmd->argc < 3 || !parse_sd(cmd->argv[0], &sd) || !parse_port(cmd->argv[2], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_sock_drop_client(sd, cmd->argv[1], port));
}

void cmd_oth_bind(const at_command_t *cmd)
{
    int sd;
    uint16_t port;
    if (cmd->argc < 2 || !parse_sd(cmd->argv[0], &sd) || !parse_port(cmd->argv[1], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_sock_bind(sd, port));
}

void cmd_oth_listen(const at_command_t *cmd)
{
    int sd;
    reply(cmd, cmd->argc >= 1 && parse_sd(cmd->argv[0], &sd) ? oth_sock_listen(sd) : OTH_ERR_SOCKET_INVALID);
}

/* AT*OTH*LSTATUS=<sd> -- "<sd> [ip port] ..." of the connected clients. */
void cmd_oth_lstatus(const at_command_t *cmd)
{
    int sd;
    char out[160];
    int err = cmd->argc >= 1 && parse_sd(cmd->argv[0], &sd) ? oth_sock_list_clients(sd, out, sizeof(out))
                                                             : OTH_ERR_SOCKET_INVALID;
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, "%s", out);
}

/* AT*OTH*SEND=<sd> <ip> <port> <size> <payload> -- 0 0 for a connected
 * client socket. */
void cmd_oth_send(const at_command_t *cmd)
{
    char *f[4];
    const uint8_t *data;
    int sd;
    uint16_t port;
    int n = split_payload(cmd, f, 4, &data);
    if (n < 0 || !parse_sd(f[0], &sd) || !parse_port(f[2], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_sock_send(sd, f[1], port, data, (size_t)n));
}

/* AT*OTH*SENDTO=<sd> <ip> <port> <size> <payload> -- UDP. */
void cmd_oth_sendto(const at_command_t *cmd)
{
    char *f[4];
    const uint8_t *data;
    int sd;
    uint16_t port;
    int n = split_payload(cmd, f, 4, &data);
    if (n < 0 || !parse_sd(f[0], &sd) || !parse_port(f[2], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_sock_sendto(sd, f[1], port, data, (size_t)n));
}

/* AT*OTH*TCPKEEP=<keep_time> <keep_count> / =? -- keep_time in seconds
 * (idle time before the first probe, and between probes), keep_count the
 * number of probes; 0 0 (default) turns keep-alive off. Kept in NV memory. */
void cmd_oth_tcpkeep(const at_command_t *cmd)
{
    uint16_t t = 0, c = 0;
    if (at_is_query(cmd) || cmd->argc == 0) {
        m2m_nvs_get_u16("keep_t", &t);
        m2m_nvs_get_u16("keep_c", &c);
        at_reply_ok(cmd->name, "%u %u", t, c);
        return;
    }
    long tv = cmd->argc >= 2 ? atol(cmd->argv[0]) : -1;
    long cv = cmd->argc >= 2 ? atol(cmd->argv[1]) : -1;
    if (tv < 0 || tv > 65535 || cv < 0 || cv > 255) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    m2m_nvs_set_u16("keep_t", (uint16_t)tv);
    m2m_nvs_set_u16("keep_c", (uint16_t)cv);
    oth_sock_set_keepalive((int)tv, (int)cv);
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*NW_CONN -- descriptor of a socket with a remote connection, or -1. */
void cmd_oth_nw_conn(const at_command_t *cmd)
{
    at_reply_ok(cmd->name, "%d", oth_sock_connected_sd());
}

/* AT*OTH*PING=<count> <target_ip> <size> -- OK, then *OTH*PINGREPLY:<ip>
 * <size> <time> per reply. */
void cmd_oth_ping(const at_command_t *cmd)
{
    int count = cmd->argc >= 3 ? atoi(cmd->argv[0]) : 0;
    int size = cmd->argc >= 3 ? atoi(cmd->argv[2]) : -1;
    ip_addr_t target;
    if (count <= 0 || count > 100 || size < 0 || size > OTH_PAYLOAD_MAX || !ipaddr_aton(cmd->argv[1], &target)) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    at_net_ping_run(cmd->name, &target, count, size, true);
}

/* AT*OTH*DNSQUERY=<hostname> -- OK, then *OTH*DNSRESPONSE:<ip>. */
void cmd_oth_dnsquery(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    if (lwip_getaddrinfo(cmd->argv[0], NULL, &hints, &res) != 0 || !res) {
        at_reply_error(cmd->name, OTH_ERR_CONNECTION_ESTABLISHMENT);
        return;
    }
    char ip[16];
    lwip_inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof(ip));
    lwip_freeaddrinfo(res);
    at_reply_ok(cmd->name, NULL);
    at_reply_line("DNSRESPONSE:%s", ip);
}

/* AT*OTH*DATA_SOCKET=<type> <remote_ip> <remote_port> <local_port> */
void cmd_oth_data_socket(const at_command_t *cmd)
{
    uint16_t rport, lport;
    if (cmd->argc < 4 || !parse_port(cmd->argv[2], &rport) || !parse_port(cmd->argv[3], &lport)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    int sd;
    int err = oth_sock_data_open(atoi(cmd->argv[0]), cmd->argv[1], rport, lport, &sd);
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, "%d", sd);
    oth_sock_data_start();
}

/* AT*OTH*DATA_INTERVAL=<ms> / =? -- 10..1000, otherwise the 200 ms default. */
void cmd_oth_data_interval(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        at_reply_ok(cmd->name, "%d", oth_sock_data_interval());
        return;
    }
    oth_sock_set_data_interval(atoi(cmd->argv[0]));
    at_reply_ok(cmd->name, NULL);
}

/* ---- SSL --------------------------------------------------------------------- */

/* AT*OTH*SSL_CONNECT=<sd> <ip> <port> -- OK, then *OTH*SSL_IND:<sd> 0 OK|ERROR.
 * The server certificate is verified (stored ca.pem, else public CAs). */
void cmd_oth_ssl_connect(const at_command_t *cmd)
{
    int sd;
    uint16_t port;
    if (cmd->argc < 3 || !parse_sd(cmd->argv[0], &sd) || !parse_port(cmd->argv[2], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_ssl_connect(sd, cmd->argv[1], port));
}

/* AT*OTH*SSL_SEND=<sd> <size> <payload> */
void cmd_oth_ssl_send(const at_command_t *cmd)
{
    char *f[2];
    const uint8_t *data;
    int sd;
    int n = split_payload(cmd, f, 2, &data);
    if (n < 0 || !parse_sd(f[0], &sd)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_ssl_send(sd, data, (size_t)n));
}

void cmd_oth_ssl_close(const at_command_t *cmd)
{
    int sd;
    if (cmd->argc < 1 || !parse_sd(cmd->argv[0], &sd) || sd != OTH_SD_SSL) {
        at_reply_error(cmd->name, OTH_ERR_SOCKET_INVALID);
        return;
    }
    reply(cmd, oth_sock_close(sd));
}

/* AT*OTH*SSL_SVR_START=0 <port> -- the server certificate and key are the
 * PEM file "server.pem" stored on the module (HTTP_DOWNLOAD or the web
 * TLS screen). Clients: *OTH*SSL_SVR_ACCEPTED:<1|2>. */
void cmd_oth_ssl_svr_start(const at_command_t *cmd)
{
    int sd;
    uint16_t port;
    if (cmd->argc < 2 || !parse_sd(cmd->argv[0], &sd) || sd != 0 || !parse_port(cmd->argv[1], &port)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_ssl_svr_start(port));
}

/* AT*OTH*SSL_SVR_SEND=<client_sd> <size> <payload> */
void cmd_oth_ssl_svr_send(const at_command_t *cmd)
{
    char *f[2];
    const uint8_t *data;
    int csd;
    int n = split_payload(cmd, f, 2, &data);
    if (n < 0 || !parse_sd(f[0], &csd)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    reply(cmd, oth_ssl_svr_send(csd, data, (size_t)n));
}

void cmd_oth_ssl_svr_close(const at_command_t *cmd)
{
    int sd;
    if (cmd->argc < 1 || !parse_sd(cmd->argv[0], &sd) || sd != 0) {
        at_reply_error(cmd->name, OTH_ERR_SOCKET_INVALID);
        return;
    }
    reply(cmd, oth_ssl_svr_close());
}

/* Boot: keep-alive settings from NV memory. */
void at_oth_net_init(void)
{
    uint16_t t = 0, c = 0;
    m2m_nvs_get_u16("keep_t", &t);
    m2m_nvs_get_u16("keep_c", &c);
    oth_sock_init();
    oth_sock_set_keepalive(t, c);
}
