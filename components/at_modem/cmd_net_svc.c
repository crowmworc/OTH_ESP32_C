/* AT*M2M*NET_PING/NET_DNS/NET_SNTP/NET_SNTPCONF/NET_DHCPS/NET_DHCP --
 * standalone network services (doc Ch.4.2, 6.1) that don't touch the
 * net_link.c link table. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "ping/ping_sock.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "dhcpserver/dhcpserver.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_nvs_kv.h"
#include "at_wifi.h"
#include "at_cmdset.h"
#if CONFIG_AT_MODEM_CMDSET_OTH
#include "at_commands_oth.h"
#endif

/* --------------------------------------------------------------- NET_PING */

typedef struct {
    SemaphoreHandle_t done_sem;
    uint32_t sent;
    uint32_t received;
    bool oth; /* OTH-AT PING: *OTH*PINGREPLY per reply, no closing line */
} ping_ctx_t;

static void on_ping_success(esp_ping_handle_t hdl, void *args)
{
    ip_addr_t target_addr;
    uint32_t recv_len, elapsed_ms;
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_SIZE, &recv_len, sizeof(recv_len));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_ms, sizeof(elapsed_ms));
    char ip[16];
    ipaddr_ntoa_r(&target_addr, ip, sizeof(ip));
    if (((ping_ctx_t *)args)->oth) {
        at_reply_line("PINGREPLY:%s %u %u", ip, (unsigned)recv_len, (unsigned)elapsed_ms);
    } else {
        at_reply_line("NET_PING:IND %s %u %u", ip, (unsigned)recv_len, (unsigned)elapsed_ms);
    }
}

static void on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    (void)args; /* doc defines no per-timeout line -- only affects the final sent/received tally */
}

static void on_ping_end(esp_ping_handle_t hdl, void *args)
{
    ping_ctx_t *ctx = args;
    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &ctx->sent, sizeof(ctx->sent));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &ctx->received, sizeof(ctx->received));
    xSemaphoreGive(ctx->done_sem);
}

/* AT*M2M*NET_PING=<count> <target_ip> <size> */
void cmd_net_ping(const at_command_t *cmd)
{
    if (cmd->argc < 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int count = atoi(cmd->argv[0]);
    int size = atoi(cmd->argv[2]);
    if (count <= 0 || count > 100 || size < 0 || size > 1452) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    ip_addr_t target_addr;
    if (!ipaddr_aton(cmd->argv[1], &target_addr)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    at_net_ping_run(cmd->name, &target_addr, count, size, false);
}

/* Replies OK, then runs the ping to completion (bounded), writing one line
 * per reply. Shared by NET_PING and OTH-AT PING. */
void at_net_ping_run(const char *name, const ip_addr_t *target, int count, int size, bool oth)
{
    ip_addr_t target_addr = *target;
    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    config.target_addr = target_addr;
    config.count = (uint32_t)count;
    config.data_size = (uint32_t)size;

    ping_ctx_t ctx = {.done_sem = xSemaphoreCreateBinary(), .oth = oth};
    if (!ctx.done_sem) {
        at_reply_error(name, oth ? 7 : AT_ERR_GENERIC);
        return;
    }
    esp_ping_callbacks_t cbs = {
        .cb_args = &ctx,
        .on_ping_success = on_ping_success,
        .on_ping_timeout = on_ping_timeout,
        .on_ping_end = on_ping_end,
    };
    esp_ping_handle_t hdl;
    if (esp_ping_new_session(&config, &cbs, &hdl) != ESP_OK) {
        vSemaphoreDelete(ctx.done_sem);
        at_reply_error(name, oth ? 7 : AT_ERR_GENERIC);
        return;
    }

    at_reply_ok(name, NULL);
    esp_ping_start(hdl);
    /* Bounded wait: default interval 1s/request plus slack, so this can't
     * hang the AT dispatcher indefinitely against an unreachable host. */
    if (xSemaphoreTake(ctx.done_sem, pdMS_TO_TICKS((uint32_t)count * 1500 + 5000)) != pdTRUE) {
        if (!oth) {
            at_reply_line("NET_PING:ERROR %d", AT_ERR_TIMEOUT);
        }
    } else if (!oth) {
        at_reply_line("NET_PING:DONE %u %u", (unsigned)ctx.sent, (unsigned)ctx.received);
    }
    esp_ping_delete_session(hdl);
    /* esp_ping_delete_session() is fire-and-forget: it only clears a flag on
     * the session, it does NOT synchronously tear anything down. The actual
     * background ping task (ping_sock.c's esp_ping_thread()) only notices
     * that flag on its own next PING_CHECK_START_TIMEOUT_MS-ms (1000ms)
     * poll, and only *then* closes the raw ICMP socket and frees the
     * session. Without this wait, that socket (and one of
     * CONFIG_LWIP_MAX_RAW_PCBS's limited slots) stays open for up to a
     * second into whatever the AT host sends next -- since this handler
     * already blocks the whole AT dispatcher for the ping's duration
     * (undocumented as async, same as the rest of this command), waiting
     * here too costs nothing extra in practice and guarantees the socket is
     * actually gone before this command returns. */
    vTaskDelay(pdMS_TO_TICKS(1100));
    vSemaphoreDelete(ctx.done_sem);
}

/* ---------------------------------------------------------------- NET_DNS */

/* AT*M2M*NET_DNS=<hostname> */
void cmd_net_dns(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    if (lwip_getaddrinfo(cmd->argv[0], NULL, &hints, &res) != 0 || !res) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    char ip[16];
    lwip_inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof(ip));
    lwip_freeaddrinfo(res);
    at_reply_ok(cmd->name, "%s", ip);
}

/* --------------------------------------------------------------- NET_SNTP */

static bool s_sntp_ever_inited = false;

/* Doc: "tries the configured NTP server first (default pool.ntp.org) and
 * falls back to time.nist.gov and time.windows.com" -- the primary server
 * is configurable (NET_SNTPCONF mode=0), the two fallbacks are fixed. Fully
 * re-inits every call rather than trying to patch a running SNTP client's
 * server list in place -- NET_SNTP isn't a hot path, and this guarantees a
 * server change from NET_SNTPCONF is picked up on the next sync. */
static void ensure_sntp_configured(void)
{
    char server[64] = "";
    size_t len = sizeof(server);
    m2m_nvs_get_str("sntp_server", server, &len);
    if (server[0] == '\0') {
        strlcpy(server, "pool.ntp.org", sizeof(server));
    }

    if (s_sntp_ever_inited) {
        esp_netif_sntp_deinit();
    }
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(
        3, ESP_SNTP_SERVER_LIST(server, "time.nist.gov", "time.windows.com"));
    /* wait_for_sync must stay true (the macro's own default) -- it's what
     * makes esp_netif_sntp_init() allocate the sync semaphore that
     * cmd_net_sntp()'s esp_netif_sntp_sync_wait() call below blocks on.
     * This was previously forced to false here, which left that semaphore
     * NULL and made esp_netif_sntp_sync_wait() return ESP_ERR_INVALID_STATE
     * *immediately* on every call, regardless of network -- misdiagnosed for
     * a long time as the test network blocking NTP (see status xlsx/README
     * history for NET_SNTP), when the sync attempt never actually had a way
     * to succeed on any network. */
    esp_netif_sntp_init(&config);
    s_sntp_ever_inited = true;
}

/* Formats the synced time, offset by NET_SNTPCONF's hours, as
 * "Thu Oct 22 11:45:48 2015"; returns its length. */
static int sntp_time_string(char *buf, size_t cap)
{
    time_t now;
    time(&now);

    char offset_str[8] = "0";
    size_t len = sizeof(offset_str);
    m2m_nvs_get_str("sntp_offset", offset_str, &len);
    now += (time_t)(atoi(offset_str) * 3600);

    struct tm tm_info;
    gmtime_r(&now, &tm_info);
    return (int)strftime(buf, cap, "%a %b %d %H:%M:%S %Y", &tm_info);
}

/* AT*M2M*NET_SNTP -- Execute only. */
void cmd_net_sntp(const at_command_t *cmd)
{
    ensure_sntp_configured();
    at_reply_ok(cmd->name, NULL);

    if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(10000)) != ESP_OK) {
        at_reply_line("NET_SNTP:ERROR %d", AT_ERR_TIMEOUT);
        return;
    }
    char buf[32];
    int n = sntp_time_string(buf, sizeof(buf));
    at_reply_line("NET_SNTP:IND %d %s", n, buf);
    at_reply_line("NET_SNTP:DONE");
}

#if CONFIG_AT_MODEM_CMDSET_OTH
/* AT*OTH*SNTP -- OK, then *OTH*SNTP_RESPONSE:<length> <time> (or TIMEOUT);
 * ERROR 4 when not associated with an AP. */
void cmd_oth_sntp(const at_command_t *cmd)
{
    if (!at_wifi_sta_is_connected()) {
        at_reply_error(cmd->name, 4);
        return;
    }
    ensure_sntp_configured();
    at_reply_ok(cmd->name, NULL);
    if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(10000)) != ESP_OK) {
        at_reply_line("SNTP_RESPONSE:TIMEOUT");
        return;
    }
    char buf[32];
    int n = sntp_time_string(buf, sizeof(buf));
    at_reply_line("SNTP_RESPONSE:%d %s", n, buf);
}

bool at_sntp_ensure_synced(uint32_t wait_ms)
{
    time_t now = time(NULL);
    if (now > 1600000000) { /* already set (2020 or later) */
        return true;
    }
    if (!s_sntp_ever_inited) {
        ensure_sntp_configured();
    }
    return wait_ms && esp_netif_sntp_sync_wait(pdMS_TO_TICKS(wait_ms)) == ESP_OK;
}

/* AT*OTH*SNTP_GET=<index> / SNTP_SET=<index> <value> -- 0: NTP server
 * (max. 32 characters), 1: GMT offset in hours. Same NV items as
 * NET_SNTPCONF. */
void cmd_oth_sntp_get(const at_command_t *cmd)
{
    char v[64] = "";
    size_t len = sizeof(v);
    if (cmd->argc >= 1 && strcmp(cmd->argv[0], "0") == 0) {
        m2m_nvs_get_str("sntp_server", v, &len);
        at_reply_ok(cmd->name, "%s", v[0] ? v : "pool.ntp.org");
    } else if (cmd->argc >= 1 && strcmp(cmd->argv[0], "1") == 0) {
        m2m_nvs_get_str("sntp_offset", v, &len);
        at_reply_ok(cmd->name, "%s", v[0] ? v : "0");
    } else {
        at_reply_error(cmd->name, -1);
    }
}

void cmd_oth_sntp_set(const at_command_t *cmd)
{
    if (cmd->argc >= 2 && strcmp(cmd->argv[0], "0") == 0 && strlen(cmd->argv[1]) <= 32) {
        m2m_nvs_set_str("sntp_server", cmd->argv[1]);
    } else if (cmd->argc >= 2 && strcmp(cmd->argv[0], "1") == 0 && atoi(cmd->argv[1]) >= -12 &&
               atoi(cmd->argv[1]) <= 14) {
        char v[8];
        snprintf(v, sizeof(v), "%d", atoi(cmd->argv[1]));
        m2m_nvs_set_str("sntp_offset", v);
    } else {
        at_reply_error(cmd->name, 8);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}
#endif

/* AT*M2M*NET_SNTPCONF -- doc's own param table is internally inconsistent
 * (labels the Set command's 2nd argument "offset" even for mode=0, though
 * mode=0's own worked example clearly passes a server URL there, e.g.
 * "AT*M2M*NET_SNTPCONF=0 time.windows.com"); implemented per the worked
 * examples: mode 0's value is a server URL/IP, mode 1's is an integer
 * hour offset from GMT. Likewise the Query response is documented as
 * "<mode> <offset> <url>" but the worked example returns just one bare
 * value -- resolved here as "<url> <offset>" together. */
void cmd_net_sntpconf(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        char server[64] = "";
        size_t len = sizeof(server);
        m2m_nvs_get_str("sntp_server", server, &len);
        if (server[0] == '\0') {
            strlcpy(server, "pool.ntp.org", sizeof(server));
        }
        char offset[8] = "0";
        len = sizeof(offset);
        m2m_nvs_get_str("sntp_offset", offset, &len);
        at_reply_ok(cmd->name, "%s %s", server, offset);
        return;
    }

    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    if (mode == 0) {
        m2m_nvs_set_str("sntp_server", cmd->argv[1]);
    } else if (mode == 1) {
        m2m_nvs_set_str("sntp_offset", cmd->argv[1]);
    } else {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* -------------------------------------------------------------- NET_DHCPS */

/* AT*M2M*NET_DHCPS -- SoftAP DHCP server address pool/lease time. */
void cmd_net_dhcps(const at_command_t *cmd)
{
    esp_netif_t *ap = at_wifi_get_ap_netif();

    if (at_is_query(cmd) || cmd->argc == 0) {
        uint32_t lease_min = 0;
        dhcps_lease_t lease = {0};
        esp_netif_dhcps_option(ap, ESP_NETIF_OP_GET, ESP_NETIF_IP_ADDRESS_LEASE_TIME,
                                &lease_min, sizeof(lease_min));
        esp_netif_dhcps_option(ap, ESP_NETIF_OP_GET, ESP_NETIF_REQUESTED_IP_ADDRESS,
                                &lease, sizeof(lease));
        char start_ip[16], end_ip[16];
        ip4addr_ntoa_r(&lease.start_ip, start_ip, sizeof(start_ip));
        ip4addr_ntoa_r(&lease.end_ip, end_ip, sizeof(end_ip));
        at_reply_ok(cmd->name, "%u %s %s", (unsigned)lease_min, start_ip, end_ip);
        return;
    }

    if (cmd->argc < 4) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int flag = atoi(cmd->argv[0]);
    long lease_min = atol(cmd->argv[1]);
    if ((flag != 0 && flag != 1) || lease_min < 0 || lease_min > 2880) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    esp_netif_dhcps_stop(ap); /* option changes require the server to be stopped first */

    if (lease_min > 0) {
        uint32_t lease_min_u32 = (uint32_t)lease_min;
        esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_IP_ADDRESS_LEASE_TIME,
                                &lease_min_u32, sizeof(lease_min_u32));
    }

    dhcps_lease_t lease = {.enable = true};
    if (ip4addr_aton(cmd->argv[2], &lease.start_ip) != 1 ||
        ip4addr_aton(cmd->argv[3], &lease.end_ip) != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_REQUESTED_IP_ADDRESS,
                            &lease, sizeof(lease));

    if (flag == 1) {
        esp_netif_dhcps_start(ap);
    }
    at_reply_ok(cmd->name, NULL);
}

/* --------------------------------------------------------------- NET_DHCP */

/* AT*M2M*NET_DHCP -- doc's Query form "=? [mode]" is non-standard (every
 * other Query in this doc is bare "=?"); implemented as: no mode given
 * reports station: mode given selects which one. */
void cmd_net_dhcp(const at_command_t *cmd)
{
    if (cmd->argc == 0 || (cmd->argc >= 1 && strcmp(cmd->argv[0], "?") == 0)) {
        int mode = (cmd->argc >= 2) ? atoi(cmd->argv[1]) : 0;
        esp_netif_t *netif = (mode == 1) ? at_wifi_get_ap_netif() : at_wifi_get_sta_netif();
        esp_netif_dhcp_status_t status;
        if (mode == 1) {
            esp_netif_dhcps_get_status(netif, &status);
        } else {
            esp_netif_dhcpc_get_status(netif, &status);
        }
        at_reply_ok(cmd->name, "%d %d", mode, status == ESP_NETIF_DHCP_STARTED ? 1 : 0);
        return;
    }

    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    int flag = atoi(cmd->argv[1]);
    if (mode != 0 && mode != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    esp_err_t err;
    if (mode == 0) {
        esp_netif_t *sta = at_wifi_get_sta_netif();
        err = flag ? esp_netif_dhcpc_start(sta) : esp_netif_dhcpc_stop(sta);
    } else {
        esp_netif_t *ap = at_wifi_get_ap_netif();
        err = flag ? esp_netif_dhcps_start(ap) : esp_netif_dhcps_stop(ap);
    }
    /* Calling start/stop when already in that state returns an
     * ESP_ERR_ESP_NETIF_DHCP_ALREADY_* error -- not a real failure. */
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED &&
        err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}
