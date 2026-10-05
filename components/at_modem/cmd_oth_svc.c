/* AT*OTH* Network Service AT Commands (OTH-AT Essentials Ch.6) that sit on
 * the shared M2M-AT services -- embedded web server, FTP credentials, OTA
 * -- and the MIB attribute commands (Ch.2, Appendix B). HTTP client and
 * SNTP live next to their M2M-AT counterparts (cmd_http.c, cmd_net_svc.c).
 *
 * Not provided: DDNS_*, UPNP_*, LPD_* (out of scope, as in M2M-AT). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_app_desc.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/inet.h"

#include "at_commands.h"
#include "at_commands_oth.h"
#include "at_response.h"
#include "at_nvs_kv.h"
#include "at_uart.h"
#include "at_wifi.h"
#include "oth_sock.h"
#include "at_httpd.h"
#include "sdkconfig.h"

/* ---- embedded web server (Ch.6.2) ------------------------------------------ */

/* AT*OTH*HTTPD_START -- starts the configuration web server and keeps it
 * enabled across reboots: plain HTTP on port 80, or HTTPS on 443 with the
 * stored server.pem when the build allows HTTPS only (Kconfig
 * AT_MODEM_HTTPD_MODE). Same server and NV items as NET_HTTPDSTART. */
void cmd_oth_httpd_start(const at_command_t *cmd)
{
    if (at_httpd_running()) {
        m2m_nvs_set_u16("httpd_enabled", 1); /* already serving: just keep it enabled */
        at_reply_ok(cmd->name, NULL);
        return;
    }
    at_command_t c = *cmd;
#if CONFIG_AT_MODEM_HTTPD_MODE_HTTPS_ONLY
    static char port[] = "443", ssl[] = "1", cert[] = OTH_SSL_SERVER_CERT;
    c.argv[0] = port;
    c.argv[1] = ssl;
    c.argv[2] = cert;
    c.argc = 3;
#else
    static char port[] = "80", ssl[] = "0";
    c.argv[0] = port;
    c.argv[1] = ssl;
    c.argc = 2;
#endif
    cmd_net_httpdstart(&c);
}

void cmd_oth_httpd_stop(const at_command_t *cmd)
{
    cmd_net_httpdstop(cmd);
}

/* AT*OTH*HTTPD_IDPW=<id> <pw> / =? -- the password is checked against the
 * web password policy and stored only as a salted hash, so the query
 * answers "<id> ********" (an open item of the EN 18031-1 review: the
 * guide shows the password itself). */
void cmd_oth_httpd_idpw(const at_command_t *cmd)
{
    cmd_net_httpdconf(cmd);
}

/* ---- FTP client credentials (Ch.6.3) ---------------------------------------- */

/* AT*OTH*FTPC_SET=<index> <value> -- 0: login ID (32), 1: password (64).
 * Stored in (encrypted) NV memory. No FTP client uses them yet: OTA runs
 * over HTTP(S) only. */
void cmd_oth_ftpc_set(const at_command_t *cmd)
{
    if (cmd->argc < 2 || (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0) ||
        strlen(cmd->argv[1]) > (cmd->argv[0][0] == '0' ? 32u : 64u)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    m2m_nvs_set_str(cmd->argv[0][0] == '0' ? "ftp_id" : "ftp_pw", cmd->argv[1]);
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*FTPC_GET=<index> -- the password reads back masked (open item of
 * the EN 18031-1 review). */
void cmd_oth_ftpc_get(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    char v[65] = "";
    size_t len = sizeof(v);
    bool pw = cmd->argv[0][0] == '1';
    m2m_nvs_get_str(pw ? "ftp_pw" : "ftp_id", v, &len);
    at_reply_ok(cmd->name, "%s", !v[0] ? "null" : pw ? "********" : v);
}

/* ---- OTA (Ch.6.5) --------------------------------------------------------------- */

static bool ota_url_ok(const at_command_t *cmd)
{
    return cmd->argc >= 1 &&
           (strncasecmp(cmd->argv[0], "http://", 7) == 0 || strncasecmp(cmd->argv[0], "https://", 8) == 0);
}

/* AT*OTH*OTA_VERCHECK=<url> -- <url> is the firmware image itself (as for
 * OTA_CHECK); result *OTH*OTA_VERSION:<local> <server>, MM.NN as MM*100+NN.
 * ftp:// is not supported (2: argument error). */
void cmd_oth_ota_vercheck(const at_command_t *cmd)
{
    if (!ota_url_ok(cmd)) {
        at_reply_error(cmd->name, 2);
        return;
    }
    cmd_ota_check(cmd);
}

/* AT*OTH*OTA_REQUEST=<url> -- result *OTH*OTA_UPDATE:OK|ERROR <code>; the
 * new image boots after the next RESET. */
void cmd_oth_ota_request(const at_command_t *cmd)
{
    if (!ota_url_ok(cmd)) {
        at_reply_error(cmd->name, 2);
        return;
    }
    cmd_ota_update(cmd);
}

/* ---- MIB / SETMIB (Appendix B) -------------------------------------------------- */

static int mib_security(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN: return 0;
    case WIFI_AUTH_WEP: return 1;
    case WIFI_AUTH_WPA_PSK: return 2;
    case WIFI_AUTH_WAPI_PSK: return 4;
    case WIFI_AUTH_ENTERPRISE:
    case WIFI_AUTH_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA3_ENT_192:
        return 6;
    default: return 3; /* WPA2 / WPA-WPA2 / WPA3 personal */
    }
}

static int mib_cipher(wifi_cipher_type_t c)
{
    switch (c) {
    case WIFI_CIPHER_TYPE_TKIP: return 0;
    case WIFI_CIPHER_TYPE_WEP40:
    case WIFI_CIPHER_TYPE_WEP104: return 2;
    case WIFI_CIPHER_TYPE_NONE: return 4;
    case WIFI_CIPHER_TYPE_AES_CMAC128: return 5;
    case WIFI_CIPHER_TYPE_SMS4: return 6;
    case WIFI_CIPHER_TYPE_AES_GMAC128:
    case WIFI_CIPHER_TYPE_AES_GMAC256: return 7;
    default: return 1; /* CCMP and its GCMP variants */
    }
}

static int mib_eap_type(const char *m)
{
    if (!m[0]) return 0;
    if (strcasecmp(m, "ttls") == 0) return 1;
    if (strcasecmp(m, "tls") == 0) return 2;
    if (strcasecmp(m, "peap") == 0) return 3;
    if (strcasecmp(m, "fast") == 0) return 5;
    return 0;
}

/* MIB index -> SYS_CONF NV key, for the shared device-identity fields */
static const char *ident_key(int idx)
{
    switch (idx) {
    case 15: return "c1";  /* serial number */
    case 16: return "c35"; /* device code (u16) */
    case 17: return "c36"; /* device type (u16) */
    case 18: return "c37"; /* device name */
    case 19: return "c38"; /* model name */
    case 20: return "c39"; /* manufacturer */
    default: return NULL;
    }
}

static void reply_str(const at_command_t *cmd, const char *v)
{
    at_reply_ok(cmd->name, "%s", (v && v[0]) ? v : "null");
}

/* AT*OTH*MIB=<index> -- one attribute; "null" when not assigned. Secrets
 * (7 WPA passphrase, 11 EAP password) read back as "********" when set
 * (open item of the EN 18031-1 review); WEP (6, 8) and the radio
 * thresholds this driver does not expose (64-66) read null. */
void cmd_oth_mib(const at_command_t *cmd)
{
    char *end;
    long idx = cmd->argc >= 1 ? strtol(cmd->argv[0], &end, 10) : -1;
    if (cmd->argc < 1 || *end != '\0') {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    wifi_mode_t wm = WIFI_MODE_NULL;
    esp_wifi_get_mode(&wm);
    bool sta_on = wm == WIFI_MODE_STA || wm == WIFI_MODE_APSTA;
    bool ap_on = wm == WIFI_MODE_AP || wm == WIFI_MODE_APSTA;
    wifi_ap_record_t ap;
    bool joined = sta_on && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    wifi_config_t sta_cfg = {0}, ap_cfg = {0};
    esp_wifi_get_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_get_config(WIFI_IF_AP, &ap_cfg);
    bool ap_view = !joined && ap_on; /* report the SoftAP when not joined */
    at_wifi_eap_info_t eap;
    at_wifi_eap_info(&eap);
    uint8_t mac[6];
    char buf[40];

    switch (idx) {
    case 0:
        reply_str(cmd, joined ? (const char *)ap.ssid : ap_view ? (const char *)ap_cfg.ap.ssid
                                                                  : (const char *)sta_cfg.sta.ssid);
        return;
    case 1:
        if (joined || ap_view) {
            at_reply_ok(cmd->name, "%u", joined ? ap.primary : ap_cfg.ap.channel);
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 2:
        at_reply_ok(cmd->name, "%d", ap_view ? 2 : 0);
        return;
    case 3:
        if (joined || ap_view) {
            at_reply_ok(cmd->name, "%d", mib_security(joined ? ap.authmode : ap_cfg.ap.authmode));
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 4:
    case 5:
        if (joined) {
            at_reply_ok(cmd->name, "%d", mib_cipher(idx == 4 ? ap.pairwise_cipher : ap.group_cipher));
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 7:
        reply_str(cmd, (ap_view ? ap_cfg.ap.password[0] : sta_cfg.sta.password[0]) ? "********" : NULL);
        return;
    case 9:
        at_reply_ok(cmd->name, "%d", mib_eap_type(eap.method));
        return;
    case 10: reply_str(cmd, eap.identity); return;
    case 11: reply_str(cmd, eap.has_password ? "********" : NULL); return;
    case 12: reply_str(cmd, eap.ca_file); return;
    case 13: reply_str(cmd, eap.cert_file); return;
    case 14: reply_str(cmd, eap.key_file); return;
    case 24: reply_str(cmd, eap.pac_file); return;
    case 15: case 18: case 19: case 20: {
        char v[65] = "";
        size_t len = sizeof(v);
        m2m_nvs_get_str(ident_key((int)idx), v, &len);
        reply_str(cmd, v);
        return;
    }
    case 16: case 17: {
        uint16_t v = 0;
        m2m_nvs_get_u16(ident_key((int)idx), &v);
        at_reply_ok(cmd->name, "%u", v);
        return;
    }
    case 32:
        reply_str(cmd, esp_app_get_description()->version);
        return;
    case 33:
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        at_reply_ok(cmd->name, MACSTR, MAC2STR(mac));
        return;
    case 34:
        if (joined) {
            at_reply_ok(cmd->name, MACSTR, MAC2STR(ap.bssid));
        } else if (ap_view) {
            esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
            at_reply_ok(cmd->name, MACSTR, MAC2STR(mac));
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 35: {
        int ch = joined ? ap.primary : ap_view ? ap_cfg.ap.channel : 0;
        if (!ch) {
            reply_str(cmd, NULL);
        } else {
            at_reply_ok(cmd->name, "%d", ch == 14 ? 2484 : 2407 + 5 * ch);
        }
        return;
    }
    case 36: {
        uint32_t baud = 0;
        if (m2m_nvs_get_u32("uart_baud", &baud) != ESP_OK || !baud) {
            baud = CONFIG_AT_MODEM_UART_BAUD_RATE;
        }
        at_reply_ok(cmd->name, "%lu", (unsigned long)baud);
        return;
    }
    case 37: {
        esp_netif_ip_info_t ip = {0};
        esp_netif_get_ip_info(at_wifi_get_sta_netif(), &ip);
        at_reply_ok(cmd->name, "%d", !joined ? 0 : ip.ip.addr ? 2 : 1);
        return;
    }
    case 67:
        if (ap_on) {
            at_reply_ok(cmd->name, "%u", ap_cfg.ap.beacon_interval ? ap_cfg.ap.beacon_interval : 100);
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 96: case 97: case 98: case 99: case 100: {
        esp_netif_t *n = ap_view ? at_wifi_get_ap_netif() : at_wifi_get_sta_netif();
        esp_netif_ip_info_t ip = {0};
        esp_netif_dns_info_t dns = {0};
        esp_netif_get_ip_info(n, &ip);
        esp_netif_get_dns_info(n, ESP_NETIF_DNS_MAIN, &dns);
        if (idx == 100) {
            esp_netif_dhcp_status_t st = ESP_NETIF_DHCP_INIT;
            esp_netif_dhcpc_get_status(at_wifi_get_sta_netif(), &st);
            at_reply_ok(cmd->name, "%d", st == ESP_NETIF_DHCP_STOPPED ? 0 : 1);
            return;
        }
        const esp_ip4_addr_t *a = idx == 96 ? &ip.ip : idx == 97 ? &ip.netmask : idx == 98 ? &ip.gw
                                                                                     : &dns.ip.u_addr.ip4;
        at_reply_ok(cmd->name, IPSTR, IP2STR(a));
        return;
    }
    case 101: {
        uint16_t lo = 10, hi = 254;
        if (m2m_nvs_get_u16("lease_min", &lo) != ESP_OK || m2m_nvs_get_u16("lease_max", &hi) != ESP_OK) {
            lo = 10, hi = 254;
        }
        at_reply_ok(cmd->name, "%u:%u", lo, hi);
        return;
    }
    case 102: {
        uint16_t port = 0;
        m2m_nvs_get_u16("svc_port", &port);
        if (port) {
            at_reply_ok(cmd->name, "%u", port);
        } else {
            reply_str(cmd, NULL);
        }
        return;
    }
    case 104:
        at_reply_ok(cmd->name, "%d", oth_sock_data_connected() ? 1 : 0);
        return;
    case 105: {
        char v[16] = "";
        size_t len = sizeof(v);
        m2m_nvs_get_str("dm_rip", v, &len);
        reply_str(cmd, v);
        return;
    }
    case 106: {
        uint16_t p = 0;
        m2m_nvs_get_u16("dm_rport", &p);
        snprintf(buf, sizeof(buf), "%u", p);
        reply_str(cmd, p ? buf : NULL);
        return;
    }
    case 112:
        if (joined) {
            at_reply_ok(cmd->name, "%d", ap.rssi);
        } else {
            reply_str(cmd, NULL);
        }
        return;
    case 6: case 8: case 64: case 65: case 66: case 103:
        reply_str(cmd, NULL);
        return;
    default:
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM); /* reserved index */
        return;
    }
}

/* AT*OTH*SETMIB=<index> [parameters] -- writable indexes of Appendix B.2.
 * Replies as *OTH*MIB, as the guide shows. 36 (baud rate) applies after
 * the next RESET; 102 (standing service port) and 105/106 (data-mode
 * peer) are stored and read back -- no service is opened from them yet. */
void cmd_oth_setmib(const at_command_t *cmd)
{
    const char *name = "MIB";
    char *end;
    long idx = cmd->argc >= 2 ? strtol(cmd->argv[0], &end, 10) : -1;
    if (cmd->argc < 2 || *end != '\0') {
        at_reply_error(name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    const char *v = cmd->argv[1];
    size_t len = strlen(v);
    long num = strtol(v, &end, 10);
    bool numeric = *end == '\0' && len > 0;
    struct in_addr a;

    switch (idx) {
    case 15: case 19:
        if (len > 32) goto bad;
        m2m_nvs_set_str(ident_key((int)idx), v);
        break;
    case 18: case 20:
        if (len > 16) goto bad;
        m2m_nvs_set_str(ident_key((int)idx), v);
        break;
    case 16: case 17:
        if (!numeric || num < 0 || num > 65535) goto bad;
        m2m_nvs_set_u16(ident_key((int)idx), (uint16_t)num);
        break;
    case 36:
        if (!numeric || num < 110 || num > 9216000) goto bad;
        m2m_nvs_set_u32("uart_baud", (uint32_t)num);
        break;
    case 102: {
        long port = cmd->argc >= 3 ? atol(cmd->argv[2]) : 0;
        if (!numeric || (num != 0 && num != 4 && num != 8) || (num != 0 && (port < 1024 || port > 65535))) goto bad;
        m2m_nvs_set_u16("svc_type", (uint16_t)num);
        m2m_nvs_set_u16("svc_port", num ? (uint16_t)port : 0);
        break;
    }
    case 105:
        if (!inet_aton(v, &a)) goto bad;
        m2m_nvs_set_str("dm_rip", v);
        break;
    case 106:
        if (!numeric || num < 1 || num > 65535) goto bad;
        m2m_nvs_set_u16("dm_rport", (uint16_t)num);
        break;
    default:
        goto bad;
    }
    at_reply_ok(name, NULL);
    return;
bad:
    at_reply_error(name, OTH_ERR_GENERAL_PARAM);
}

/* Boot: a baud rate set with SETMIB 36 takes effect (no-op over USB). */
void at_oth_svc_init(void)
{
    uint32_t baud = 0;
    if (m2m_nvs_get_u32("uart_baud", &baud) == ESP_OK && baud) {
        at_uart_apply_baud_rate(baud);
    }
}
