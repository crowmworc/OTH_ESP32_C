/* AT*OTH* Wi-Fi AT Commands (OTH-AT Essentials Ch.3). Front end over the
 * station/SoftAP code in cmd_wifi.c. OTH-AT has no station/SoftAP mode
 * command: a join turns station mode on and APSTART turns SoftAP on, each
 * keeping the other running.
 *
 * Not provided (ESP32-C3 / ESP-IDF has no support): MODE 0/4-7 (11g-only,
 * 11n-only, 5 GHz), ADSTART/ADSTOP (IBSS), WDS, P2P_*. WEP (CRYPTO
 * key_mgmt 1, WEP) is refused, as in the M2M-AT build -- an open item of
 * the EN 18031-1 review. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_wps.h"
#include "lwip/inet.h"
#include "dhcpserver/dhcpserver.h"

#include "at_commands.h"
#include "at_commands_oth.h"
#include "at_response.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_wifi.h"
#include "oth_platform.h"

#define APMODE_TARGET_AP 1 /* cmd_wifi.c's apm_target value for a SoftAP profile */

/* ---- staged station security (CRYPTO / PSK) ------------------------------ */
static int  s_key_mgmt = -1;    /* -1: not set -- WPA2 when a PSK is staged, else open */
static int  s_pairwise = 1;     /* 0: TKIP, 1: CCMP (informational, the driver negotiates) */
static int  s_group = 1;
static char s_psk[65];

/* ---- AUCONMODE (RAM copy, persisted by AUCONMODE=2) ---------------------- */
static bool s_auc_loaded;
static uint16_t s_auc_mode; /* 0: off, 1: on, 2: factory SoftAP */
static uint16_t s_auc_type; /* 0..3, see cmd_oth_auconmode() */

static void auc_load(void)
{
    if (s_auc_loaded) {
        return;
    }
    s_auc_loaded = true;
    if (m2m_nvs_get_u16("auc_mode", &s_auc_mode) != ESP_OK) {
        uint16_t apm = 0;
        m2m_nvs_get_u16("apm_type", &apm);
        s_auc_mode = apm == 1 ? 1 : apm == 2 ? 2 : 0;
    }
    m2m_nvs_get_u16("auc_type", &s_auc_type);
}

bool at_oth_wifi_autoconnect_enabled(void)
{
    auc_load();
    return s_auc_mode == 1;
}

void at_oth_wifi_keep_station(void)
{
    auc_load();
    s_auc_mode = 1;
    m2m_nvs_set_u16("auc_mode", 1);
    at_wifi_persist_apmode_sta();
}

/* *OTH*ASSOCIATED:<result> -- 1: failure, 2: AP not found, 3: timeout,
 * 4: connection restricted. */
int at_oth_wifi_assoc_result(uint8_t r)
{
    switch (r) {
    case WIFI_REASON_NO_AP_FOUND:
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
        return 2;
    case WIFI_REASON_AUTH_EXPIRE:
    case WIFI_REASON_ASSOC_EXPIRE:
    case WIFI_REASON_BEACON_TIMEOUT:
        return 3;
    case WIFI_REASON_ASSOC_TOOMANY:
    case WIFI_REASON_NOT_AUTHED:
    case WIFI_REASON_NOT_ASSOCED:
    case WIFI_REASON_ASSOC_NOT_AUTHED:
        return 4;
    default:
        return 1;
    }
}

/* ---- MODE (802.11 PHY) / TXGAIN, applied each time an interface starts -- */
static bool phy_mode_to_protocol(int mode, uint8_t *proto)
{
    switch (mode) {
    case 1: *proto = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G; return true;
    case 2: *proto = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N; return true;
    case 3: *proto = WIFI_PROTOCOL_11B; return true;
    default: return false; /* 0 (G only), 4 (N only), 5-7 (5 GHz): not supported by the radio */
    }
}

void at_oth_wifi_on_start(wifi_interface_t ifx)
{
    uint16_t mode = 2;
    if (m2m_nvs_get_u16("phymode", &mode) != ESP_OK) {
        mode = 2;
    }
    uint8_t proto;
    if (phy_mode_to_protocol(mode, &proto)) {
        esp_wifi_set_protocol(ifx, proto);
    }
    uint16_t gain = 0;
    if (m2m_nvs_get_u16("txgain", &gain) == ESP_OK && gain > 0) {
        esp_wifi_set_max_tx_power((int8_t)(84 - gain));
    }
}

/* AT*OTH*MODE -- 0: G only; 1: B+G; 2: B+G+N (default); 3: B only; 4: N only;
 * 5-7: 5 GHz. Only 1-3 exist on this radio. */
void cmd_oth_mode(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t mode = 2;
        if (m2m_nvs_get_u16("phymode", &mode) != ESP_OK) {
            mode = 2;
        }
        at_reply_ok(cmd->name, "%u", mode);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    uint8_t proto;
    if (!isdigit((unsigned char)cmd->argv[0][0]) || !phy_mode_to_protocol(mode, &proto)) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    m2m_nvs_set_u16("phymode", (uint16_t)mode);
    wifi_mode_t wm = WIFI_MODE_NULL;
    esp_wifi_get_mode(&wm);
    if (wm == WIFI_MODE_STA || wm == WIFI_MODE_APSTA) {
        esp_wifi_set_protocol(WIFI_IF_STA, proto);
    }
    if (wm == WIFI_MODE_AP || wm == WIFI_MODE_APSTA) {
        esp_wifi_set_protocol(WIFI_IF_AP, proto);
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- SCAN ---------------------------------------------------------------- */
/* *OTH*SCANIND security: 0 open, 1 WEP, 2 WPA-PSK, 3 WPA-Enterprise,
 * 4 WPA2-PSK, 5 WPA2-Enterprise. WPA3 networks are reported as their WPA2
 * counterpart, the closest code the table has. */
static int scan_security(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN:
    case WIFI_AUTH_OWE:
        return 0;
    case WIFI_AUTH_WEP:
        return 1;
    case WIFI_AUTH_WPA_PSK:
        return 2;
    case WIFI_AUTH_ENTERPRISE: /* == WIFI_AUTH_WPA2_ENTERPRISE */
    case WIFI_AUTH_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA3_ENT_192:
        return 5;
    default:
        return 4;
    }
}

/* AT*OTH*SCAN -- OK, then one *OTH*SCANIND per network and *OTH*SCANRESULT.
 * Blocking, so the lines follow the OK in order (at_reply_line()). An SSID
 * with a space is quoted; a hidden one reads NULL. */
void cmd_oth_scan(const at_command_t *cmd)
{
    if (!at_wifi_ensure_sta_started()) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    if (esp_wifi_scan_start(NULL, true) == ESP_OK) {
        uint16_t num = 0;
        esp_wifi_scan_get_ap_num(&num);
        if (num > 32) {
            num = 32;
        }
        wifi_ap_record_t *rec = num ? calloc(num, sizeof(*rec)) : NULL;
        if (rec) {
            esp_wifi_scan_get_ap_records(&num, rec);
            for (uint16_t i = 0; i < num; i++) {
                const char *ssid = (const char *)rec[i].ssid;
                bool quote = strchr(ssid, ' ') != NULL;
                at_reply_line("SCANIND:%u %s%s%s " MACSTR " 0 %d %d %d", i, quote ? "\"" : "",
                              ssid[0] ? ssid : "NULL", quote ? "\"" : "", MAC2STR(rec[i].bssid),
                              scan_security(rec[i].authmode), rec[i].primary, rec[i].rssi);
            }
            free(rec);
        } else {
            esp_wifi_clear_ap_list();
        }
    }
    at_reply_line("SCANRESULT");
}

/* ---- CRYPTO / WEP / PSK / ASSOCIATE -------------------------------------- */

/* AT*OTH*CRYPTO=<key_mgmt> <pairwise> <group> -- key_mgmt 0: OPEN,
 * 1: WEP (refused), 2: WPA-PSK, 3: WPA2-PSK; ciphers 0: TKIP, 1: CCMP,
 * 2: WEP (group only). */
void cmd_oth_crypto(const at_command_t *cmd)
{
    if (cmd->argc < 3) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    int km = atoi(cmd->argv[0]), pw = atoi(cmd->argv[1]), gr = atoi(cmd->argv[2]);
    if (km < 0 || km > 3 || pw < 0 || pw > 1 || gr < 0 || gr > 2) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    if (km == 1) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM); /* WEP not supported */
        return;
    }
    s_key_mgmt = km;
    s_pairwise = pw;
    s_group = gr;
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*WEP -- WEP is not supported by this module. */
void cmd_oth_wep(const at_command_t *cmd)
{
    at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
}

static bool psk_ok(const char *p)
{
    size_t n = strlen(p);
    return n >= 8 && n <= 64;
}

/* AT*OTH*PSK=<passphrase> -- 8..64 characters. */
void cmd_oth_psk(const at_command_t *cmd)
{
    if (cmd->argc < 1 || !psk_ok(cmd->argv[0])) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    strlcpy(s_psk, cmd->argv[0], sizeof(s_psk));
    at_reply_ok(cmd->name, NULL);
}

static bool fill_ssid(wifi_config_t *cfg, const char *ssid)
{
    size_t n = strlen(ssid);
    if (n == 0 || n > 32) {
        return false;
    }
    memcpy(cfg->sta.ssid, ssid, n);
    return true;
}

/* AT*OTH*ASSOCIATE=<ssid> [channel] -- joins with the CRYPTO/PSK settings;
 * the result follows as *OTH*ASSOCIATED:<result>. */
void cmd_oth_associate(const at_command_t *cmd)
{
    wifi_config_t cfg = {0};
    if (cmd->argc < 1 || !fill_ssid(&cfg, cmd->argv[0])) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    if (cmd->argc >= 2) {
        int ch = atoi(cmd->argv[1]);
        if (ch < 1 || ch > 14) {
            at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
            return;
        }
        cfg.sta.channel = (uint8_t)ch;
    }
    int km = s_key_mgmt >= 0 ? s_key_mgmt : (s_psk[0] ? 3 : 0);
    if (km >= 2) {
        if (!s_psk[0]) {
            at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
            return;
        }
        strlcpy((char *)cfg.sta.password, s_psk, sizeof(cfg.sta.password));
        cfg.sta.threshold.authmode = (km == 2) ? WIFI_AUTH_WPA_PSK : WIFI_AUTH_WPA2_PSK;
    }
    if (!at_wifi_sta_join(&cfg)) {
        at_reply_error(cmd->name, OTH_ERR_CONNECTION_ESTABLISHMENT);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

void cmd_oth_disassociate(const at_command_t *cmd)
{
    if (!at_wifi_sta_leave()) {
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

static bool parse_mac(const char *s, uint8_t out[6])
{
    unsigned int b[6];
    char tail;
    if (strlen(s) != 17 ||
        sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)b[i];
    }
    return true;
}

/* AT*OTH*SCONN=<ssid> [bssid] [wep_key_index] [passphrase] -- one-shot join;
 * security follows from the passphrase (none: open). The optional fields
 * are told apart by shape: a MAC is the BSSID, a lone 1-4 followed by
 * another field is the WEP key index (WEP itself is not supported, so the
 * index is ignored), the rest is the passphrase. */
void cmd_oth_sconn(const at_command_t *cmd)
{
    wifi_config_t cfg = {0};
    if (cmd->argc < 1 || !fill_ssid(&cfg, cmd->argv[0])) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    const char *pass = NULL;
    for (int i = 1; i < cmd->argc; i++) {
        const char *a = cmd->argv[i];
        if (!cfg.sta.bssid_set && parse_mac(a, cfg.sta.bssid)) {
            cfg.sta.bssid_set = true;
        } else if (i < cmd->argc - 1 && a[0] >= '1' && a[0] <= '4' && a[1] == '\0') {
            continue;
        } else if (!pass) {
            pass = a;
        } else {
            at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
            return;
        }
    }
    if (pass) {
        if (!psk_ok(pass)) {
            at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM); /* WEP-length keys are not supported */
            return;
        }
        strlcpy((char *)cfg.sta.password, pass, sizeof(cfg.sta.password));
    }
    if (!at_wifi_sta_join(&cfg)) {
        at_reply_error(cmd->name, OTH_ERR_CONNECTION_ESTABLISHMENT);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- AUCONMODE / SMODE --------------------------------------------------- */

static bool start_factory_softap(void)
{
    char ssid[16];
    at_oth_factory_ssid(ssid, sizeof(ssid));
    return at_wifi_start_softap(ssid, 1, WIFI_AUTH_OPEN, WIFI_CIPHER_TYPE_UNKNOWN, "");
}

/* AT*OTH*AUCONMODE
 *   =0 <mode>  0: auto-connect off; 1: on -- the current station profile is
 *              rejoined after a reboot and after a lost link; 2: start the
 *              factory SoftAP (OTH_xxxxxx, open, channel 1) now and at boot.
 *   =1 <type>  save policy 0-3. Kept and reported; the driver itself always
 *              keeps the profile of the last join in NV memory.
 *   =2         store mode and type in NV memory.
 * Query: "<mode> <type>". */
void cmd_oth_auconmode(const at_command_t *cmd)
{
    auc_load();
    if (at_is_query(cmd) || cmd->argc == 0) {
        at_reply_ok(cmd->name, "%u %u", s_auc_mode, s_auc_type);
        return;
    }
    int op = atoi(cmd->argv[0]);
    if (op == 2 && cmd->argc == 1) {
        m2m_nvs_set_u16("auc_mode", s_auc_mode);
        m2m_nvs_set_u16("auc_type", s_auc_type);
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (cmd->argc < 2 || (op != 0 && op != 1)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    int v = atoi(cmd->argv[1]);
    if (op == 1) {
        if (v < 0 || v > 3) {
            at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
            return;
        }
        s_auc_type = (uint16_t)v;
        at_reply_ok(cmd->name, NULL);
        return;
    }
    switch (v) {
    case 0:
        m2m_nvs_set_u16("apm_type", 0);
        break;
    case 1:
        at_wifi_persist_apmode_sta();
        break;
    case 2: {
        if (!start_factory_softap()) {
            at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
            return;
        }
        char ssid[16];
        at_oth_factory_ssid(ssid, sizeof(ssid));
        m2m_nvs_set_u16("apm_type", 2);
        m2m_nvs_set_u16("apm_target", APMODE_TARGET_AP);
        m2m_nvs_set_str("apm_ssid", ssid);
        m2m_nvs_set_str("apm_pw", "");
        m2m_nvs_set_u16("apm_ch", 1);
        break;
    }
    default:
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    s_auc_mode = (uint16_t)v;
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*SMODE=<mode> [ssid] -- 0: SoftAP with the predefined SSID, channel
 * and security (the saved SoftAP profile, else the factory SoftAP);
 * 1: the same with [ssid]; 99: station mode, join the predefined AP (the
 * last station profile). Replies as *OTH*MODE, as the guide shows. */
void cmd_oth_smode(const at_command_t *cmd)
{
    const char *name = "MODE";
    if (cmd->argc < 1) {
        at_reply_error(name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    bool ok;
    if (mode == 99) {
        wifi_config_t cfg;
        ok = at_wifi_ensure_sta_started() && esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK &&
             cfg.sta.ssid[0] != '\0' && at_wifi_sta_join(&cfg);
    } else if (mode == 0 || (mode == 1 && cmd->argc >= 2)) {
        char ssid[33] = "", pw[65] = "";
        uint16_t ch = 1, target = 0;
        size_t sl = sizeof(ssid), pl = sizeof(pw);
        m2m_nvs_get_u16("apm_target", &target);
        if (target == APMODE_TARGET_AP) {
            m2m_nvs_get_str("apm_ssid", ssid, &sl);
            m2m_nvs_get_str("apm_pw", pw, &pl);
            m2m_nvs_get_u16("apm_ch", &ch);
        }
        if (ssid[0] == '\0') {
            at_oth_factory_ssid(ssid, sizeof(ssid));
            pw[0] = '\0';
            ch = 1;
        }
        const char *use = (mode == 1) ? cmd->argv[1] : ssid;
        ok = at_wifi_start_softap(use, (uint8_t)ch, WIFI_AUTH_WPA2_PSK, WIFI_CIPHER_TYPE_UNKNOWN, pw);
    } else {
        at_reply_error(name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    if (!ok) {
        at_reply_error(name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    at_reply_ok(name, NULL);
}

/* ---- EAPSET / EAPCERT (Optional) ----------------------------------------- */

void cmd_oth_eapset(const at_command_t *cmd)
{
    int err = at_wifi_oth_eapset(cmd->argc, (char **)cmd->argv);
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* Fields 0-5 match WF_EAPCERT's types; files must be stored on the module. */
void cmd_oth_eapcert(const at_command_t *cmd)
{
    int err = at_wifi_eapcert_apply(cmd->argc, (char **)cmd->argv);
    if (err) {
        /* AT_ERR_ARG: bad field/file -> 8; no method set / load failure -> 5 */
        at_reply_error(cmd->name, err == AT_ERR_ARG ? OTH_ERR_GENERAL_PARAM : OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- NWSTATUS ------------------------------------------------------------ */

static int nw_security(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN: return 0;
    case WIFI_AUTH_WEP: return 1;
    case WIFI_AUTH_WPA_PSK: return 2;
    default: return 3;
    }
}

/* AT*OTH*NWSTATUS=? -- "<mac> <network_type> <channel> <rssi> <ssid> <bssid>
 * <security> <dhcp_mode> <ip> <subnet> <gateway> <dns>"; network_type
 * 2: station (while joined), 3: SoftAP. */
void cmd_oth_nwstatus(const at_command_t *cmd)
{
    wifi_mode_t wm = WIFI_MODE_NULL;
    esp_wifi_get_mode(&wm);
    esp_netif_ip_info_t ip = {0};
    esp_netif_dns_info_t dns = {0};
    uint8_t mac[6];
    wifi_ap_record_t ap;

    if ((wm == WIFI_MODE_STA || wm == WIFI_MODE_APSTA) && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        esp_netif_t *n = at_wifi_get_sta_netif();
        esp_netif_dhcp_status_t st = ESP_NETIF_DHCP_INIT;
        esp_netif_get_ip_info(n, &ip);
        esp_netif_get_dns_info(n, ESP_NETIF_DNS_MAIN, &dns);
        esp_netif_dhcpc_get_status(n, &st);
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        at_reply_ok(cmd->name, MACSTR " 2 %d %d %s " MACSTR " %d %d " IPSTR " " IPSTR " " IPSTR " " IPSTR,
                    MAC2STR(mac), ap.primary, ap.rssi, (const char *)ap.ssid, MAC2STR(ap.bssid),
                    nw_security(ap.authmode), st == ESP_NETIF_DHCP_STARTED ? 1 : 0, IP2STR(&ip.ip),
                    IP2STR(&ip.netmask), IP2STR(&ip.gw), IP2STR(&dns.ip.u_addr.ip4));
        return;
    }
    wifi_config_t cfg;
    if ((wm == WIFI_MODE_AP || wm == WIFI_MODE_APSTA) && esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
        esp_netif_get_ip_info(at_wifi_get_ap_netif(), &ip);
        esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
        at_reply_ok(cmd->name, MACSTR " 3 %d 0 %s " MACSTR " %d 0 " IPSTR " " IPSTR " " IPSTR " 0.0.0.0",
                    MAC2STR(mac), cfg.ap.channel, (const char *)cfg.ap.ssid, MAC2STR(mac),
                    nw_security(cfg.ap.authmode), IP2STR(&ip.ip), IP2STR(&ip.netmask), IP2STR(&ip.gw));
        return;
    }
    at_reply_error(cmd->name, OTH_ERR_CONNECTION_ESTABLISHMENT); /* not joined, no SoftAP */
}

/* ---- SoftAP: APSTART / APSTOP / APNSET / APLEASEIP / DHCPD ---------------- */

/* AT*OTH*APSTART=<ssid> <channel> [key_mgmt] [pairwise] [group] [passphrase]
 * key_mgmt 0: OPEN, 2: WPA-PSK, 3: WPA2-PSK (WEP is not supported). */
void cmd_oth_apstart(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    int ch = atoi(cmd->argv[1]);
    int km = cmd->argc >= 3 ? atoi(cmd->argv[2]) : 0;
    int pw = cmd->argc >= 4 ? atoi(cmd->argv[3]) : 1;
    const char *pass = cmd->argc >= 6 ? cmd->argv[5] : "";
    if (ch < 1 || ch > 14 || (km != 0 && km != 2 && km != 3) || pw < 0 || pw > 1 ||
        (km != 0 && !psk_ok(pass))) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    if (km == 0) {
        pass = "";
    }
    wifi_auth_mode_t auth = (km == 2) ? WIFI_AUTH_WPA_PSK : WIFI_AUTH_WPA2_PSK;
    wifi_cipher_type_t cipher = pw ? WIFI_CIPHER_TYPE_CCMP : WIFI_CIPHER_TYPE_TKIP;
    if (!at_wifi_start_softap(cmd->argv[0], (uint8_t)ch, auth, cipher, pass)) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*APSTOP -- stops the SoftAP, keeping station mode if it is on. */
void cmd_oth_apstop(const at_command_t *cmd)
{
    wifi_mode_t wm = WIFI_MODE_NULL;
    esp_wifi_get_mode(&wm);
    esp_err_t err = ESP_OK;
    if (wm == WIFI_MODE_APSTA) {
        err = esp_wifi_set_mode(WIFI_MODE_STA);
    } else if (wm == WIFI_MODE_AP) {
        err = esp_wifi_stop();
        if (err == ESP_OK) {
            err = esp_wifi_set_mode(WIFI_MODE_NULL);
        }
    }
    if (err != ESP_OK) {
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* SoftAP addressing: APNSET (default 192.168.0.1/24, gateway 192.168.0.1)
 * and APLEASEIP (last octets 10..254), kept in NV memory and applied to the
 * SoftAP interface at boot and on every change. The DHCP server hands out
 * at most DHCPS_MAX_LEASE (100) addresses, so a longer range is served from
 * its first 100; the query still reports the configured range. DHCPDSTOP keeps the server
 * off until DHCPDSTART. */
static bool s_dhcpd_on = true;

static void ap_addr_get(struct in_addr *ip, struct in_addr *nm, struct in_addr *gw)
{
    char a[16] = "", b[16] = "", c[16] = "";
    size_t la = sizeof(a), lb = sizeof(b), lc = sizeof(c);
    m2m_nvs_get_str("apn_ip", a, &la);
    m2m_nvs_get_str("apn_sn", b, &lb);
    m2m_nvs_get_str("apn_gw", c, &lc);
    if (!inet_aton(a, ip) || !inet_aton(b, nm) || !inet_aton(c, gw)) {
        inet_aton("192.168.0.1", ip);
        inet_aton("255.255.255.0", nm);
        inet_aton("192.168.0.1", gw);
    }
}

static void ap_lease_get(uint16_t *min, uint16_t *max)
{
    if (m2m_nvs_get_u16("lease_min", min) != ESP_OK || m2m_nvs_get_u16("lease_max", max) != ESP_OK ||
        *min < 1 || *max > 254 || *min > *max) {
        *min = 10;
        *max = 254;
    }
}

static bool ap_addr_apply(void)
{
    esp_netif_t *ap = at_wifi_get_ap_netif();
    struct in_addr ip, nm, gw;
    uint16_t lo, hi;
    ap_addr_get(&ip, &nm, &gw);
    ap_lease_get(&lo, &hi);

    esp_netif_ip_info_t info = { .ip.addr = ip.s_addr, .netmask.addr = nm.s_addr, .gw.addr = gw.s_addr };
    if (hi - lo + 1 > DHCPS_MAX_LEASE) {
        hi = lo + DHCPS_MAX_LEASE - 1; /* the DHCP server serves at most 100 leases */
    }
    uint32_t net = ntohl(ip.s_addr) & 0xFFFFFF00u;
    dhcps_lease_t lease = { .enable = true };
    lease.start_ip.addr = htonl(net | lo);
    lease.end_ip.addr = htonl(net | hi);

    esp_netif_dhcps_stop(ap); /* options can only change while the server is stopped */
    bool ok = esp_netif_set_ip_info(ap, &info) == ESP_OK &&
              esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_REQUESTED_IP_ADDRESS, &lease,
                                     sizeof(lease)) == ESP_OK;
    if (s_dhcpd_on) {
        esp_netif_dhcps_start(ap);
    }
    return ok;
}

/* AT*OTH*APNSET=<ip> <subnet> <gateway> / =? */
void cmd_oth_apnset(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        struct in_addr ip, nm, gw;
        ap_addr_get(&ip, &nm, &gw);
        char a[16], b[16], c[16];
        strlcpy(a, inet_ntoa(ip), sizeof(a));
        strlcpy(b, inet_ntoa(nm), sizeof(b));
        strlcpy(c, inet_ntoa(gw), sizeof(c));
        at_reply_ok(cmd->name, "%s %s %s", a, b, c);
        return;
    }
    struct in_addr ip, nm, gw;
    if (cmd->argc < 3 || !inet_aton(cmd->argv[0], &ip) || !inet_aton(cmd->argv[1], &nm) ||
        !inet_aton(cmd->argv[2], &gw)) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    m2m_nvs_set_str("apn_ip", cmd->argv[0]);
    m2m_nvs_set_str("apn_sn", cmd->argv[1]);
    m2m_nvs_set_str("apn_gw", cmd->argv[2]);
    if (!ap_addr_apply()) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*APLEASEIP=<min> <max> / =? -- last octet of the lease range. */
void cmd_oth_apleaseip(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t lo, hi;
        ap_lease_get(&lo, &hi);
        at_reply_ok(cmd->name, "%u %u", lo, hi);
        return;
    }
    int lo = cmd->argc >= 2 ? atoi(cmd->argv[0]) : -1;
    int hi = cmd->argc >= 2 ? atoi(cmd->argv[1]) : -1;
    if (lo < 1 || hi > 254 || lo > hi) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    m2m_nvs_set_u16("lease_min", (uint16_t)lo);
    m2m_nvs_set_u16("lease_max", (uint16_t)hi);
    if (!ap_addr_apply()) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

void cmd_oth_dhcpdstart(const at_command_t *cmd)
{
    esp_err_t err = esp_netif_dhcps_start(at_wifi_get_ap_netif());
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        at_reply_error(cmd->name, OTH_ERR_TCPIP_PARAM);
        return;
    }
    s_dhcpd_on = true;
    at_reply_ok(cmd->name, NULL);
}

void cmd_oth_dhcpdstop(const at_command_t *cmd)
{
    esp_err_t err = esp_netif_dhcps_stop(at_wifi_get_ap_netif());
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        at_reply_error(cmd->name, -1);
        return;
    }
    s_dhcpd_on = false;
    at_reply_ok(cmd->name, NULL);
}

/* ---- WPS ----------------------------------------------------------------- */

static void wps_start(const at_command_t *cmd, wps_type_t type, const char *pin)
{
    if (!at_wifi_ensure_sta_started()) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    esp_wps_config_t wps = {0};
    wps.wps_type = type;
    if (pin) {
        strlcpy(wps.pin, pin, sizeof(wps.pin));
    }
    esp_wifi_wps_disable();
    if (esp_wifi_wps_enable(&wps) != ESP_OK || esp_wifi_wps_start(0) != ESP_OK) {
        at_reply_error(cmd->name, OTH_ERR_CONNECTION_ESTABLISHMENT);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*WPS_PBC=[any] -- the result follows as *OTH*ASSOCIATED. Pairing
 * with one given BSSID is not supported by the WPS client. */
void cmd_oth_wps_pbc(const at_command_t *cmd)
{
    if (cmd->argc >= 1 && strcasecmp(cmd->argv[0], "any") != 0) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    wps_start(cmd, WPS_TYPE_PBC, NULL);
}

/* AT*OTH*WPS_PIN=[pin] -- 8 digits; without one the module's own PIN is
 * used. */
void cmd_oth_wps_pin(const at_command_t *cmd)
{
    const char *pin = cmd->argc >= 1 ? cmd->argv[0] : NULL;
    if (pin) {
        bool ok = strlen(pin) == 8;
        for (int i = 0; ok && i < 8; i++) {
            ok = isdigit((unsigned char)pin[i]);
        }
        if (!ok) {
            at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
            return;
        }
    }
    wps_start(cmd, WPS_TYPE_PIN, pin);
}

void cmd_oth_wps_cancel(const at_command_t *cmd)
{
    esp_wifi_wps_disable();
    at_reply_ok(cmd->name, NULL);
}

/* ---- boot ------------------------------------------------------------------ */

void at_oth_init(void)
{
    uint16_t evtdel = 0;
    m2m_nvs_get_u16("evtdel", &evtdel);
    at_event_set_enabled(evtdel == 0);
    ap_addr_apply();
    at_oth_svc_init();
    oth_pairing_init();
}
