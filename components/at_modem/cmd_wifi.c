/* AT*M2M*WF_* -- Wi-Fi AT Commands (M2M-AT Command Set doc, Ch.3: Common,
 * Station, SoftAP, WPS, EAP-Enterprise).
 *
 * Also owns at_wifi_init(): brings up the Wi-Fi driver once at boot and
 * turns WIFI_EVENT/IP_EVENT into the Ch.7 async "*M2M*..." notifications. */

#include <ctype.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_wifi.h"
#include "esp_wps.h"
#include "esp_eap_client.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "lwip/inet.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_uart.h"
#include "at_event.h"
#include "at_wifi.h"
#include "at_nvs_kv.h"
#include "fs_store.h"
#include "at_pem_scratch.h"
#include "at_cmdset.h"
#if CONFIG_AT_MODEM_CMDSET_OTH
#include "at_commands_oth.h"
#endif

static const char *TAG = "at_wifi";

static esp_netif_t *s_netif_sta;
static esp_netif_t *s_netif_ap;

/* Set by cmd_wf_disconn() right before esp_wifi_disconnect() so the event
 * handler can tell a host-requested disconnect apart from an unsolicited
 * one (only the latter gets a WF_DISCONN:DONE notification, doc Ch.7.2). */
static atomic_bool s_disconnect_requested = false;

/* Some APs (seen with a phone hotspot) still hold the association of a
 * station that vanished without a deauth -- a power loss or EN reset while
 * connected -- and reject its next auth (AUTH_FAIL), clearing the stale
 * entry as they do but ignoring the station for a few more seconds (an
 * immediate retry ends in CONNECTION_FAIL). Without a retry a WF_APMODE
 * auto-reconnect after a power cycle would stay offline until the host
 * stepped in. So an auth-type failure (doc reason 2) starts up to
 * AUTH_RETRY_MAX quiet retries, AUTH_RETRY_DELAY_US apart, and only the
 * last failure is reported as WF_DISCONN:DONE. Cancelled by every new
 * connect attempt, WF_DISCONN, and a successful connection. */
#define AUTH_RETRY_MAX      3
#define AUTH_RETRY_DELAY_US (3 * 1000 * 1000)
static atomic_int s_auth_retries = 0;
static esp_timer_handle_t s_auth_retry_timer;

/* True between WIFI_EVENT_STA_CONNECTED and the next STA_DISCONNECTED, so a
 * disconnect can be told apart from a join attempt that never succeeded
 * (OTH-AT reports the two differently: DISASSOCIATED vs ASSOCIATED:<n>). */
static atomic_bool s_sta_connected = false;

#if CONFIG_AT_MODEM_CMDSET_OTH
/* OTH-AT AUCONMODE: with auto-connect on, a lost link is rejoined by the
 * module itself (every OTH_RECONNECT_DELAY_US until it succeeds or the host
 * sends DISASSOCIATE / a new join). */
#define OTH_RECONNECT_DELAY_US (5 * 1000 * 1000)
static esp_timer_handle_t s_reconnect_timer;
static bool s_boot_autoconnect;
#endif

static void auth_retry_timer_cb(void *arg)
{
    (void)arg;
    esp_wifi_connect();
}

static void auth_retry_reset(void)
{
    if (s_auth_retry_timer) {
        esp_timer_stop(s_auth_retry_timer); /* ESP_ERR_INVALID_STATE if idle -- fine */
    }
    atomic_store(&s_auth_retries, 0);
#if CONFIG_AT_MODEM_CMDSET_OTH
    if (s_reconnect_timer) {
        esp_timer_stop(s_reconnect_timer);
    }
#endif
}

/* Doc's Wi-Fi auth enum (Ch.3.2) diverges from ESP-IDF's wifi_auth_mode_t
 * past index 4 -- map explicitly instead of casting. Anything the doc's
 * enum has no slot for (enterprise, OWE, WAPI, DPP, ...) falls back to
 * WPA2-PSK(3) as the closest generic "it's secured" bucket. */
static int map_authmode_to_doc(wifi_auth_mode_t authmode)
{
    switch (authmode) {
    case WIFI_AUTH_OPEN:          return 0;
    case WIFI_AUTH_WEP:           return 1;
    case WIFI_AUTH_WPA_PSK:       return 2;
    case WIFI_AUTH_WPA2_PSK:      return 3;
    case WIFI_AUTH_WPA_WPA2_PSK:  return 4;
    case WIFI_AUTH_WPA2_WPA3_PSK: return 5;
    case WIFI_AUTH_WPA3_PSK:      return 6;
    default:                      return 3;
    }
}

static int map_disconnect_reason_to_doc(uint8_t esp_reason)
{
    switch (esp_reason) {
    case WIFI_REASON_AUTH_EXPIRE:
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_MIC_FAILURE:
        return 2; /* authentication or key-exchange failure */
    case WIFI_REASON_BEACON_TIMEOUT:
    case WIFI_REASON_NO_AP_FOUND:
        return 1; /* beacon loss or out of range */
    default:
        return 0; /* AP-initiated deauthentication (catch-all) */
    }
}

/* ---- AT*M2M*WF_APMODE storage + profile activation ------------------
 * Backing store (m2m_sys NVS namespace, wiped along with everything else
 * by AT*M2M*SYS_FACTORY) for the profile AT*M2M*WF_APMODE saves/replays.
 * "target" tells at_wifi_activate_saved_profile() whether the saved
 * profile is a station or a SoftAP one -- the doc's own type values only
 * disambiguate this for type 2 (explicit SoftAP); type 1 ("activate the
 * predefined profile") replays whichever target was saved last. */
#define APMODE_TARGET_STA 0
#define APMODE_TARGET_AP  1

/* EN 18031-1 GEC-6: SSID 1..32 bytes; passphrase empty (open), 8..63
 * characters or 64 hex digits -- rejected rather than silently truncated
 * by strlcpy() into wifi_config_t. */
static bool wifi_cred_lengths_ok(const char *ssid, const char *password)
{
    size_t pw_len = password ? strlen(password) : 0;
    return ssid && ssid[0] && strlen(ssid) <= 32 && (pw_len == 0 || (pw_len >= 8 && pw_len <= 64));
}

/* Configures and starts a SoftAP, keeping station mode if it is on.
 * authmode is used only with a password (an empty one means open); cipher
 * WIFI_CIPHER_TYPE_UNKNOWN leaves the driver default. Shared by
 * apmode_start_ap() and OTH-AT APSTART/SMODE. */
bool at_wifi_start_softap(const char *ssid, uint8_t channel, wifi_auth_mode_t authmode,
                          wifi_cipher_type_t cipher, const char *password)
{
    if (!wifi_cred_lengths_ok(ssid, password)) {
        return false;
    }
    wifi_config_t ap_cfg = {0};
    strlcpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(ssid);
    ap_cfg.ap.channel = channel ? channel : 1;
    ap_cfg.ap.max_connection = 4;
    if (password && password[0] != '\0') {
        if (strlen(password) < 8) {
            return false;
        }
        strlcpy((char *)ap_cfg.ap.password, password, sizeof(ap_cfg.ap.password));
        ap_cfg.ap.authmode = (authmode == WIFI_AUTH_OPEN) ? WIFI_AUTH_WPA2_PSK : authmode;
        if (cipher != WIFI_CIPHER_TYPE_UNKNOWN) {
            ap_cfg.ap.pairwise_cipher = cipher;
        }
    } else {
#if !CONFIG_AT_MODEM_SOFTAP_ALLOW_OPEN
        return false; /* open (unauthenticated) SoftAP disabled in this build */
#endif
        ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    }

    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);
    wifi_mode_t new_mode = (cur_mode == WIFI_MODE_STA || cur_mode == WIFI_MODE_APSTA)
                            ? WIFI_MODE_APSTA : WIFI_MODE_AP;

    return esp_wifi_set_mode(new_mode) == ESP_OK &&
           esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) == ESP_OK &&
           esp_wifi_start() == ESP_OK;
}

static bool apmode_start_ap(const char *ssid, uint8_t channel, const char *password)
{
    return at_wifi_start_softap(ssid, channel, WIFI_AUTH_WPA2_PSK, WIFI_CIPHER_TYPE_UNKNOWN, password);
}

/* Replays the station profile esp_wifi already has persisted in flash
 * (WIFI_STORAGE_FLASH) from a prior successful AT*M2M*WF_CONN -- that's
 * the doc's "predefined station profile", no separate copy needed here. */
static bool apmode_start_sta(void)
{
    wifi_config_t sta_cfg;
    if (esp_wifi_get_config(WIFI_IF_STA, &sta_cfg) != ESP_OK || sta_cfg.sta.ssid[0] == '\0') {
        return false;
    }
    wifi_mode_t cur_mode;
    esp_wifi_get_mode(&cur_mode);
    wifi_mode_t new_mode = (cur_mode == WIFI_MODE_AP || cur_mode == WIFI_MODE_APSTA)
                            ? WIFI_MODE_APSTA : WIFI_MODE_STA;
    if (esp_wifi_set_mode(new_mode) != ESP_OK || esp_wifi_start() != ESP_OK) {
        return false;
    }
    atomic_store(&s_disconnect_requested, false);
    auth_retry_reset();
    return esp_wifi_connect() == ESP_OK;
}

/* Shared by cmd_wf_apmode() (type 1), at_wifi_init()'s boot-time
 * auto-reconnect and OTH-AT AUCONMODE/SMODE. */
bool at_wifi_activate_saved_profile(void)
{
    uint16_t target = APMODE_TARGET_STA;
    m2m_nvs_get_u16("apm_target", &target);

    if (target == APMODE_TARGET_AP) {
        char ssid[33] = "";
        char pw[65] = "";
        size_t ssid_len = sizeof(ssid);
        size_t pw_len = sizeof(pw);
        uint16_t channel = 1;
        m2m_nvs_get_str("apm_ssid", ssid, &ssid_len);
        m2m_nvs_get_str("apm_pw", pw, &pw_len);
        m2m_nvs_get_u16("apm_ch", &channel);
        if (ssid[0] == '\0') {
            return false;
        }
        return apmode_start_ap(ssid, (uint8_t)channel, pw);
    }
    return apmode_start_sta();
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;

    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_CONNECTED:
            auth_retry_reset();
            atomic_store(&s_sta_connected, true);
#if CONFIG_AT_MODEM_CMDSET_OTH
            at_event_post("ASSOCIATED:0");
#else
            at_event_post("WF_CONN:DONE");
#endif
            break;

#if CONFIG_AT_MODEM_CMDSET_OTH
        case WIFI_EVENT_STA_START:
            at_oth_wifi_on_start(WIFI_IF_STA);
            break;
        case WIFI_EVENT_AP_START:
            at_oth_wifi_on_start(WIFI_IF_AP);
            break;
#endif

        case WIFI_EVENT_STA_DISCONNECTED: {
            bool was_connected = atomic_exchange(&s_sta_connected, false);
            if (atomic_exchange(&s_disconnect_requested, false)) {
#if CONFIG_AT_MODEM_CMDSET_OTH
                if (was_connected) {
                    at_event_post("DISASSOCIATED"); /* "lost or closed" */
                }
#endif
                break; /* host-initiated via AT*M2M*WF_DISCONN -- no async notice */
            }
            const wifi_event_sta_disconnected_t *ev = (const wifi_event_sta_disconnected_t *)data;
            int doc_reason = map_disconnect_reason_to_doc(ev->reason);
            ESP_LOGI(TAG, "disconnected, reason %u", ev->reason);
            /* the first auth failure starts the sequence; once started,
             * any failure (e.g. CONNECTION_FAIL) continues it */
            if (doc_reason == 2 || atomic_load(&s_auth_retries) > 0) {
                int tries = atomic_fetch_add(&s_auth_retries, 1);
                if (tries < AUTH_RETRY_MAX && s_auth_retry_timer &&
                    esp_timer_start_once(s_auth_retry_timer, AUTH_RETRY_DELAY_US) == ESP_OK) {
                    ESP_LOGW(TAG, "connect failed (reason %u), retry %d/%d in 3 s", ev->reason, tries + 1,
                             AUTH_RETRY_MAX);
                    break;
                }
            }
#if CONFIG_AT_MODEM_CMDSET_OTH
            if (was_connected) {
                at_event_post("DISASSOCIATED");
                if (at_oth_wifi_autoconnect_enabled() && s_reconnect_timer) {
                    esp_timer_start_once(s_reconnect_timer, OTH_RECONNECT_DELAY_US);
                }
            } else if (ev->reason != WIFI_REASON_STA_LEAVING && ev->reason != WIFI_REASON_ASSOC_LEAVE) {
                /* (the module leaving by itself, e.g. WPS starting, is no
                 * failed join) */
                at_event_post("ASSOCIATED:%d", at_oth_wifi_assoc_result(ev->reason));
            }
#else
            (void)was_connected;
            at_event_post("WF_DISCONN:DONE %d", doc_reason);
#endif
            break;
        }

        case WIFI_EVENT_AP_STACONNECTED: {
            const wifi_event_ap_staconnected_t *ev = (const wifi_event_ap_staconnected_t *)data;
            int8_t rssi = 0;
            wifi_sta_list_t sta_list;
            if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
                for (int i = 0; i < sta_list.num; i++) {
                    if (memcmp(sta_list.sta[i].mac, ev->mac, 6) == 0) {
                        rssi = sta_list.sta[i].rssi;
                        break;
                    }
                }
            }
            at_event_post("STA_ASSOCIATED:" MACSTR " %d", MAC2STR(ev->mac), rssi);
            break;
        }

        case WIFI_EVENT_AP_STADISCONNECTED: {
#if !CONFIG_AT_MODEM_CMDSET_OTH /* OTH-AT has no "station left" message */
            const wifi_event_ap_stadisconnected_t *ev = (const wifi_event_ap_stadisconnected_t *)data;
            at_event_post("STA_DISASSOCIATED:" MACSTR, MAC2STR(ev->mac));
#endif
            break;
        }

        /* AT*M2M*WF_WPS (doc Ch.3.4) outcomes. Success hands the AP
         * credentials WPS just negotiated to the normal STA connect path --
         * esp_wifi_connect() below re-triggers WIFI_EVENT_STA_CONNECTED /
         * IP_EVENT_STA_GOT_IP, which already produce WF_CONN:DONE /
         * NET_IP:IND above, exactly like a doc-example WF_CONN would. */
        case WIFI_EVENT_STA_WPS_ER_SUCCESS: {
            const wifi_event_sta_wps_er_success_t *ev = (const wifi_event_sta_wps_er_success_t *)data;
            wifi_config_t sta_cfg = {0};
            if (ev && ev->ap_cred_cnt > 0) {
                memcpy(sta_cfg.sta.ssid, ev->ap_cred[0].ssid, sizeof(sta_cfg.sta.ssid));
                memcpy(sta_cfg.sta.password, ev->ap_cred[0].passphrase, sizeof(sta_cfg.sta.password));
            }
            esp_wifi_wps_disable();
            if (sta_cfg.sta.ssid[0] != '\0' && esp_wifi_set_config(WIFI_IF_STA, &sta_cfg) == ESP_OK) {
                atomic_store(&s_disconnect_requested, false);
                auth_retry_reset();
                esp_wifi_connect();
            }
            break;
        }

        /* The doc defines no async message of its own for a failed/timed-out
         * WPS attempt (Ch.3.4's only response is the synchronous WF_WPS:OK
         * ack of the request) -- WF_WPS:DONE is a project-specific notice,
         * mirroring the :DONE convention used throughout Ch.7, so the host
         * isn't left waiting forever on an attempt that will never reach
         * WF_CONN:DONE. reason: 0-failed; 1-timed out; 2-PBC session overlap
         * (two APs in PBC mode heard at once, doc has no code for this). */
        case WIFI_EVENT_STA_WPS_ER_FAILED:
        case WIFI_EVENT_STA_WPS_ER_TIMEOUT:
        case WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP: {
            esp_wifi_wps_disable();
#if CONFIG_AT_MODEM_CMDSET_OTH
            /* OTH-AT has no WPS message: a session that never joins ends as
             * a failed association -- 3 (timeout) or 1 (failure). */
            at_event_post("ASSOCIATED:%d", (id == WIFI_EVENT_STA_WPS_ER_TIMEOUT) ? 3 : 1);
#else
            int reason = (id == WIFI_EVENT_STA_WPS_ER_TIMEOUT) ? 1 :
                         (id == WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP) ? 2 : 0;
            at_event_post("WF_WPS:DONE %d", reason);
#endif
            break;
        }

        /* Also project-specific (see above) -- reports the PIN this WPS
         * session is actually using, so a WF_WPS=2 caller that omitted [pin]
         * (module then generates its own) still learns it. */
        case WIFI_EVENT_STA_WPS_ER_PIN: {
            const wifi_event_sta_wps_er_pin_t *ev = (const wifi_event_sta_wps_er_pin_t *)data;
            char pin[9];
            memcpy(pin, ev->pin_code, 8);
            pin[8] = '\0';
#if !CONFIG_AT_MODEM_CMDSET_OTH
            at_event_post("WF_WPS:IND %s", pin);
#endif
            break;
        }

        default:
            break;
        }
        return;
    }

    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = (const ip_event_got_ip_t *)data;
        esp_netif_dns_info_t dns = {0};
        esp_netif_get_dns_info(s_netif_sta, ESP_NETIF_DNS_MAIN, &dns);
        /* Doc Ch.7.1 message summary table: "NET_IP:IND <ip> <subnet>
         * <gateway> <dns>". (Ch.7.2 body text calls the same event "IP:IND"
         * and the Ch.8.1 usage examples call it "IPALLOCATED" -- three
         * spellings for one event in the doc as written; standardized on
         * the Ch.7.1 summary-table name per decision 2026-08-29.) */
#if CONFIG_AT_MODEM_CMDSET_OTH
        at_oth_mqtt_on_ip();
        at_oth_aws_on_ip();
        at_event_post("IPALLOCATED:" IPSTR " " IPSTR " " IPSTR " " IPSTR,
#else
        at_event_post("NET_IP:IND " IPSTR " " IPSTR " " IPSTR " " IPSTR,
#endif
                      IP2STR(&ev->ip_info.ip), IP2STR(&ev->ip_info.netmask),
                      IP2STR(&ev->ip_info.gw), IP2STR(&dns.ip.u_addr.ip4));
    }
#if CONFIG_AT_MODEM_CMDSET_OTH
    if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        at_event_post("IPRELEASED");
    }
#endif
}

void at_wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_netif_sta = esp_netif_create_default_wifi_sta();
    s_netif_ap = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    const esp_timer_create_args_t retry_args = { .callback = auth_retry_timer_cb, .name = "wifi_retry" };
    ESP_ERROR_CHECK(esp_timer_create(&retry_args, &s_auth_retry_timer));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                          &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                          &wifi_event_handler, NULL, NULL));
#if CONFIG_AT_MODEM_CMDSET_OTH
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_LOST_IP,
                                                          &wifi_event_handler, NULL, NULL));
    const esp_timer_create_args_t reconnect_args = { .callback = auth_retry_timer_cb, .name = "wifi_reconn" };
    ESP_ERROR_CHECK(esp_timer_create(&reconnect_args, &s_reconnect_timer));
#endif

    char cc[4] = "";
    size_t len = sizeof(cc);
    if (m2m_nvs_get_str("country", cc, &len) == ESP_OK && cc[0] != '\0') {
        esp_wifi_set_country_code(cc, true);
    }

    /* AT*M2M*SYS_LSLEEP: reapply the persisted power-save mode (default 0 =
     * WIFI_PS_NONE if never set, matching what cmd_sys_lsleep() reports on
     * an unset query). Mode 2 (light sleep) is never stored -- cmd_sys.c
     * rejects it before persisting -- so only 0/1/3 can reach here. */
    uint16_t lsleep_mode = 0;
#if CONFIG_AT_MODEM_CMDSET_OTH
    /* OTH-AT HWPS default is "automatic" (modem sleep, M2M numbering 1) */
    if (m2m_nvs_get_u16("lsleep", &lsleep_mode) != ESP_OK) {
        lsleep_mode = 1;
    }
#else
    m2m_nvs_get_u16("lsleep", &lsleep_mode);
#endif
    wifi_ps_type_t lsleep_ps = WIFI_PS_NONE;
    if (lsleep_mode == 1) {
        lsleep_ps = WIFI_PS_MIN_MODEM;
    } else if (lsleep_mode == 3) {
        lsleep_ps = WIFI_PS_MAX_MODEM;
    }
    esp_wifi_set_ps(lsleep_ps);

    /* AT*M2M*WF_APMODE: type 0 (default when never set) leaves the radio in
     * WIFI_MODE_NULL per doc, idle until a WF_MODE Set command engages it;
     * type 1/2 replays the saved station/SoftAP profile automatically. */
    uint16_t apm_type = 0;
    m2m_nvs_get_u16("apm_type", &apm_type);
    if (apm_type != 0) {
        if (at_wifi_activate_saved_profile()) {
#if CONFIG_AT_MODEM_CMDSET_OTH
            uint16_t target = APMODE_TARGET_STA;
            m2m_nvs_get_u16("apm_target", &target);
            s_boot_autoconnect = (target == APMODE_TARGET_STA);
#endif
            ESP_LOGI(TAG, "Wi-Fi driver ready, WF_APMODE=%u auto-reconnect activated", apm_type);
        } else {
            esp_wifi_set_mode(WIFI_MODE_NULL);
            ESP_LOGW(TAG, "Wi-Fi driver ready, WF_APMODE=%u profile unavailable, staying idle", apm_type);
        }
    } else {
        /* esp_wifi keeps the last mode in its own NVS namespace, so without
         * this WF_MODE's query would report e.g. 1 (station) for a radio
         * that was never started this boot. */
        esp_wifi_set_mode(WIFI_MODE_NULL);
        ESP_LOGI(TAG, "Wi-Fi driver ready, WF_APMODE disabled, staying in WIFI_MODE_NULL");
    }
}

esp_netif_t *at_wifi_get_sta_netif(void) { return s_netif_sta; }
esp_netif_t *at_wifi_get_ap_netif(void)  { return s_netif_ap; }

/* AT*M2M*WF_MODE -- mode: 0-init;1-station;2-SoftAP;3-station+SoftAP.
 * wifi_mode_t's own enum values already match the doc's numbering exactly. */
void cmd_wf_mode(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        at_reply_ok(cmd->name, "%d", (int)mode);
        return;
    }

    int mode = atoi(cmd->argv[0]);
    if (mode < WIFI_MODE_NULL || mode > WIFI_MODE_APSTA) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    /* argv[1] auto_connect is accepted for doc compatibility but not wired
     * to anything -- boot-time auto-reconnect is a separate, explicit
     * profile selection made through AT*M2M*WF_APMODE (cmd_wf_apmode()),
     * not a side effect of this command's own auto_connect flag. */

    esp_err_t err;
    if (mode == WIFI_MODE_NULL) {
        err = esp_wifi_stop();
        if (err == ESP_ERR_WIFI_NOT_STARTED) {
            err = ESP_OK;
        }
        if (err == ESP_OK) {
            /* stop alone leaves the driver's mode (and so our query) at the
             * previous value */
            err = esp_wifi_set_mode(WIFI_MODE_NULL);
        }
    } else {
        err = esp_wifi_set_mode((wifi_mode_t)mode);
        if (err == ESP_OK) {
            err = esp_wifi_start();
        }
    }

    if (err != ESP_OK) {
        at_reply_error(cmd->name, 0); /* doc: "reason: 0-not supported" */
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_APMODE=[type] [ssid] [channel] [password]
 * Doc Ch.3.1: controls automatic reconnection -- stores the working
 * connection profile in NV memory and rejoins/replays it (station or
 * SoftAP) after a reboot, per the selected type.
 * type: 0-init (clear the saved profile, disable auto-reconnect);
 *       1-activate the predefined profile (whichever station or SoftAP
 *         profile was saved last -- see at_wifi_activate_saved_profile());
 *       2-start a SoftAP with the given ssid/channel/password and save
 *         it as the new predefined profile.
 * The doc's Query response is "*M2M*WF_APMODE:OK [type] [ssid] [channel]
 * {password}" -- reproduced literally except a bare "0" when no profile
 * is saved, since the doc has nothing to report in that case either. */

void at_wifi_persist_apmode_sta(void)
{
    m2m_nvs_set_u16("apm_type", 1);
    m2m_nvs_set_u16("apm_target", APMODE_TARGET_STA);
}

void cmd_wf_apmode(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t type = 0;
        m2m_nvs_get_u16("apm_type", &type);
        if (type == 0) {
            at_reply_ok(cmd->name, "0");
            return;
        }
        char ssid[33] = "";
        char pw[65] = "";
        size_t ssid_len = sizeof(ssid);
        size_t pw_len = sizeof(pw);
        uint16_t channel = 0;
        m2m_nvs_get_str("apm_ssid", ssid, &ssid_len);
        m2m_nvs_get_str("apm_pw", pw, &pw_len);
        m2m_nvs_get_u16("apm_ch", &channel);
        /* EN 18031-1 SSM-3/ACM-2 (2026-09-27): never echo the stored
         * passphrase back -- "********" just says one is set. */
        at_reply_ok(cmd->name, "%d %s %d %s", type, ssid, channel, pw[0] ? "********" : "");
        return;
    }

    int type = atoi(cmd->argv[0]);

    if (type == 0) {
        m2m_nvs_set_u16("apm_type", 0);
        m2m_nvs_set_u16("apm_target", APMODE_TARGET_STA);
        m2m_nvs_set_str("apm_ssid", "");
        m2m_nvs_set_str("apm_pw", "");
        m2m_nvs_set_u16("apm_ch", 0);
        /* Also wipes esp_wifi's own flash-persisted STA/AP profile -- the
         * actual stored "AP connection info" -- not just this command's
         * own bookkeeping above, since WIFI_STORAGE_FLASH keeps that in a
         * separate NVS blob that esp_wifi_set_config() writes to directly. */
        esp_wifi_restore();
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (type == 1) {
        if (!at_wifi_activate_saved_profile()) {
            at_reply_error(cmd->name, AT_ERR_STATE); /* no predefined profile saved yet */
            return;
        }
        m2m_nvs_set_u16("apm_type", 1);
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (type == 2) {
        if (cmd->argc < 2) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        const char *ssid = cmd->argv[1];
        int channel = (cmd->argc >= 3) ? atoi(cmd->argv[2]) : 1;
        const char *password = (cmd->argc >= 4) ? cmd->argv[3] : "";
        if (channel < 1 || channel > 14) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        if (!apmode_start_ap(ssid, (uint8_t)channel, password)) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        m2m_nvs_set_u16("apm_type", 2);
        m2m_nvs_set_u16("apm_target", APMODE_TARGET_AP);
        m2m_nvs_set_str("apm_ssid", ssid);
        m2m_nvs_set_str("apm_pw", password);
        m2m_nvs_set_u16("apm_ch", (uint16_t)channel);
        at_reply_ok(cmd->name, NULL);
        return;
    }

    at_reply_error(cmd->name, AT_ERR_ARG);
}

/* AT*M2M*WF_SCAN -- Execute only. Implemented as a blocking scan (the
 * command channel is half-duplex per doc Ch.1.3 anyway), so the IND/DONE
 * lines below are written synchronously in-order rather than through the
 * async event queue -- see at_reply_line(). */
void cmd_wf_scan(const at_command_t *cmd)
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_STA && mode != WIFI_MODE_APSTA) {
        at_reply_error(cmd->name, 0); /* needs WF_MODE=1 or 3 first */
        return;
    }

    at_reply_ok(cmd->name, NULL);

    if (esp_wifi_scan_start(NULL, true) != ESP_OK) {
        at_reply_line("WF_SCAN:DONE");
        return;
    }

    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);
    if (num > 32) {
        num = 32; /* sane cap; doc doesn't bound scan result count */
    }
    wifi_ap_record_t *records = calloc(num, sizeof(wifi_ap_record_t));
    if (records) {
        esp_wifi_scan_get_ap_records(&num, records);
        for (uint16_t i = 0; i < num; i++) {
            at_reply_line("WF_SCAN:IND %s %d " MACSTR " %d %d",
                          records[i].ssid, records[i].rssi,
                          MAC2STR(records[i].bssid), records[i].primary,
                          map_authmode_to_doc(records[i].authmode));
        }
        free(records);
    }
    at_reply_line("WF_SCAN:DONE");
}

/* AT*M2M*WF_CONN=<ssid> [password] [bssid] [wep_key_index]
 * wep_key_index is accepted but not applied -- WEP isn't wired up through
 * this simple wifi_config_t path (deferred alongside WF_EAPCONF/CERT). */
void cmd_wf_conn(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        wifi_ap_record_t info;
        if (esp_wifi_sta_get_ap_info(&info) != ESP_OK) {
            at_reply_error(cmd->name, AT_ERR_STATE);
            return;
        }
        at_reply_ok(cmd->name, "%s " MACSTR " %d %d",
                    info.ssid, MAC2STR(info.bssid), info.primary, info.rssi);
        return;
    }

    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_STA && mode != WIFI_MODE_APSTA) {
        at_reply_error(cmd->name, 0); /* needs WF_MODE=1 or 3 first */
        return;
    }

    if (!wifi_cred_lengths_ok(cmd->argv[0], cmd->argc >= 2 ? cmd->argv[1] : NULL)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid, cmd->argv[0], sizeof(wifi_cfg.sta.ssid));
    if (cmd->argc >= 2) {
        strlcpy((char *)wifi_cfg.sta.password, cmd->argv[1], sizeof(wifi_cfg.sta.password));
    }
    if (cmd->argc >= 3) {
        unsigned int b[6];
        if (sscanf(cmd->argv[2], "%2x:%2x:%2x:%2x:%2x:%2x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
            for (int i = 0; i < 6; i++) {
                wifi_cfg.sta.bssid[i] = (uint8_t)b[i];
            }
            wifi_cfg.sta.bssid_set = true;
        }
    }

    if (esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg) != ESP_OK) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    atomic_store(&s_disconnect_requested, false);
    auth_retry_reset();
    if (esp_wifi_connect() != ESP_OK) {
        at_reply_error(cmd->name, 0);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    /* *M2M*WF_CONN:DONE and *M2M*IPALLOCATED follow asynchronously from
     * wifi_event_handler() once the association/DHCP lease complete. */
}

/* ---- Web UI (cmd_httpd.c) integration helpers --------------------------
 * Thin wrappers around the same esp_wifi_.../esp_eap_client_... calls the AT
 * commands above use, exposed so the embedded web server's /api/wifi*
 * routes can drive a scan/connect/enterprise-connect without going through
 * the AT command parser. Unlike WF_CONN/WF_SCAN (which require WF_MODE=1/3
 * to already be set and error out otherwise), these auto-enable STA mode
 * for a friendlier one-step web UX -- the AT command handlers above are
 * untouched, so existing AT behavior/tests are unaffected. */

bool at_wifi_ensure_sta_started(void)
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) {
        return true;
    }
    return esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK && esp_wifi_start() == ESP_OK;
}

/* Returns a cJSON array (caller must cJSON_Delete()) of
 * {ssid,rssi,channel,authmode,secure}, or NULL on failure. */
cJSON *at_wifi_web_scan(void)
{
    if (!at_wifi_ensure_sta_started()) {
        return NULL;
    }
    if (esp_wifi_scan_start(NULL, true) != ESP_OK) {
        return NULL;
    }
    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);
    if (num > 32) {
        num = 32;
    }
    cJSON *arr = cJSON_CreateArray();
    if (num == 0) {
        return arr;
    }
    wifi_ap_record_t *records = calloc(num, sizeof(wifi_ap_record_t));
    if (!records) {
        return arr;
    }
    esp_wifi_scan_get_ap_records(&num, records);
    for (uint16_t i = 0; i < num; i++) {
        cJSON *net = cJSON_CreateObject();
        cJSON_AddStringToObject(net, "ssid", (const char *)records[i].ssid);
        cJSON_AddNumberToObject(net, "rssi", records[i].rssi);
        cJSON_AddNumberToObject(net, "channel", records[i].primary);
        cJSON_AddBoolToObject(net, "secure", records[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(arr, net);
    }
    free(records);
    return arr;
}

/* Plain WPA-PSK/open connect, for the web UI's Wi-Fi screen. */
bool at_wifi_web_connect_psk(const char *ssid, const char *password)
{
    if (!wifi_cred_lengths_ok(ssid, password) || !at_wifi_ensure_sta_started()) {
        return false;
    }
    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid));
    if (password) {
        strlcpy((char *)wifi_cfg.sta.password, password, sizeof(wifi_cfg.sta.password));
    }
    if (esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg) != ESP_OK) {
        return false;
    }
    atomic_store(&s_disconnect_requested, false);
    auth_retry_reset();
    return esp_wifi_connect() == ESP_OK;
}

/* AT*M2M*WF_DISCONN -- Execute only. */
void cmd_wf_disconn(const at_command_t *cmd)
{
    atomic_store(&s_disconnect_requested, true);
    auth_retry_reset();
    if (esp_wifi_disconnect() != ESP_OK) {
        atomic_store(&s_disconnect_requested, false);
        at_reply_error(cmd->name, 0);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- AT*M2M*WF_EAPCONF / WF_EAPCERT -- 802.1X/EAP-Enterprise (doc Ch.3.2)
 * ESP-IDF's esp_eap_client_* API (CONFIG_ESP_WIFI_ENTERPRISE_SUPPORT=y,
 * already on in sdkconfig) is a set of independent global setters with no
 * single "apply" call -- WF_EAPCONF stages method/identity/password and
 * WF_EAPCERT stages certificate-file bytes (read from the same SPIFFS
 * store AT*M2M*NET_HTTPDOWNLOAD populates, via fs_store.c -- identical
 * pattern to AT*M2M*AWS_CLAIMCERT in cmd_aws.c). Either one re-arms
 * esp_wifi_sta_enterprise_enable() so a following WF_CONN can actually
 * attempt 802.1X authentication with whatever is currently staged. */

static char s_eap_method[8] = "";      /* "tls"/"ttls"/"peap"/"fast" */
static char s_eap_id[65] = "";
static char s_eap_password[129] = "";
static char s_eap_cert_file[17] = "";  /* WF_EAPCERT type 3, paired with 4 */
static char s_eap_key_file[17] = "";   /* WF_EAPCERT type 4 */
static char s_eap_key_password[129] = ""; /* OTH-AT EAPSET field 3; empty: use s_eap_password */
static char s_eap_ca_file[17] = "";    /* WF_EAPCERT type 2 / 5, for OTH-AT MIB 12/24 */
static char s_eap_pac_file[17] = "";

/* out_len (optional) receives the raw file byte count (excludes the NUL
 * this appends at out[n]) -- callers passing PEM text to mbedtls-backed
 * esp_eap_client_set_*() APIs need out_len+1 so mbedtls's PEM-vs-DER
 * autodetect (which requires buf[buflen-1]=='\0', see mbedtls's own
 * x509_crt.c/pkparse.c) actually recognizes it as PEM instead of silently
 * misparsing it as DER; callers passing opaque binary data (EAP-FAST PAC
 * files) need the raw out_len as-is, per esp_eap_client_set_pac_file()'s
 * own doc note ("length has to be decremented by 1 byte" from the
 * NUL-inclusive convention). */
static bool load_cert_file(const char *filename, char *out, size_t out_cap, size_t *out_len)
{
    return fs_store_read(filename, out, out_cap, out_len);
}

/* Heap-allocating counterpart, sized to the actual file content -- for
 * s_ca_pem/s_cert_pem/s_key_pem below, which wpa_supplicant's
 * esp_eap_client_set_ca_cert()/set_certificate_and_key() keep as raw
 * pointers (no internal copy) for as long as EAP-Enterprise Wi-Fi might
 * reconnect, i.e. indefinitely -- unlike esp_eap_client_set_pac_file(),
 * which does copy and so uses the shared g_at_pem_scratch instead. */
static char *load_cert_file_alloc(const char *filename, size_t *out_len)
{
    return fs_store_read_alloc(filename, out_len);
}

/* Shared by cmd_wf_eapcert() (AT*M2M*WF_EAPCERT, arbitrary staged filename)
 * and at_wifi_web_connect_enterprise() (web Enterprise screen, fixed
 * ca.pem/client.crt/client.key names -- same files the TLS Certificates
 * screen uploads and MQTT mTLS already reuses). Heap-allocated, sized to
 * actual content, rather than fixed 2200-byte statics reserved whether or
 * not this device ever uses EAP-Enterprise Wi-Fi: wpa_supplicant keeps
 * these as raw pointers (see load_cert_file_alloc()'s comment) with no
 * "clear EAP cert" API of its own, so each is simply freed-then-replaced
 * whenever a new cert/key is loaded, and otherwise lives until the process
 * restarts. */
static char *s_ca_pem;
static char *s_cert_pem;
static char *s_key_pem;

static bool load_and_set_ca_cert(const char *filename)
{
    size_t len;
    char *pem = load_cert_file_alloc(filename, &len);
    if (!pem) {
        return false;
    }
    if (esp_eap_client_set_ca_cert((const unsigned char *)pem, (int)(len + 1)) != ESP_OK) {
        free(pem);
        return false;
    }
    free(s_ca_pem);
    s_ca_pem = pem;
    return true;
}

static bool load_and_set_cert_and_key(const char *cert_file, const char *key_file, const char *password)
{
    size_t cert_len, key_len;
    char *cert_pem = load_cert_file_alloc(cert_file, &cert_len);
    char *key_pem = cert_pem ? load_cert_file_alloc(key_file, &key_len) : NULL;
    if (!cert_pem || !key_pem) {
        free(cert_pem);
        free(key_pem);
        return false;
    }
    if (esp_eap_client_set_certificate_and_key((const unsigned char *)cert_pem, (int)(cert_len + 1),
                                                (const unsigned char *)key_pem, (int)(key_len + 1),
                                                (const unsigned char *)password, (int)strlen(password)) != ESP_OK) {
        free(cert_pem);
        free(key_pem);
        return false;
    }
    free(s_cert_pem);
    free(s_key_pem);
    s_cert_pem = cert_pem;
    s_key_pem = key_pem;
    return true;
}

/* EN 18031-1 SCM-2 / C-05: the RADIUS server's certificate is always
 * verified -- against the staged CA (ca.pem / WF_EAPCERT type 2) when there
 * is one, otherwise against the same public CA bundle every other TLS client
 * in this firmware uses. Without either, PEAP/TTLS/TLS would hand the inner
 * credentials to any access point posing as the network. The bundle is only
 * attached when no CA is loaded: esp_crt_bundle_attach() replaces the verify
 * callback, which would ignore a private CA. Kconfig
 * AT_MODEM_EAP_ALLOW_NO_CA restores the old unverified behaviour. */
static esp_err_t eap_enable_with_server_validation(void)
{
#if CONFIG_AT_MODEM_EAP_ALLOW_NO_CA
    esp_eap_client_use_default_cert_bundle(false);
#else
    esp_eap_client_use_default_cert_bundle(s_ca_pem == NULL);
#endif
    return esp_wifi_sta_enterprise_enable();
}

/* Doc method values are "tls, ttls, peap, leap or fast" -- ESP-IDF's
 * esp_eap_method_t has no LEAP bit at all (not a config option here, the
 * EAP client code simply doesn't implement it), so "leap" is accepted by
 * the parser but rejected with AT_ERR_NOT_SUPPORTED, same treatment as
 * WF_MODE's unsupported 5GHz values in apply_wifi_protocol() above. */
static bool map_eap_method(const char *method, esp_eap_method_t *out)
{
    if (strcasecmp(method, "tls") == 0)  { *out = ESP_EAP_TYPE_TLS;  return true; }
    if (strcasecmp(method, "ttls") == 0) { *out = ESP_EAP_TYPE_TTLS; return true; }
    if (strcasecmp(method, "peap") == 0) { *out = ESP_EAP_TYPE_PEAP; return true; }
    if (strcasecmp(method, "fast") == 0) { *out = ESP_EAP_TYPE_FAST; return true; }
    return false;
}

/* WPA2/3-Enterprise connect (PEAP/TTLS/TLS), for the web UI's Enterprise
 * screen -- same esp_eap_client_* sequence as cmd_wf_eapconf()'s op=1
 * path, collapsed into one call since the web form submits everything at
 * once. Reuses the fixed ca.pem/client.crt/client.key names the TLS
 * Certificates screen uploads (same files MQTT mTLS already reuses):
 * ca.pem is applied to verify the server whenever it's staged, on any
 * method; a "tls" method additionally requires client.crt+client.key
 * (EAP-TLS authenticates with a client certificate, not a username/
 * password) and fails the connect attempt if they aren't staged yet --
 * AT*M2M*WF_EAPCERT remains available for a one-off CA cert under a
 * different filename. */
bool at_wifi_web_connect_enterprise(const char *ssid, const char *method,
                                     const char *identity, const char *anonymous_identity,
                                     const char *username, const char *password)
{
    /* EN 18031-1 GEC-6: lengths must fit what is kept for reconnects
     * (s_eap_id/s_eap_password) -- no silent truncation. */
    if (!ssid || !ssid[0] || strlen(ssid) > 32 || !method ||
        (identity && strlen(identity) >= sizeof(s_eap_id)) ||
        (anonymous_identity && strlen(anonymous_identity) >= sizeof(s_eap_id)) ||
        (username && strlen(username) >= sizeof(s_eap_id)) ||
        (password && strlen(password) >= sizeof(s_eap_password)) || !at_wifi_ensure_sta_started()) {
        return false;
    }
    esp_eap_method_t eap_bit;
    if (!map_eap_method(method, &eap_bit)) {
        return false;
    }
    const char *outer_id = (anonymous_identity && anonymous_identity[0]) ? anonymous_identity : identity;
    if (!outer_id || !outer_id[0]) {
        outer_id = username;
    }
    if (!outer_id || !outer_id[0]) {
        return false;
    }
    bool needs_user_pass = (eap_bit != ESP_EAP_TYPE_TLS);
    if (needs_user_pass && (!username || !username[0])) {
        return false;
    }

    if (esp_eap_client_set_identity((const unsigned char *)outer_id, (int)strlen(outer_id)) != ESP_OK ||
        esp_eap_client_set_eap_methods(eap_bit) != ESP_OK) {
        return false;
    }
    if (username && username[0]) {
        if (esp_eap_client_set_username((const unsigned char *)username, (int)strlen(username)) != ESP_OK) {
            return false;
        }
    }
    if (password && password[0]) {
        if (esp_eap_client_set_password((const unsigned char *)password, (int)strlen(password)) != ESP_OK) {
            return false;
        }
    } else {
        esp_eap_client_clear_password();
    }

    if (fs_store_exists("ca.pem") && !load_and_set_ca_cert("ca.pem")) {
        return false;
    }
    if (eap_bit == ESP_EAP_TYPE_TLS) {
        if (!fs_store_exists("client.crt") || !fs_store_exists("client.key") ||
            !load_and_set_cert_and_key("client.crt", "client.key", password ? password : "")) {
            return false;
        }
    }

    strlcpy(s_eap_method, method, sizeof(s_eap_method));
    strlcpy(s_eap_id, outer_id, sizeof(s_eap_id));
    strlcpy(s_eap_password, password ? password : "", sizeof(s_eap_password));

    if (eap_enable_with_server_validation() != ESP_OK) {
        return false;
    }

    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid));
    if (esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg) != ESP_OK) {
        return false;
    }
    atomic_store(&s_disconnect_requested, false);
    auth_retry_reset();
    return esp_wifi_connect() == ESP_OK;
}

/* AT*M2M*WF_EAPCONF=<cmd> <method> [id] [password]
 * cmd: 0-get;1-set. id is applied as both esp_eap_client_set_identity()
 * (outer/anonymous identity) and esp_eap_client_set_username() (phase-2
 * credential) -- the doc exposes a single identity-like field where
 * ESP-IDF has two, so the same value covers both roles.
 * The doc's Query form ("=<cmd> <method>") requires a method argument even
 * though only one profile is ever staged here -- accepted for wire
 * compatibility, not used to select between multiple profiles. */
void cmd_wf_eapconf(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int op = atoi(cmd->argv[0]);

    if (op == 0) {
        if (s_eap_method[0] == '\0') {
            at_reply_error(cmd->name, AT_ERR_STATE);
            return;
        }
        /* EN 18031-1 SSM-3/ACM-2 (2026-09-27): the password is masked. */
        at_reply_ok(cmd->name, "%s %s %s", s_eap_method, s_eap_id, s_eap_password[0] ? "********" : "");
        return;
    }
    if (op != 1 || cmd->argc < 4) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    esp_eap_method_t eap_bit;
    if (!map_eap_method(cmd->argv[1], &eap_bit)) {
        at_reply_error(cmd->name, AT_ERR_NOT_SUPPORTED);
        return;
    }
    const char *id = cmd->argv[2];
    const char *password = cmd->argv[3];
    if (id[0] == '\0' || strlen(id) > 64 || strlen(password) > 128) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    if (esp_eap_client_set_identity((const unsigned char *)id, (int)strlen(id)) != ESP_OK ||
        esp_eap_client_set_username((const unsigned char *)id, (int)strlen(id)) != ESP_OK ||
        esp_eap_client_set_eap_methods(eap_bit) != ESP_OK) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    if (password[0] != '\0') {
        if (esp_eap_client_set_password((const unsigned char *)password, (int)strlen(password)) != ESP_OK) {
            at_reply_error(cmd->name, AT_ERR_GENERIC);
            return;
        }
    } else {
        esp_eap_client_clear_password();
    }

    strlcpy(s_eap_method, cmd->argv[1], sizeof(s_eap_method));
    strlcpy(s_eap_id, id, sizeof(s_eap_id));
    strlcpy(s_eap_password, password, sizeof(s_eap_password));

    if (eap_enable_with_server_validation() != ESP_OK) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_EAPCERT=<type> <value> {..<type> <value>}
 * type 0: TTLS phase-2 method name ("EAP"/"MSCHAPV2"/"MSCHAP"/"PAP"/"CHAP").
 * type 1: PEAP phase-1 label -- accepted for wire compatibility, ESP-IDF's
 * EAP client exposes no such setting, so it's a no-op.
 * type 2/3/4/5: CA cert / client cert / private key / FAST PAC file name
 * (max 16 chars, must already exist on the module -- see fs_store.c/doc
 * Ch.6.2 NET_HTTPDOWNLOAD). Cert+key (3+4) are staged and only applied
 * together via esp_eap_client_set_certificate_and_key() once both are
 * present, since that's a single combined call.
 * Requires WF_EAPCONF to have run first (needs a method/id staged).
 * The doc's own example reply reads "*M2M*WF_CERT:OK" -- a doc typo (every
 * other reference in Ch.3.2 says WF_EAPCERT); not reproduced here. */
int at_wifi_eapcert_apply(int argc, char *argv[])
{
    char *pac_pem = g_at_pem_scratch; /* shared scratch, see at_pem_scratch.h --
                                        * esp_eap_client_set_pac_file() below
                                        * copies it internally (unlike the
                                        * ca/cert/key setters this file's own
                                        * s_ca_pem/s_cert_pem/s_key_pem feed,
                                        * which keep the raw pointer and so
                                        * stay as their own persistent statics). */

    if (argc < 2 || argc % 2 != 0) {
        return AT_ERR_ARG;
    }
    if (s_eap_method[0] == '\0') {
        return AT_ERR_STATE; /* WF_EAPCONF must run first */
    }

    for (int i = 0; i < argc; i += 2) {
        int type = atoi(argv[i]);
        const char *value = argv[i + 1];

        switch (type) {
        case 0: {
            esp_eap_ttls_phase2_types phase2;
            if (strcasecmp(value, "EAP") == 0)           phase2 = ESP_EAP_TTLS_PHASE2_EAP;
            else if (strcasecmp(value, "MSCHAPV2") == 0) phase2 = ESP_EAP_TTLS_PHASE2_MSCHAPV2;
            else if (strcasecmp(value, "MSCHAP") == 0)   phase2 = ESP_EAP_TTLS_PHASE2_MSCHAP;
            else if (strcasecmp(value, "PAP") == 0)      phase2 = ESP_EAP_TTLS_PHASE2_PAP;
            else if (strcasecmp(value, "CHAP") == 0)     phase2 = ESP_EAP_TTLS_PHASE2_CHAP;
            else {
                return AT_ERR_ARG;
            }
            esp_eap_client_set_ttls_phase2_method(phase2);
            break;
        }
        case 1:
            break; /* PEAP phase-1 label -- no ESP-IDF equivalent */
        case 2: {
            if (strlen(value) > 16 || !fs_store_exists(value)) {
                return AT_ERR_ARG;
            }
            if (!load_and_set_ca_cert(value)) {
                return AT_ERR_GENERIC;
            }
            strlcpy(s_eap_ca_file, value, sizeof(s_eap_ca_file));
            break;
        }
        case 3:
            if (strlen(value) > 16 || !fs_store_exists(value)) {
                return AT_ERR_ARG;
            }
            strlcpy(s_eap_cert_file, value, sizeof(s_eap_cert_file));
            break;
        case 4:
            if (strlen(value) > 16 || !fs_store_exists(value)) {
                return AT_ERR_ARG;
            }
            strlcpy(s_eap_key_file, value, sizeof(s_eap_key_file));
            break;
        case 5: {
            if (strlen(value) > 16 || !fs_store_exists(value)) {
                return AT_ERR_ARG;
            }
            /* PAC is an opaque binary blob, not PEM text -- use the raw
             * file length (not strlen(), which would truncate at the
             * first embedded 0x00 byte) per esp_eap_client_set_pac_file()'s
             * own doc note. */
            size_t pac_pem_len;
            if (!load_cert_file(value, pac_pem, AT_PEM_SCRATCH_LEN, &pac_pem_len) ||
                esp_eap_client_set_pac_file((const unsigned char *)pac_pem, (int)pac_pem_len) != ESP_OK) {
                return AT_ERR_GENERIC;
            }
            strlcpy(s_eap_pac_file, value, sizeof(s_eap_pac_file));
            break;
        }
        default:
            return AT_ERR_ARG;
        }
    }

    if (s_eap_cert_file[0] != '\0' && s_eap_key_file[0] != '\0') {
        if (!load_and_set_cert_and_key(s_eap_cert_file, s_eap_key_file,
                                       s_eap_key_password[0] ? s_eap_key_password : s_eap_password)) {
            return AT_ERR_GENERIC;
        }
    }

    if (eap_enable_with_server_validation() != ESP_OK) {
        return AT_ERR_GENERIC;
    }
    return 0;
}

void cmd_wf_eapcert(const at_command_t *cmd)
{
    int err = at_wifi_eapcert_apply(cmd->argc, (char **)cmd->argv);
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_IPSTATUS=? -- Query only. Reports one interface (station takes
 * priority over SoftAP in APSTA mode); the doc's single-line response shape
 * doesn't provide for reporting both at once. */
/* Applies a static IP (dhcp=false, ip/netmask/gateway required) or
 * switches back to the DHCP client (dhcp=true, other args ignored) on the
 * station interface. Shared by WF_IPSTATUS's Set form below and the web
 * UI's POST /api/network (cmd_httpd.c) -- the doc's own WF_IPSTATUS
 * description ("Reads or sets...") always intended a setter, but only a
 * Query Command was ever specified; this closes that gap. */
bool at_wifi_set_station_ip(bool dhcp, const char *ip, const char *netmask, const char *gateway)
{
    if (dhcp) {
        esp_netif_dhcpc_start(s_netif_sta); /* ESP_ERR_INVALID_STATE if already on -- not a failure */
        return true;
    }
    if (!ip || !ip[0] || !netmask || !netmask[0] || !gateway || !gateway[0]) {
        return false;
    }
    /* EN 18031-1 GEC-6: reject malformed dotted quads instead of applying
     * ipaddr_addr()'s IPADDR_NONE (255.255.255.255) as an address. */
    struct in_addr a_ip, a_nm, a_gw;
    if (!inet_aton(ip, &a_ip) || !inet_aton(netmask, &a_nm) || !inet_aton(gateway, &a_gw)) {
        return false;
    }
    esp_netif_ip_info_t ip_info = {0};
    ip_info.ip.addr = a_ip.s_addr;
    ip_info.netmask.addr = a_nm.s_addr;
    ip_info.gw.addr = a_gw.s_addr;
    esp_netif_dhcpc_stop(s_netif_sta);
    return esp_netif_set_ip_info(s_netif_sta, &ip_info) == ESP_OK;
}

/* AT*M2M*WF_IPSTATUS=<dhcp> [ip] [subnet] [gateway] -- Set form, station
 * interface only (matching the web UI's own scope -- SoftAP's addressing
 * is configured via WF_APSTART/NET_DHCPS instead). */
void cmd_wf_ipstatus(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);

        esp_netif_ip_info_t ip_info = {0};
        int bss_type = 0;
        bool have_info = false;

        if ((mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) &&
            esp_netif_get_ip_info(s_netif_sta, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            bss_type = 1;
            have_info = true;
        }
        if (!have_info && (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) &&
            esp_netif_get_ip_info(s_netif_ap, &ip_info) == ESP_OK) {
            bss_type = 2;
            have_info = true;
        }

        if (!have_info) {
            at_reply_error(cmd->name, AT_ERR_STATE);
            return;
        }

        /* doc: "dhcp: 0-static; 1-DHCP" -- station reports its DHCP *client*
         * state, SoftAP reports its DHCP *server* state. */
        esp_netif_dhcp_status_t dhcp_status = ESP_NETIF_DHCP_INIT;
        if (bss_type == 1) {
            esp_netif_dhcpc_get_status(s_netif_sta, &dhcp_status);
        } else {
            esp_netif_dhcps_get_status(s_netif_ap, &dhcp_status);
        }
        int dhcp = (dhcp_status == ESP_NETIF_DHCP_STARTED) ? 1 : 0;

        at_reply_ok(cmd->name, "%d %d " IPSTR " " IPSTR " " IPSTR,
                    bss_type, dhcp, IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
        return;
    }

    int dhcp = atoi(cmd->argv[0]);
    bool ok;
    if (dhcp == 1) {
        ok = at_wifi_set_station_ip(true, NULL, NULL, NULL);
    } else if (dhcp == 0 && cmd->argc >= 4) {
        ok = at_wifi_set_station_ip(false, cmd->argv[1], cmd->argv[2], cmd->argv[3]);
    } else {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (!ok) {
        at_reply_error(cmd->name, 2); /* reason 2: invalid IP arguments */
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_APSTART=<channel> <ssid> [auth] [password] [hidden]
 * auth=5 (WPA2-Enterprise) is accepted for completeness but not functional
 * without a RADIUS server integration, which is out of scope here. */
void cmd_wf_apstart(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_AP && mode != WIFI_MODE_APSTA) {
        at_reply_error(cmd->name, 0); /* needs WF_MODE=2 or 3 first */
        return;
    }

    int channel = atoi(cmd->argv[0]);
    const char *ssid = cmd->argv[1];
    int auth = (cmd->argc >= 3) ? atoi(cmd->argv[2]) : 0;
    const char *password = (cmd->argc >= 4) ? cmd->argv[3] : "";
    int hidden = (cmd->argc >= 5) ? atoi(cmd->argv[4]) : 0;

    wifi_auth_mode_t authmode;
    switch (auth) {
    case 0: authmode = WIFI_AUTH_OPEN; break;
    case 1: authmode = WIFI_AUTH_WPA_PSK; break;
    case 2: authmode = WIFI_AUTH_WPA2_PSK; break;
    case 3: authmode = WIFI_AUTH_WPA2_WPA3_PSK; break;
    case 4: authmode = WIFI_AUTH_WPA3_PSK; break;
    case 5: authmode = WIFI_AUTH_WPA2_ENTERPRISE; break;
    default:
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
#if !CONFIG_AT_MODEM_SOFTAP_ALLOW_OPEN
    if (authmode == WIFI_AUTH_OPEN) {
        at_reply_error(cmd->name, 0); /* 0-not supported: open SoftAP disabled in this build (Kconfig) */
        return;
    }
#endif
    if (!wifi_cred_lengths_ok(ssid, authmode == WIFI_AUTH_OPEN ? NULL : password) ||
        (authmode != WIFI_AUTH_OPEN && password[0] == '\0')) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (channel < 1 || channel > 14) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.ap.ssid, ssid, sizeof(wifi_cfg.ap.ssid));
    wifi_cfg.ap.channel = (uint8_t)channel;
    wifi_cfg.ap.authmode = authmode;
    strlcpy((char *)wifi_cfg.ap.password, password, sizeof(wifi_cfg.ap.password));
    wifi_cfg.ap.ssid_hidden = (uint8_t)(hidden ? 1 : 0);
    wifi_cfg.ap.max_connection = 4;

    if (esp_wifi_set_config(WIFI_IF_AP, &wifi_cfg) != ESP_OK) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_APSTATION -- Execute only. IP lookup is best-effort via the
 * DHCP server's lease table; a station that used a static IP (not DHCP)
 * reports 0.0.0.0. */
void cmd_wf_apstation(const at_command_t *cmd)
{
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) {
        at_reply_error(cmd->name, 0);
        return;
    }

    for (int i = 0; i < sta_list.num; i++) {
        esp_netif_pair_mac_ip_t pair = {0};
        memcpy(pair.mac, sta_list.sta[i].mac, 6);
        if (!s_netif_ap || esp_netif_dhcps_get_clients_by_mac(s_netif_ap, 1, &pair) != ESP_OK) {
            memset(&pair.ip, 0, sizeof(pair.ip));
        }
        at_reply_line("WF_APSTATION:IND " IPSTR " " MACSTR,
                      IP2STR(&pair.ip), MAC2STR(sta_list.sta[i].mac));
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*WF_WPS=<flag> [pin]
 * Doc Ch.3.4: flag 0-cancel; 1-start push-button mode; 2-start pin mode.
 * pin (8 decimal digits) is optional per the doc's own "[pin]" bracket --
 * given, it's used as-is; omitted, esp_wifi generates one itself and
 * reports it asynchronously (see wifi_event_handler()'s
 * WIFI_EVENT_STA_WPS_ER_PIN case, *M2M*WF_WPS:IND <pin>).
 * WPS only applies to station mode, same WF_MODE=1/3 precondition as
 * cmd_wf_conn(). Completion is asynchronous either way: success flows into
 * the normal WF_CONN:DONE/NET_IP:IND path, failure/timeout/PBC-overlap into
 * the project-specific WF_WPS:DONE notice -- see wifi_event_handler(). */
void cmd_wf_wps(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int flag = atoi(cmd->argv[0]);

    if (flag == 0) {
        esp_wifi_wps_disable();
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (flag != 1 && flag != 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_STA && mode != WIFI_MODE_APSTA) {
        at_reply_error(cmd->name, 0); /* needs WF_MODE=1 or 3 first */
        return;
    }

    esp_wps_config_t wps_cfg = {0};
    wps_cfg.wps_type = (flag == 1) ? WPS_TYPE_PBC : WPS_TYPE_PIN;
    if (flag == 2 && cmd->argc >= 2) {
        const char *pin = cmd->argv[1];
        if (strlen(pin) != 8) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        for (int i = 0; i < 8; i++) {
            if (!isdigit((unsigned char)pin[i])) {
                at_reply_error(cmd->name, AT_ERR_ARG);
                return;
            }
        }
        strlcpy(wps_cfg.pin, pin, sizeof(wps_cfg.pin));
    }

    if (esp_wifi_wps_enable(&wps_cfg) != ESP_OK || esp_wifi_wps_start(0) != ESP_OK) {
        at_reply_error(cmd->name, 0);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- OTH-AT integration helpers -----------------------------------------
 * Station join/leave in the shape OTH-AT needs (it has no WF_MODE: a join
 * switches station mode on by itself), plus EAPSET, which stages the same
 * esp_eap_client_* settings WF_EAPCONF does but field by field. */

/* Joins with an already-filled station config. */
bool at_wifi_sta_join(const wifi_config_t *cfg)
{
    if (!at_wifi_ensure_sta_started()) {
        return false;
    }
    if (esp_wifi_set_config(WIFI_IF_STA, (wifi_config_t *)cfg) != ESP_OK) {
        return false;
    }
    atomic_store(&s_disconnect_requested, false);
    auth_retry_reset();
    return esp_wifi_connect() == ESP_OK;
}

bool at_wifi_sta_leave(void)
{
    atomic_store(&s_disconnect_requested, true);
    auth_retry_reset();
    if (esp_wifi_disconnect() != ESP_OK) {
        atomic_store(&s_disconnect_requested, false);
        return false;
    }
    return true;
}

bool at_wifi_sta_is_connected(void)
{
    return atomic_load(&s_sta_connected);
}

#if CONFIG_AT_MODEM_CMDSET_OTH
/* True once, right after boot, when a saved station profile is being
 * rejoined (OTH-AT *OTH*INITSCAN). */
bool at_wifi_take_boot_autoconnect(void)
{
    bool v = s_boot_autoconnect;
    s_boot_autoconnect = false;
    return v;
}

/* OTH-AT EAPSET field/value pairs. field 0: method, 1: identity (inner user
 * name), 2: anonymous (outer) identity, 3: private-key password, 4: EAP
 * password. Returns 0 or an OTH Appendix A error code. */
int at_wifi_oth_eapset(int argc, char *argv[])
{
    if (argc < 2 || argc % 2 != 0) {
        return 8; /* ERR_GENERAL_PARAM_INVALID */
    }
    for (int i = 0; i < argc; i += 2) {
        int field = atoi(argv[i]);
        const char *v = argv[i + 1];
        size_t len = strlen(v);
        switch (field) {
        case 0: {
            esp_eap_method_t bit;
            if (!map_eap_method(v, &bit)) {
                return 5; /* ERR_WIFI_CONFIG_PARAM_INVALID (incl. leap: not in ESP-IDF) */
            }
            if (esp_eap_client_set_eap_methods(bit) != ESP_OK) {
                return 5;
            }
            strlcpy(s_eap_method, v, sizeof(s_eap_method));
            break;
        }
        case 1:
            if (len == 0 || len > 64 ||
                esp_eap_client_set_username((const unsigned char *)v, (int)len) != ESP_OK) {
                return 5;
            }
            if (s_eap_id[0] == '\0') { /* outer identity too, unless field 2 sets one */
                esp_eap_client_set_identity((const unsigned char *)v, (int)len);
            }
            break;
        case 2:
            if (len == 0 || len > 64 ||
                esp_eap_client_set_identity((const unsigned char *)v, (int)len) != ESP_OK) {
                return 5;
            }
            strlcpy(s_eap_id, v, sizeof(s_eap_id));
            break;
        case 3:
            if (len > 128) {
                return 5;
            }
            strlcpy(s_eap_key_password, v, sizeof(s_eap_key_password));
            break;
        case 4:
            if (len > 128) {
                return 5;
            }
            if (len) {
                if (esp_eap_client_set_password((const unsigned char *)v, (int)len) != ESP_OK) {
                    return 5;
                }
            } else {
                esp_eap_client_clear_password();
            }
            strlcpy(s_eap_password, v, sizeof(s_eap_password));
            break;
        default:
            return 8;
        }
    }
    return eap_enable_with_server_validation() == ESP_OK ? 0 : 5;
}
/* Staged EAP settings for OTH-AT MIB (read-only view, password not
 * exposed -- only whether one is set). */
void at_wifi_eap_info(at_wifi_eap_info_t *out)
{
    out->method = s_eap_method;
    out->identity = s_eap_id;
    out->has_password = s_eap_password[0] != '\0';
    out->ca_file = s_eap_ca_file;
    out->cert_file = s_eap_cert_file;
    out->key_file = s_eap_key_file;
    out->pac_file = s_eap_pac_file;
}
#endif
