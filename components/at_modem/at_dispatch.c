#include <strings.h>

#include "at_dispatch.h"
#include "at_parser.h"
#include "at_response.h"
#include "at_commands.h"
#include "at_cmdset.h"
#if CONFIG_AT_MODEM_CMDSET_OTH
#include "at_commands_oth.h"
#endif

typedef void (*at_cmd_handler_t)(const at_command_t *cmd);

typedef struct {
    const char *name;
    at_cmd_handler_t handler;
    bool raw; /* true: skip generic tokenization, handler parses raw_params itself
               * (needed when the last field is arbitrary payload data that may
               * contain spaces, e.g. NET_SEND). */
} at_dispatch_entry_t;

/* Special commands (bare OK/ERROR, no *M2M* wrapper) share this table --
 * lookup is by at_command_t.name regardless of the is_special flag.
 *
 * Phase 0: AT/ATE/ATV. Phase 1: SYS_* Basic + core WF_* Wi-Fi commands.
 * SYS_LSLEEP/SYS_ANTENNA were deferred here and implemented later (2026-09-26,
 * see cmd_sys.c for the hardware caveats on each: SYS_LSLEEP mode=2 and
 * SYS_ANTENNA type=1 both reply the doc's own "reason: 0-not supported").
 * BLE_PROV (doc Ch.3.5, added 2026-09-26) is a later addition too, on
 * wifi_provisioning + protocomm rather than anything WF_*-adjacent hand-rolls
 * -- see cmd_ble_prov.c and doc/M2M BT Provisioning Architecture Review.docx.
 * Phase 2: NET_* TCP/IP + DHCP/PING/DNS/SNTP commands, including
 * NET_CONN/NET_SERVER's SSL type on net_link.c's own raw-socket TLS layer
 * (esp_tls-based, see net_link.h's top comment).
 * Phase 3: NET_HTTP.../NET_HTTPD... -- HTTPS is supported here via a
 * different, already-solved mechanism (esp_http_client owns its own TLS
 * session internally), unrelated to net_link.c's raw-socket layer.
 * Phase 4: MQTT_* -- likewise TLS-capable via esp-mqtt's own TLS handling
 * (mqtts/wss), same reasoning as Phase 3.
 * Phase 6: OTA_CHECK/OTA_UPDATE, on esp_https_ota.
 * Phase 5 (this table, done out of order after the doc was updated to add
 * AWS IoT's own Fleet Provisioning by Claim): AWS_*. AWS_PAIR (a custom
 * pairing-service protocol) is still a stub -- its wire protocol is never
 * specified -- but AWS_CLAIMCERT/AWS_PROVISION/AWS_CERT/AWS_CONN/AWS_DISC/
 * AWS_PUB/AWS_SUB are fully implemented against AWS IoT's own documented
 * $aws/... topics, a real (not invented) protocol. Per
 * C:\Users\crowm\.claude\plans\tingly-gathering-parasol.md. */
#if !CONFIG_AT_MODEM_CMDSET_OTH
static const at_dispatch_entry_t s_table[] = {
    { "AT",           cmd_at,           false },
    { "ATE",          cmd_ate,          false },
    { "ATV",          cmd_atv,          false },

    { "SYS_VER",      cmd_sys_ver,      false },
    { "SYS_MAC",      cmd_sys_mac,      false },
    { "SYS_RST",      cmd_sys_rst,      false },
    { "SYS_FACTORY",  cmd_sys_factory,  false },
    { "SYS_UART",     cmd_sys_uart,     false },
    { "SYS_CONF",     cmd_sys_conf,     false },
    { "SYS_COUNTRY",  cmd_sys_country,  false },
    { "SYS_LSLEEP",   cmd_sys_lsleep,   false },
    { "SYS_ANTENNA",  cmd_sys_antenna,  false },

    { "WF_MODE",      cmd_wf_mode,      false },
    { "WF_APMODE",    cmd_wf_apmode,    false },
    { "WF_SCAN",      cmd_wf_scan,      false },
    { "WF_CONN",      cmd_wf_conn,      false },
    { "WF_DISCONN",   cmd_wf_disconn,   false },
    { "WF_EAPCONF",   cmd_wf_eapconf,   false },
    { "WF_EAPCERT",   cmd_wf_eapcert,   false },
    { "WF_IPSTATUS",  cmd_wf_ipstatus,  false },
    { "WF_APSTART",   cmd_wf_apstart,   false },
    { "WF_APSTATION", cmd_wf_apstation, false },
    { "WF_WPS",       cmd_wf_wps,       false },
    { "BLE_PROV",     cmd_ble_prov,     false },
    { "BLE_POP",      cmd_ble_pop,      false },

    { "NET_STATUS",   cmd_net_status,   false },
    { "NET_CONN",     cmd_net_conn,     false },
    { "NET_DISCONN",  cmd_net_disconn, false },
    { "NET_SEND",     cmd_net_send,     true }, /* payload may contain spaces */
    { "NET_SERVER",   cmd_net_server,   false },
    { "NET_PING",     cmd_net_ping,     false },
    { "NET_DNS",      cmd_net_dns,      false },
    { "NET_DTMODE",   cmd_net_dtmode,   false },
    { "NET_SNTP",     cmd_net_sntp,     false },
    { "NET_SNTPCONF", cmd_net_sntpconf, false },
    { "NET_DHCPS",    cmd_net_dhcps,    false },
    { "NET_DHCP",     cmd_net_dhcp,     false },

    { "NET_HTTPSET",     cmd_net_httpset,      false },
    { "NET_HTTPHEADER",  cmd_net_httpheader,   false },
    { "NET_HTTPGET",     cmd_net_httpget,      false },
    { "NET_HTTPPOST",    cmd_net_httppost,     true }, /* payload may contain spaces */
    { "NET_HTTPDOWNLOAD",cmd_net_httpdownload, true }, /* tolerant comma/space parsing, see cmd_http.c */
    { "NET_FILELIST",    cmd_net_filelist,     false },
    { "NET_FILEINFO",    cmd_net_fileinfo,     false },
    { "NET_HTTPSTOP",    cmd_net_httpstop,     false },
    { "NET_HTTPDSTART",  cmd_net_httpdstart,   false },
    { "NET_HTTPDSTOP",   cmd_net_httpdstop,    false },
    { "NET_HTTPDCONF",   cmd_net_httpdconf,    false },

    { "MQTT_CONF",  cmd_mqtt_conf,  false },
    { "MQTT_ALPN",  cmd_mqtt_alpn,  false },
    { "MQTT_CONN",  cmd_mqtt_conn,  false },
    { "MQTT_STATUS",cmd_mqtt_status,false },
    { "MQTT_PUB",   cmd_mqtt_pub,   true }, /* doubled-quote-escaped topic/data, see cmd_mqtt.c */
    { "MQTT_SUB",   cmd_mqtt_sub,   false },
    { "MQTT_CLEAN", cmd_mqtt_clean, false },

    { "OTA_CHECK",  cmd_ota_check,  false },
    { "OTA_UPDATE", cmd_ota_update, false },

    { "AWS_PAIR",      cmd_aws_pair,      false },
    { "AWS_CLAIMCERT", cmd_aws_claimcert, false },
    { "AWS_PROVISION", cmd_aws_provision, false },
    { "AWS_CERT",      cmd_aws_cert,      false },
    { "AWS_CONN",      cmd_aws_conn,      false },
    { "AWS_DISC",      cmd_aws_disc,      false },
    { "AWS_PUB",       cmd_aws_pub,       false },
    { "AWS_SUB",       cmd_aws_sub,       false },
};
#else
/* OTH-AT Compatible Command Set (Essentials/MQTT/AWS/COAP volumes). Each
 * cmd_oth_*.c handler is a thin front end over the same Wi-Fi, socket and
 * service code the M2M handlers use. */
static const at_dispatch_entry_t s_table[] = {
    { "AT",           cmd_at,           false },
    { "ATE",          cmd_ate,          false },
    /* Ch.2 Basic */
    { "SWVER",        cmd_oth_swver,        false },
    { "MAC",          cmd_oth_mac,          false },
    { "RESET",        cmd_oth_reset,        false },
    { "FACRESET",     cmd_oth_facreset,     false },
    { "EVTDEL",       cmd_oth_evtdel,       false },
    { "HWPS",         cmd_oth_hwps,         false },
    { "ANTVER",       cmd_oth_antver,       false },
    { "SETANT",       cmd_oth_setant,       false },
    { "TXGAIN",       cmd_oth_txgain,       false },
    { "COUNTRY",      cmd_oth_country,      false },
    /* Ch.3 Wi-Fi */
    { "MODE",         cmd_oth_mode,         false },
    { "SCAN",         cmd_oth_scan,         false },
    { "CRYPTO",       cmd_oth_crypto,       false },
    { "WEP",          cmd_oth_wep,          false },
    { "PSK",          cmd_oth_psk,          false },
    { "ASSOCIATE",    cmd_oth_associate,    false },
    { "DISASSOCIATE", cmd_oth_disassociate, false },
    { "SCONN",        cmd_oth_sconn,        false },
    { "AUCONMODE",    cmd_oth_auconmode,    false },
    { "SMODE",        cmd_oth_smode,        false },
    { "EAPSET",       cmd_oth_eapset,       false },
    { "EAPCERT",      cmd_oth_eapcert,      false },
    { "NWSTATUS",     cmd_oth_nwstatus,     false },
    { "APSTART",      cmd_oth_apstart,      false },
    { "APSTOP",       cmd_oth_apstop,       false },
    { "APNSET",       cmd_oth_apnset,       false },
    { "APLEASEIP",    cmd_oth_apleaseip,    false },
    { "DHCPDSTART",   cmd_oth_dhcpdstart,   false },
    { "DHCPDSTOP",    cmd_oth_dhcpdstop,    false },
    { "WPS_PBC",      cmd_oth_wps_pbc,      false },
    { "WPS_PIN",      cmd_oth_wps_pin,      false },
    { "WPS_CANCEL",   cmd_oth_wps_cancel,   false },
};
#endif

#define TABLE_LEN (sizeof(s_table) / sizeof(s_table[0]))

void at_dispatch_line(char *line)
{
    at_command_t cmd;
    if (!at_parse_line(line, &cmd)) {
        at_reply_special_error();
        return;
    }

    for (size_t i = 0; i < TABLE_LEN; i++) {
        if (strcasecmp(s_table[i].name, cmd.name) == 0) {
            if (!s_table[i].raw && !cmd.is_special) {
                cmd.argc = at_tokenize_params(cmd.raw_params, cmd.argv, AT_MAX_PARAMS);
            }
            s_table[i].handler(&cmd);
            return;
        }
    }

    /* Unknown command: special commands get a bare ERROR, tagged commands get
     * a wrapped ERROR with the "not supported" code. */
    if (cmd.is_special) {
        at_reply_special_error();
    } else {
        at_reply_error(cmd.name, AT_ERR_UNKNOWN_CMD);
    }
}
