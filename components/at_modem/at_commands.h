#pragma once
/* Private (component-internal) declarations of every AT command handler.
 * Included only by at_dispatch.c to build the dispatch table.
 *
 * Phase 0: only the bare special commands exist. Later phases add a
 * commented-header section per source file (cmd_basic.c, cmd_wifi.c, ...)
 * as those files are ported, per the plan at
 * C:\Users\crowm\.claude\plans\tingly-gathering-parasol.md. */

#include "at_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* cmd_special.c */
void cmd_at(const at_command_t *cmd);
void cmd_ate(const at_command_t *cmd);
void cmd_atv(const at_command_t *cmd);

/* cmd_sys.c -- Basic AT Commands (doc Ch.2) */
void cmd_sys_ver(const at_command_t *cmd);
void cmd_sys_mac(const at_command_t *cmd);
void cmd_sys_rst(const at_command_t *cmd);
void cmd_sys_factory(const at_command_t *cmd);
void cmd_sys_uart(const at_command_t *cmd);
void cmd_sys_conf(const at_command_t *cmd);
void cmd_sys_country(const at_command_t *cmd);
void cmd_sys_lsleep(const at_command_t *cmd);
void cmd_sys_antenna(const at_command_t *cmd);
/* NVS wipe shared by SYS_FACTORY and OTH-AT FACRESET */
void at_sys_nv_erase(void);

/* cmd_wifi.c -- Wi-Fi AT Commands (doc Ch.3: Common, Station, SoftAP) */
void cmd_wf_mode(const at_command_t *cmd);
void cmd_wf_apmode(const at_command_t *cmd);
void cmd_wf_scan(const at_command_t *cmd);
void cmd_wf_conn(const at_command_t *cmd);
void cmd_wf_disconn(const at_command_t *cmd);
void cmd_wf_eapconf(const at_command_t *cmd);
void cmd_wf_eapcert(const at_command_t *cmd);
void cmd_wf_ipstatus(const at_command_t *cmd);
void cmd_wf_apstart(const at_command_t *cmd);
void cmd_wf_apstation(const at_command_t *cmd);
void cmd_wf_wps(const at_command_t *cmd);

/* cmd_ble_prov.c -- BLE Provisioning (doc Ch.3.5), on wifi_provisioning + protocomm */
void cmd_ble_prov(const at_command_t *cmd);
void cmd_ble_pop(const at_command_t *cmd);

/* cmd_net.c -- socket/address commands (doc Ch.4.2), on net_link.c */
void cmd_net_status(const at_command_t *cmd);
void cmd_net_conn(const at_command_t *cmd);
void cmd_net_disconn(const at_command_t *cmd);
void cmd_net_send(const at_command_t *cmd);
void cmd_net_server(const at_command_t *cmd);

/* cmd_net_svc.c -- standalone network services (doc Ch.4.2, 6.1) */
void cmd_net_ping(const at_command_t *cmd);
void cmd_net_dns(const at_command_t *cmd);
void cmd_net_sntp(const at_command_t *cmd);
void cmd_net_sntpconf(const at_command_t *cmd);
void cmd_net_dhcps(const at_command_t *cmd);
void cmd_net_dhcp(const at_command_t *cmd);

/* cmd_net_dtmode.c -- transparent passthrough (doc Ch.4.1/8.5) */
void cmd_net_dtmode(const at_command_t *cmd);

/* cmd_http.c -- HTTP client (doc Ch.6.2) */
void cmd_net_httpset(const at_command_t *cmd);
void cmd_net_httpheader(const at_command_t *cmd);
void cmd_net_httpget(const at_command_t *cmd);
void cmd_net_httppost(const at_command_t *cmd);
void cmd_net_httpdownload(const at_command_t *cmd);
void cmd_net_filelist(const at_command_t *cmd);
void cmd_net_fileinfo(const at_command_t *cmd);
void cmd_net_httpstop(const at_command_t *cmd);

/* cmd_httpd.c -- HTTP server (doc Ch.6.3) */
void cmd_net_httpdstart(const at_command_t *cmd);
void cmd_net_httpdstop(const at_command_t *cmd);
void cmd_net_httpdconf(const at_command_t *cmd);

/* cmd_mqtt.c -- MQTT client (doc Ch.6.4) */
void cmd_mqtt_conf(const at_command_t *cmd);
void cmd_mqtt_alpn(const at_command_t *cmd);
void cmd_mqtt_conn(const at_command_t *cmd);
void cmd_mqtt_status(const at_command_t *cmd);
void cmd_mqtt_pub(const at_command_t *cmd);
void cmd_mqtt_sub(const at_command_t *cmd);
void cmd_mqtt_clean(const at_command_t *cmd);

/* cmd_ota.c -- Firmware OTA (doc Ch.6.6) */
void cmd_ota_check(const at_command_t *cmd);
void cmd_ota_update(const at_command_t *cmd);

/* cmd_aws.c -- AWS IoT Core client (doc Ch.6.5) */
void cmd_aws_pair(const at_command_t *cmd);
void cmd_aws_claimcert(const at_command_t *cmd);
void cmd_aws_provision(const at_command_t *cmd);
void cmd_aws_cert(const at_command_t *cmd);
void cmd_aws_conn(const at_command_t *cmd);
void cmd_aws_disc(const at_command_t *cmd);
void cmd_aws_pub(const at_command_t *cmd);
void cmd_aws_sub(const at_command_t *cmd);

#ifdef __cplusplus
}
#endif
