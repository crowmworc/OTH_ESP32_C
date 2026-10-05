#pragma once
/* Private declarations of the OTH-AT command handlers (built only with
 * CONFIG_AT_MODEM_CMDSET_OTH), included by at_dispatch.c. Chapter numbers
 * refer to "OTH-AT Compatible Command Set - Essentials" unless noted. */

#include "at_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OTH Appendix A error codes */
#define OTH_ERR_SOCKET_NOT_AVAIL         1
#define OTH_ERR_SOCKET_INVALID           2
#define OTH_ERR_SOCKET_NOT_EXIST         3
#define OTH_ERR_CONNECTION_ESTABLISHMENT 4
#define OTH_ERR_WIFI_CONFIG_PARAM        5
#define OTH_ERR_TCPIP_PARAM              6
#define OTH_ERR_OUT_OF_MEMORY            7
#define OTH_ERR_GENERAL_PARAM            8
#define OTH_ERR_COMMAND_NOT_EXIST        9
#define OTH_ERR_ADDRESS_IN_USE           10

/* cmd_oth_basic.c -- Ch.2 Basic AT Commands */
void cmd_oth_swver(const at_command_t *cmd);
void cmd_oth_mac(const at_command_t *cmd);
void cmd_oth_reset(const at_command_t *cmd);
void cmd_oth_facreset(const at_command_t *cmd);
void cmd_oth_evtdel(const at_command_t *cmd);
void cmd_oth_hwps(const at_command_t *cmd);
void cmd_oth_antver(const at_command_t *cmd);
void cmd_oth_setant(const at_command_t *cmd);
void cmd_oth_txgain(const at_command_t *cmd);
void cmd_oth_country(const at_command_t *cmd);
/* cmd_oth_fwup.c -- FWUPGRADE (XMODEM) */
void cmd_oth_fwupgrade(const at_command_t *cmd);

/* cmd_oth_wifi.c -- Ch.3 Wi-Fi AT Commands */
void cmd_oth_mode(const at_command_t *cmd);
void cmd_oth_scan(const at_command_t *cmd);
void cmd_oth_crypto(const at_command_t *cmd);
void cmd_oth_wep(const at_command_t *cmd);
void cmd_oth_psk(const at_command_t *cmd);
void cmd_oth_associate(const at_command_t *cmd);
void cmd_oth_disassociate(const at_command_t *cmd);
void cmd_oth_sconn(const at_command_t *cmd);
void cmd_oth_auconmode(const at_command_t *cmd);
void cmd_oth_smode(const at_command_t *cmd);
void cmd_oth_eapset(const at_command_t *cmd);
void cmd_oth_eapcert(const at_command_t *cmd);
void cmd_oth_nwstatus(const at_command_t *cmd);
void cmd_oth_apstart(const at_command_t *cmd);
void cmd_oth_apstop(const at_command_t *cmd);
void cmd_oth_apnset(const at_command_t *cmd);
void cmd_oth_apleaseip(const at_command_t *cmd);
void cmd_oth_dhcpdstart(const at_command_t *cmd);
void cmd_oth_dhcpdstop(const at_command_t *cmd);
void cmd_oth_wps_pbc(const at_command_t *cmd);
void cmd_oth_wps_pin(const at_command_t *cmd);
void cmd_oth_wps_cancel(const at_command_t *cmd);

/* cmd_oth_net.c -- Ch.4 TCP/IP and Ch.5 SSL AT Commands */
void cmd_oth_ipconfig(const at_command_t *cmd);
void cmd_oth_socket(const at_command_t *cmd);
void cmd_oth_close(const at_command_t *cmd);
void cmd_oth_connect(const at_command_t *cmd);
void cmd_oth_disconnect(const at_command_t *cmd);
void cmd_oth_bind(const at_command_t *cmd);
void cmd_oth_listen(const at_command_t *cmd);
void cmd_oth_lstatus(const at_command_t *cmd);
void cmd_oth_send(const at_command_t *cmd);
void cmd_oth_sendto(const at_command_t *cmd);
void cmd_oth_tcpkeep(const at_command_t *cmd);
void cmd_oth_nw_conn(const at_command_t *cmd);
void cmd_oth_ping(const at_command_t *cmd);
void cmd_oth_dnsquery(const at_command_t *cmd);
void cmd_oth_data_socket(const at_command_t *cmd);
void cmd_oth_data_interval(const at_command_t *cmd);
void cmd_oth_ssl_connect(const at_command_t *cmd);
void cmd_oth_ssl_send(const at_command_t *cmd);
void cmd_oth_ssl_close(const at_command_t *cmd);
void cmd_oth_ssl_svr_start(const at_command_t *cmd);
void cmd_oth_ssl_svr_send(const at_command_t *cmd);
void cmd_oth_ssl_svr_close(const at_command_t *cmd);
void at_oth_net_init(void);

/* Ch.6 Network Services -- cmd_http.c (HTTP client), cmd_net_svc.c (SNTP),
 * cmd_oth_svc.c (web server, FTP credentials, OTA) */
void cmd_oth_httpget(const at_command_t *cmd);
void cmd_oth_httppost(const at_command_t *cmd);
void cmd_oth_httpset(const at_command_t *cmd);
void cmd_oth_httpheader(const at_command_t *cmd);
void cmd_oth_httpstop(const at_command_t *cmd);
void cmd_oth_http_download(const at_command_t *cmd);
void cmd_oth_sntp(const at_command_t *cmd);
void cmd_oth_sntp_get(const at_command_t *cmd);
void cmd_oth_sntp_set(const at_command_t *cmd);
void cmd_oth_httpd_start(const at_command_t *cmd);
void cmd_oth_httpd_stop(const at_command_t *cmd);
void cmd_oth_httpd_idpw(const at_command_t *cmd);
void cmd_oth_ftpc_set(const at_command_t *cmd);
void cmd_oth_ftpc_get(const at_command_t *cmd);
void cmd_oth_ota_vercheck(const at_command_t *cmd);
void cmd_oth_ota_request(const at_command_t *cmd);
/* Ch.2 / Appendix B -- cmd_oth_svc.c */
void cmd_oth_mib(const at_command_t *cmd);
void cmd_oth_setmib(const at_command_t *cmd);
void at_oth_svc_init(void);

/* Boot-time setup run from at_modem_init() (EVTDEL, SoftAP addressing). */
void at_oth_init(void);
/* Factory SoftAP SSID, "OTH_" + the last three MAC bytes. */
void at_oth_factory_ssid(char *out, size_t outsz);

#ifdef __cplusplus
}
#endif
