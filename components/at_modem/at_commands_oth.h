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

/* Boot-time setup run from at_modem_init() (EVTDEL, SoftAP addressing). */
void at_oth_init(void);
/* Factory SoftAP SSID, "OTH_" + the last three MAC bytes. */
void at_oth_factory_ssid(char *out, size_t outsz);

#ifdef __cplusplus
}
#endif
