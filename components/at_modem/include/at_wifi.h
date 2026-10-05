#pragma once

#include <stdbool.h>
#include "esp_netif.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the Wi-Fi driver (netif, default event loop, esp_wifi_init) and
 * register the event handler that turns WIFI_EVENT/IP_EVENT into the async
 * "*M2M*..." notifications documented in Ch.7. Leaves the radio in
 * WIFI_MODE_NULL ("0-init" per AT*M2M*WF_MODE) until a WF_MODE Set command
 * actually engages station or SoftAP -- unless a AT*M2M*WF_APMODE profile
 * was saved (type 1/2), in which case that profile is replayed automatically
 * (see cmd_wf_apmode()/apmode_activate_saved_profile() in cmd_wifi.c).
 */
void at_wifi_init(void);

/** The station/SoftAP esp-netif handles created by at_wifi_init(), for
 * commands outside cmd_wifi.c that need them (NET_DHCP/NET_DHCPS). */
esp_netif_t *at_wifi_get_sta_netif(void);
esp_netif_t *at_wifi_get_ap_netif(void);

/* Web UI (cmd_httpd.c) integration -- see cmd_wifi.c for details. Unlike
 * WF_SCAN/WF_CONN/WF_EAPCONF, these auto-enable STA mode rather than
 * erroring if it isn't already on. */
cJSON *at_wifi_web_scan(void);
bool at_wifi_web_connect_psk(const char *ssid, const char *password);
bool at_wifi_web_connect_enterprise(const char *ssid, const char *method,
                                     const char *identity, const char *anonymous_identity,
                                     const char *username, const char *password);

/* Shared by AT*M2M*WF_IPSTATUS's Set form (cmd_wifi.c) and the web UI's
 * POST /api/network (cmd_httpd.c). See cmd_wifi.c for details. */
bool at_wifi_set_station_ip(bool dhcp, const char *ip, const char *netmask, const char *gateway);

/* Marks the just-established STA connection (SSID/password already
 * persisted to flash by esp_wifi's own WIFI_STORAGE_FLASH, whoever called
 * esp_wifi_set_config()) as the AT*M2M*WF_APMODE=1 auto-reconnect profile,
 * without needing WF_APMODE's own Set-command argument parsing -- so
 * at_wifi_init() replays this connection on the next boot. Used by
 * cmd_ble_prov.c on a successful AT*M2M*BLE_PROV provisioning (doc
 * decision: BLE-provisioned connections should survive a reboot on their
 * own, unlike a host-driven WF_CONN where the host is expected to manage
 * WF_APMODE itself). */
void at_wifi_persist_apmode_sta(void);

#ifdef __cplusplus
}
#endif
