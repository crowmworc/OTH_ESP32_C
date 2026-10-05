#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "sdkconfig.h"
#include "esp_netif.h"
#include "esp_wifi_types.h"
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

/* Shared station/SoftAP building blocks (cmd_wifi.c), used by the OTH-AT
 * front end. at_wifi_ensure_sta_started() turns station mode on (keeping a
 * running SoftAP) if it is off. */
bool at_wifi_ensure_sta_started(void);
bool at_wifi_sta_join(const wifi_config_t *cfg);
bool at_wifi_sta_leave(void);
bool at_wifi_sta_is_connected(void);
bool at_wifi_start_softap(const char *ssid, uint8_t channel, wifi_auth_mode_t authmode,
                          wifi_cipher_type_t cipher, const char *password);
bool at_wifi_activate_saved_profile(void);
/* WF_EAPCERT / OTH EAPCERT <type> <value> pairs; 0 or an AT_ERR_* code. */
int  at_wifi_eapcert_apply(int argc, char *argv[]);

#if CONFIG_AT_MODEM_CMDSET_OTH
bool at_wifi_take_boot_autoconnect(void);
int  at_wifi_oth_eapset(int argc, char *argv[]);
typedef struct {
    const char *method, *identity, *ca_file, *cert_file, *key_file, *pac_file;
    bool has_password;
} at_wifi_eap_info_t;
void at_wifi_eap_info(at_wifi_eap_info_t *out);
/* Implemented in cmd_oth_wifi.c, called from cmd_wifi.c's event handler. */
void at_oth_wifi_on_start(wifi_interface_t ifx);
bool at_oth_wifi_autoconnect_enabled(void);
int  at_oth_wifi_assoc_result(uint8_t esp_reason);
#endif

#ifdef __cplusplus
}
#endif
