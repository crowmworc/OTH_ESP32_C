#pragma once
/* AT*M2M*BLE_PROV -- doc Ch.3.5. See cmd_ble_prov.c for the implementation. */

#ifdef __cplusplus
extern "C" {
#endif

/* One-time setup (the reusable timeout esp_timer). Does NOT touch BLE/Wi-Fi
 * hardware -- that only happens per-session, inside AT*M2M*BLE_PROV=1/0. */
void at_ble_prov_init(void);

#ifdef __cplusplus
}
#endif
