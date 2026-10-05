#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the M2M AT-command modem: UART transport, event task, and the
 * command dispatch table. Call once from app_main().
 *
 * Phase 0: UART transport + event queue only (AT/ATE/ATV). Later phases
 * add socket/Wi-Fi/MQTT/etc. bring-up here as those subsystems land, per
 * C:\Users\crowm\.claude\plans\tingly-gathering-parasol.md.
 */
void at_modem_init(void);

#ifdef __cplusplus
}
#endif
