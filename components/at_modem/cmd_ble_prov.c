/* AT*M2M*BLE_PROV -- BLE (Espressif Unified/BLE Provisioning-compatible)
 * Wi-Fi credential delivery (doc Ch.3.5, M2M-AT Command Set Rev 1.5/1.6/1.7),
 * on wifi_provisioning + protocomm's wifi_prov_scheme_ble.
 *
 * See doc/M2M BT Provisioning Architecture Review.docx for the design
 * rationale (why this exists as a separate interface from the AT command
 * set, why it's a thin wrapper around Espressif's own framework rather
 * than a custom protocol, and why it only reports the Wi-Fi join outcome
 * -- not any downstream MQTT/AWS result, which goes through the existing
 * AT*M2M*MQTT_CONN/AWS_CONN notifications instead, section 5.2).
 *
 * KNOWN LIMITATION (doc Rev 1.7, section 5.3): only one BLE_PROV session
 * (state=1) is supported per boot. Once a session has been closed --
 * BLE_PROV=0, a timeout (ERROR 1), or a start failure (ERROR 0) -- a
 * further BLE_PROV=1 in the same boot fails cleanly with ERROR 0 rather
 * than opening a new window; AT*M2M*SYS_RST is required first. Root cause:
 * wifi_prov_mgr's own NimBLE start routine (simple_ble_start(), in
 * protocomm_nimble.c) always calls nimble_port_init() unconditionally, with
 * no path to resume an already-running controller/host -- so this file must
 * choose between two failure modes for a second session and picks the safe
 * one:
 *   - fully deinit the controller on stop (this file's original design) --
 *     the *next* wifi_prov_mgr_init()+start_provisioning() call then
 *     crashes hardware-verified: a NULL function-pointer call inside
 *     Espressif's closed-source BLE controller blob (r_lld_env_init),
 *     since the controller cannot be safely reinitialized once fully torn
 *     down within the same boot; or
 *   - keep the controller/NimBLE host alive across stop (via
 *     wifi_prov_mgr_keep_ble_on(1) + CONFIG_WIFI_PROV_KEEP_BLE_ON_AFTER_PROV/
 *     CONFIG_WIFI_PROV_DISCONNECT_AFTER_PROV, what this file actually does)
 *     -- BLE_PROV=0 still stops advertising and disconnects any peer
 *     (doc's "provisioning window closed" contract holds), but the next
 *     simple_ble_start() then fails cleanly at esp_bt_controller_init()
 *     ("controller init failed", ESP_ERR_INVALID_STATE) since the
 *     controller is already up.
 * Supporting a real second in-boot session would mean bypassing
 * wifi_prov_mgr's BLE scheme entirely and driving protocomm/NimBLE
 * directly (register/unregister the GATT service on the already-running
 * host) -- out of scope for now; tracked as an open item in the companion
 * Architecture Review document rather than attempted here.
 *
 * Notification mapping (wifi_provisioning's own wifi_prov_cb_event_t ->
 * this doc's IND/DONE/ERROR):
 *   WIFI_PROV_START        -> IND CONNECTED   (see caveat below)
 *   WIFI_PROV_CRED_RECV    -> IND CRED_RECEIVED
 *   WIFI_PROV_CRED_FAIL    -> IND CRED_FAIL   (session stays open -- the
 *                              phone can resend credentials; this is
 *                              wifi_prov_mgr's own default behavior, not
 *                              something this file has to arrange)
 *   WIFI_PROV_CRED_SUCCESS -> DONE (+ at_wifi_persist_apmode_sta())
 *   (this file's own timer) -> ERROR 1, only for a timeout with nobody
 *                              completing provisioning (but see
 *                              timeout_cb()'s grace-period note: not fired
 *                              immediately if the STA already associated to
 *                              the AP and is just waiting on DHCP)
 *   WIFI_PROV_END          -> internal cleanup only, no AT notification
 *                              (already covered by DONE/ERROR/a plain
 *                              host-initiated BLE_PROV=0's own OK) -- but
 *                              NOT handled in prov_event_handler() below;
 *                              see wifi_prov_end_handler()'s own comment for
 *                              why that would self-deadlock.
 *
 * Caveat on IND CONNECTED: wifi_prov_mgr's public event set has no "a BLE
 * central actually connected" event of its own -- only WIFI_PROV_START
 * (the GATT server/advertising came up) is available at this level. Getting
 * true per-connection granularity would mean hooking the NimBLE/Bluedroid
 * GAP callback directly, underneath wifi_prov_scheme_ble, which owns that
 * stack while provisioning is active. Approximated here as "the window
 * became active" rather than "a phone attached" -- acceptable for now
 * since CRED_RECEIVED still gives a real signal that a phone did something,
 * but worth revisiting if the host needs to distinguish "nobody has shown
 * up yet" from "someone's there but hasn't sent credentials".
 *
 * Security note: WIFI_PROV_SECURITY_1's proof-of-possession (PoP) is a
 * per-device secret since 2026-09-27 (EN 18031-1 AUM-5-1/CCK-3). It used to
 * be the fixed "esp32c3pop" every Espressif example ships, i.e. the same
 * string compiled into every unit. Now at_ble_prov_init() generates 12
 * characters from the hardware RNG on first boot (~60 bits, from an
 * unambiguous 31-symbol alphabet so it can be printed on a label/QR code and
 * typed back) and keeps it in NVS; it is never derived from the MAC or any
 * other device property. AT*M2M*BLE_POP reads it (for the host to show or
 * print) or replaces it with a manufacturer-provisioned value. SYS_FACTORY's
 * NVS erase makes the next boot generate a fresh one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_wifi.h"

#include "wifi_provisioning/manager.h"
#include "wifi_provisioning/scheme_ble.h"

#include "at_ble_prov.h"
#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "at_wifi.h"

#include "esp_random.h"
#include "at_nvs_kv.h"

#define BLE_POP_KEY     "ble_pop"
#define BLE_POP_GEN_LEN 12
#define BLE_POP_MIN_LEN 8
#define BLE_POP_MAX_LEN 32
/* No 0/O/1/I/L: easy to read off a label and type into the phone app. */
static const char BLE_POP_ALPHABET[] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

static char s_pop[BLE_POP_MAX_LEN + 1];

/* Extra time timeout_cb() grants, once, if the host's chosen timeout_s
 * expires right as the STA finishes associating to the AP -- hardware-
 * verified (see doc/M2M BT Provisioning Architecture Review.docx) that a
 * slow BLE central can burn nearly all of timeout_s just on the security
 * handshake before ever sending credentials, and association+DHCP together
 * then only need a few more seconds. Tearing the session down at that exact
 * moment would throw away a provisioning attempt that was about to succeed. */
#define BLE_PROV_TIMEOUT_GRACE_US (10 * 1000000ULL)

static bool s_active;
static bool s_cred_success;
static bool s_timeout_grace_used;
static uint32_t s_timeout_s;
static int64_t s_start_us;
static esp_timer_handle_t s_timeout_timer;

static void cleanup(void)
{
    if (s_timeout_timer) {
        esp_timer_stop(s_timeout_timer); /* no-op (ESP_ERR_INVALID_STATE, ignored) if not running */
    }
    s_active = false;
    s_cred_success = false;
    s_timeout_grace_used = false;
    s_timeout_s = 0;
}

static void prov_event_handler(void *user_data, wifi_prov_cb_event_t event, void *event_data)
{
    (void)user_data;
    (void)event_data;

    switch (event) {
    case WIFI_PROV_START:
        at_event_post("BLE_PROV:IND CONNECTED");
        break;
    case WIFI_PROV_CRED_RECV:
        at_event_post("BLE_PROV:IND CRED_RECEIVED");
        break;
    case WIFI_PROV_CRED_FAIL:
        at_event_post("BLE_PROV:IND CRED_FAIL");
        break;
    case WIFI_PROV_CRED_SUCCESS:
        s_cred_success = true;
        at_wifi_persist_apmode_sta();
        at_event_post("BLE_PROV:DONE");
        break;
    /* WIFI_PROV_END is deliberately NOT handled here -- see
     * wifi_prov_end_handler() below. */
    default:
        break;
    }
}

/* Handles WIFI_PROV_END via the *system* WIFI_PROV_EVENT loop instead of
 * wifi_prov_mgr_config_t's own app_event_handler (prov_event_handler()
 * above) -- this is deliberate, not an oversight.
 *
 * wifi_prov_mgr's internal manager.c calls prov_event_handler() for
 * WIFI_PROV_END synchronously, in-line, from prov_stop_and_notify(), which
 * itself runs from wifi_prov_mgr_event_handler_internal() while that
 * function is still holding prov_ctx_lock (acquired at its top, released
 * only after prov_stop_and_notify() returns). wifi_prov_mgr_deinit()'s very
 * first line is ACQUIRE_LOCK(prov_ctx_lock) on that same (non-recursive)
 * lock -- calling it from inside prov_event_handler() self-deadlocks the
 * calling task forever. Hardware-verified: with deinit called from there,
 * it never returned even 44+ seconds later, and AT*M2M*BLE_PROV=? kept
 * reporting the session as still active indefinitely.
 *
 * esp_event_post(WIFI_PROV_EVENT, WIFI_PROV_END, ...) (also called from
 * prov_stop_and_notify(), right after the direct app_cb call) only queues
 * the event -- a handler registered for it here runs later, once the
 * default event loop's task has returned from and released whatever posted
 * it, so calling wifi_prov_mgr_deinit() from here is safe. This matches
 * Espressif's own wifi_prov_mgr example, which listens for WIFI_PROV_END on
 * this same system event loop rather than the manager's direct callback. */
static void wifi_prov_end_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)id;
    (void)data;
    wifi_prov_mgr_deinit();
    cleanup();
}

static void timeout_cb(void *arg)
{
    (void)arg;
    if (!s_active || s_cred_success) {
        return; /* already finished/closed by the time this fired */
    }

    wifi_ap_record_t ap_info;
    if (!s_timeout_grace_used && esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        /* Already associated, just waiting on DHCP (WIFI_PROV_CRED_SUCCESS
         * needs IP_EVENT_STA_GOT_IP, not just association) -- give it one
         * short grace period instead of yanking the session out from under
         * a connection this close to finishing. Granted at most once per
         * session: if DHCP is genuinely stuck (e.g. no DHCP server on the
         * AP), still give up rather than wait forever. */
        s_timeout_grace_used = true;
        esp_timer_start_once(s_timeout_timer, BLE_PROV_TIMEOUT_GRACE_US);
        return;
    }

    at_event_post("BLE_PROV:ERROR 1"); /* doc: 1-window timed out without a phone completing provisioning */
    wifi_prov_mgr_stop_provisioning(); /* -> WIFI_PROV_END -> wifi_prov_end_handler() -> cleanup() */
}

static void pop_generate(char *out, size_t len)
{
    const size_t n = sizeof(BLE_POP_ALPHABET) - 1; /* 31 symbols */
    for (size_t i = 0; i < len; i++) {
        uint32_t r;
        do {
            r = esp_random() & 0xFF;
        } while (r >= 256 - (256 % n)); /* rejection sampling: no modulo bias */
        out[i] = BLE_POP_ALPHABET[r % n];
    }
    out[len] = '\0';
}

static bool pop_valid(const char *pop)
{
    size_t l = strlen(pop);
    if (l < BLE_POP_MIN_LEN || l > BLE_POP_MAX_LEN) {
        return false;
    }
    for (size_t i = 0; i < l; i++) {
        if (pop[i] <= 0x20 || pop[i] >= 0x7f) {
            return false;
        }
    }
    return true;
}

void at_ble_prov_init(void)
{
    size_t len = sizeof(s_pop);
    m2m_nvs_get_str(BLE_POP_KEY, s_pop, &len);
    if (!pop_valid(s_pop)) {
        pop_generate(s_pop, BLE_POP_GEN_LEN);
        m2m_nvs_set_str(BLE_POP_KEY, s_pop);
    }

    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name = "ble_prov_to",
    };
    ESP_ERROR_CHECK(esp_timer_create(&args, &s_timeout_timer));
    /* Registered once at boot, not per-session -- see wifi_prov_end_handler()'s
     * own comment for why WIFI_PROV_END is handled here rather than via
     * wifi_prov_mgr_config_t's app_event_handler. */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_PROV_EVENT, WIFI_PROV_END,
                                                          &wifi_prov_end_handler, NULL, NULL));
}

/* AT*M2M*BLE_PROV -- Query: <state> [remaining_s]. Set: <state> [timeout_s]. */
void cmd_ble_prov(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        if (!s_active) {
            at_reply_ok(cmd->name, "0");
            return;
        }
        if (s_timeout_s == 0) {
            at_reply_ok(cmd->name, "1");
            return;
        }
        int64_t elapsed_s = (esp_timer_get_time() - s_start_us) / 1000000;
        uint32_t remaining = (elapsed_s < s_timeout_s) ? (uint32_t)(s_timeout_s - elapsed_s) : 0;
        at_reply_ok(cmd->name, "1 %lu", (unsigned long)remaining);
        return;
    }

    int state = atoi(cmd->argv[0]);
    if (state != 0 && state != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    if (state == 0) {
        if (s_active) {
            /* -> WIFI_PROV_END -> wifi_prov_end_handler() -> cleanup(); no
             * ERROR/DONE notification for a host-requested close. */
            wifi_prov_mgr_stop_provisioning();
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }

    /* state == 1 */
    if (s_active) {
        at_reply_error(cmd->name, AT_ERR_STATE); /* doc has no specific reason for "already open" -- generic bucket */
        return;
    }
    long timeout_s = 0;
    if (cmd->argc >= 2) {
        timeout_s = atol(cmd->argv[1]);
        if (timeout_s < 0) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
    }

    /* No scheme_event_handler here (was WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM
     * -- see wifi_prov_mgr_keep_ble_on() below for why that had to go). */
    wifi_prov_mgr_config_t config = {
        .scheme = wifi_prov_scheme_ble,
        .app_event_handler = {.event_cb = prov_event_handler, .user_data = NULL},
    };
    if (wifi_prov_mgr_init(config) != ESP_OK) {
        at_reply_error(cmd->name, 0); /* doc: 0-not supported */
        return;
    }

    /* Hardware-verified: the ESP32-C3 BLE controller cannot be safely
     * deinit'd and then reinit'd again within the same boot -- a second
     * wifi_prov_mgr_init()+start_provisioning() after a prior session's
     * WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM had torn the controller
     * down crashed every time (NULL function-pointer call inside
     * Espressif's closed-source controller blob, r_lld_env_init -- not
     * something fixable from this file). Telling wifi_prov_mgr to leave the
     * BLE/NimBLE stack running across stop/start cycles (only the GATT
     * session and this file's own manager bookkeeping get torn down and
     * rebuilt each time) avoids that reinit path entirely. Must be called
     * before wifi_prov_mgr_start_provisioning() each time -- the manager
     * doesn't remember it across its own init/deinit cycle. */
    wifi_prov_mgr_keep_ble_on(1);

    char service_name[16];
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(service_name, sizeof(service_name), "PROV_%02X%02X%02X", mac[3], mac[4], mac[5]);

    if (wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_1, s_pop, service_name, NULL) != ESP_OK) {
        wifi_prov_mgr_deinit();
        at_reply_error(cmd->name, 0);
        return;
    }

    s_active = true;
    s_cred_success = false;
    s_timeout_s = (uint32_t)timeout_s;
    s_start_us = esp_timer_get_time();
    if (timeout_s > 0) {
        esp_timer_start_once(s_timeout_timer, (uint64_t)timeout_s * 1000000ULL);
    }

    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*BLE_POP -- Query/Set the BLE provisioning proof-of-possession
 * (see the security note at the top of this file).
 *   AT*M2M*BLE_POP=?      -> *M2M*BLE_POP:OK <pop>
 *   AT*M2M*BLE_POP=<pop>  -> 8..32 printable ASCII characters, no spaces
 * reason: 1-invalid format; 2-provisioning window open (close it first). */
void cmd_ble_pop(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        at_reply_ok(cmd->name, "%s", s_pop);
        return;
    }
    if (!pop_valid(cmd->argv[0])) {
        at_reply_error(cmd->name, 1);
        return;
    }
    if (s_active) {
        at_reply_error(cmd->name, 2);
        return;
    }
    strlcpy(s_pop, cmd->argv[0], sizeof(s_pop));
    m2m_nvs_set_str(BLE_POP_KEY, s_pop);
    at_reply_ok(cmd->name, NULL);
}
