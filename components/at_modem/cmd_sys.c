/* AT*M2M*SYS_* -- Basic AT Commands (M2M-AT Command Set doc, Ch.2).
 * Station/SoftAP commands (WF_*) live in cmd_wifi.c. */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_app_desc.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_uart.h"
#include "at_nvs_kv.h"
#include "m2m_version.h"

/* AT*M2M*SYS_VER -- doc Ch.2: "<version> <compile time>", compile time
 * illustrated as a single space-free "YYYY-MM-DD-HH:MM:SS" token. Reformat
 * esp_app_desc_t's separate "Mon DD YYYY" / "HH:MM:SS" fields to match. */
static void format_compile_time(const esp_app_desc_t *desc, char *out, size_t outsz)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    char mon[4] = {0};
    int day = 0, year = 0;
    if (sscanf(desc->date, "%3s %d %d", mon, &day, &year) == 3) {
        int month = 0;
        for (int i = 0; i < 12; i++) {
            if (strncmp(mon, months[i], 3) == 0) {
                month = i + 1;
                break;
            }
        }
        if (month > 0) {
            snprintf(out, outsz, "%04d-%02d-%02d-%s", year, month, day, desc->time);
            return;
        }
    }
    /* Unexpected format from the toolchain -- fall back to the raw fields
     * rather than emit something misleading. */
    snprintf(out, outsz, "%s-%s", desc->date, desc->time);
}

/* Doc v2.0 (M2M_SW Release Naming Guide 2.0 section 6.3): SYS_VER now
 * reports a third field, <customer_code> (M2M_FW_CUSTOMER, e.g. "AC0",
 * m2m_version.h) -- not part of the <version> used for OTA_CHECK's
 * numeric comparison, just an on-device way to confirm which customer
 * build is actually flashed. */
void cmd_sys_ver(const at_command_t *cmd)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    char compile_time[40];
    format_compile_time(desc, compile_time, sizeof(compile_time));
    at_reply_ok(cmd->name, "%s %s %s", desc->version, compile_time, M2M_FW_CUSTOMER);
}

void cmd_sys_mac(const at_command_t *cmd)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    at_reply_ok(cmd->name, MACSTR, MAC2STR(mac));
}

/* AT*M2M*SYS_RST=<cmd> -- cmd: 0-restart. Reply before resetting so the OK
 * actually reaches the host first. */
void cmd_sys_rst(const at_command_t *cmd)
{
    if (cmd->argc < 1 || atoi(cmd->argv[0]) != 0) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

/* AT*M2M*SYS_FACTORY=<cmd> -- cmd: 0-erase NV; 1-erase NV and restart.
 * Erases the whole NVS partition (our own m2m_sys namespace, Wi-Fi
 * credentials, everything) -- that's the "factory defaults" this doc
 * describes; there's no narrower per-namespace reset defined. */
void cmd_sys_factory(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    if (mode != 0 && mode != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    at_reply_ok(cmd->name, NULL);
    vTaskDelay(pdMS_TO_TICKS(100));

    nvs_flash_erase();
    nvs_flash_init();

    if (mode == 1) {
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    }
}

/* AT*M2M*SYS_UART -- persisted baud rate, applied immediately when the AT
 * transport is a real UART (no-op under the default USB Serial/JTAG
 * transport, see at_uart_apply_baud_rate()). */
void cmd_sys_uart(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint32_t baud;
        if (m2m_nvs_get_u32("uart_baud", &baud) != ESP_OK || baud == 0) {
            baud = CONFIG_AT_MODEM_UART_BAUD_RATE;
        }
        at_reply_ok(cmd->name, "%lu", (unsigned long)baud);
        return;
    }

    long baud = atol(cmd->argv[0]);
    if (baud <= 0) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    m2m_nvs_set_u32("uart_baud", (uint32_t)baud);
    at_uart_apply_baud_rate((uint32_t)baud);
    at_reply_ok(cmd->name, "%lu", (unsigned long)baud);
}

/* AT*M2M*SYS_CONF -- Appendix A attribute store. cmd: 0-get, 1-set.
 * Index 0 (MAC) is derived, never stored. Indexes 1/33/34 are readable only
 * (not in the A.2 writable table). 3-32 are reserved. 35/36 are numeric
 * (0-65535); 37-39 are strings. */
enum {
    CONF_IDX_MAC          = 0,
    CONF_IDX_SERIAL       = 1,
    CONF_IDX_COMPANY      = 33,
    CONF_IDX_COMPANY_VER  = 34,
    CONF_IDX_DEVICE_CODE  = 35,
    CONF_IDX_DEVICE_TYPE  = 36,
    CONF_IDX_DEVICE_NAME  = 37,
    CONF_IDX_MODEL_NAME   = 38,
    CONF_IDX_MANUFACTURER = 39,
    /* Project-specific extension, added for Phase 5 (AWS IoT Fleet
     * Provisioning by Claim, cmd_aws.c): the doc gives AT*M2M*AWS_PROVISION
     * a <link_id>/<template_name>/[parameters_json] signature with nowhere
     * to configure the AWS IoT account endpoint the claim connection needs
     * to reach -- that endpoint is a fixed per-account value (same for
     * every device in a fleet), not something negotiated per-command. Doc
     * Appendix A explicitly reserves indexes 3-32 for exactly this kind of
     * addition ("Indexes not listed are reserved"), so this uses index 10
     * rather than inventing a whole new command or silently repurposing
     * MQTT_CONF. Also used by AT*M2M*AWS_CONN. */
    CONF_IDX_AWS_ENDPOINT = 10,
};

static bool conf_index_is_numeric(int index)
{
    return index == CONF_IDX_DEVICE_CODE || index == CONF_IDX_DEVICE_TYPE;
}

static bool conf_index_is_writable(int index)
{
    return index == CONF_IDX_DEVICE_CODE || index == CONF_IDX_DEVICE_TYPE ||
           index == CONF_IDX_DEVICE_NAME || index == CONF_IDX_MODEL_NAME ||
           index == CONF_IDX_MANUFACTURER || index == CONF_IDX_AWS_ENDPOINT;
}

static bool conf_index_is_readable(int index)
{
    return index == CONF_IDX_MAC || index == CONF_IDX_SERIAL ||
           index == CONF_IDX_COMPANY || index == CONF_IDX_COMPANY_VER ||
           conf_index_is_writable(index);
}

void cmd_sys_conf(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int op = atoi(cmd->argv[0]);
    int index = atoi(cmd->argv[1]);
    char key[8];
    snprintf(key, sizeof(key), "c%d", index);

    if (op == 0) {
        if (!conf_index_is_readable(index)) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        if (index == CONF_IDX_MAC) {
            uint8_t mac[6];
            esp_read_mac(mac, ESP_MAC_WIFI_STA);
            at_reply_ok(cmd->name, MACSTR, MAC2STR(mac));
        } else if (conf_index_is_numeric(index)) {
            uint16_t value = 0;
            m2m_nvs_get_u16(key, &value);
            at_reply_ok(cmd->name, "%u", value);
        } else {
            char value[65] = "";
            size_t len = sizeof(value);
            m2m_nvs_get_str(key, value, &len);
            at_reply_ok(cmd->name, "%s", value);
        }
        return;
    }

    if (op == 1) {
        if (!conf_index_is_writable(index) || cmd->argc < 3) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        if (conf_index_is_numeric(index)) {
            long value = atol(cmd->argv[2]);
            if (value < 0 || value > 65535) {
                at_reply_error(cmd->name, AT_ERR_ARG);
                return;
            }
            m2m_nvs_set_u16(key, (uint16_t)value);
        } else {
            m2m_nvs_set_str(key, cmd->argv[2]);
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }

    at_reply_error(cmd->name, AT_ERR_ARG);
}

/* AT*M2M*SYS_COUNTRY -- Appendix B regulatory domain. Delegates the actual
 * 2.4/5GHz channel-plan enforcement to esp_wifi_set_country_code(), which
 * already implements the "simple" per-country channel plans (built into
 * the Wi-Fi driver) matching Appendix B's table -- no need to hand-roll the
 * channel ranges ourselves. */
static const char *const k_country_codes[] = {
    "AU", "CA", "CN", "EU", "GB", "IN", "JP", "KR", "NZ", "SG", "TW", "US",
};
#define COUNTRY_CODE_COUNT (sizeof(k_country_codes) / sizeof(k_country_codes[0]))

static bool is_valid_country_code(const char *cc)
{
    for (size_t i = 0; i < COUNTRY_CODE_COUNT; i++) {
        if (strcasecmp(cc, k_country_codes[i]) == 0) {
            return true;
        }
    }
    return false;
}

void cmd_sys_country(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        char cc[4] = "";
        size_t len = sizeof(cc);
        m2m_nvs_get_str("country", cc, &len);
        if (cc[0] == '\0') {
            strcpy(cc, "US"); /* no factory default specified by the doc */
        }
        at_reply_ok(cmd->name, "%s", cc);
        return;
    }

    const char *cc = cmd->argv[0];
    if (!is_valid_country_code(cc)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    m2m_nvs_set_str("country", cc);
    esp_wifi_set_country_code(cc, true);
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*SYS_LSLEEP -- power-save policy, doc Ch.2.
 * mode: 0-disabled; 1-modem sleep (DTIM-based); 2-light sleep;
 * 3-modem sleep (listen-interval). Modes 0/1/3 are real Wi-Fi radio power
 * saving via esp_wifi_set_ps() (WIFI_PS_NONE/MIN_MODEM/MAX_MODEM -- the
 * enum's own values already match the doc's numbering for these three).
 * Mode 2 (system-wide automatic light sleep, esp_pm_configure() with
 * light_sleep_enable) needs CONFIG_PM_ENABLE, which this project's
 * sdkconfig has off -- turning it on is a separate, riskier change than
 * this command itself (the primary AT/console channel runs over native USB
 * Serial/JTAG, whose behavior across light sleep needs its own hardware
 * verification before relying on it), so mode=2 replies the doc's own
 * "reason: 0-not supported" instead of silently no-op'ing or guessing.
 * Applied at boot from the persisted value in at_wifi_init() -> right after
 * esp_wifi_init(), same pattern as SYS_COUNTRY. */
void cmd_sys_lsleep(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t mode = 0;
        m2m_nvs_get_u16("lsleep", &mode);
        at_reply_ok(cmd->name, "%u", mode);
        return;
    }

    int mode = atoi(cmd->argv[0]);
    wifi_ps_type_t ps;
    switch (mode) {
        case 0: ps = WIFI_PS_NONE; break;
        case 1: ps = WIFI_PS_MIN_MODEM; break;
        case 3: ps = WIFI_PS_MAX_MODEM; break;
        case 2:
            at_reply_error(cmd->name, 0); /* doc: "reason: 0-not supported" (CONFIG_PM_ENABLE off) */
            return;
        default:
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
    }

    if (esp_wifi_set_ps(ps) != ESP_OK) {
        at_reply_error(cmd->name, 0); /* doc: "reason: 0-not supported" */
        return;
    }
    m2m_nvs_set_u16("lsleep", (uint16_t)mode);
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*SYS_ANTENNA -- type: 0-on-board chip antenna; 1-external antenna.
 * This project's ESP32-C3 boards wire a single onboard PCB antenna with no
 * RF switch to an external-antenna connector (see README board notes) --
 * there is no physical hardware for this command to actually switch
 * between. type=0 is already what's wired, so it succeeds and is persisted
 * like any other config value; type=1 replies the doc's own "reason:
 * 0-not supported" rather than silently pretending an external-antenna
 * path exists. Revisit if this project ever targets a board with a real
 * antenna-diversity switch (esp_phy_set_ant_gpio()/esp_phy_set_ant()). */
void cmd_sys_antenna(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t type = 0;
        m2m_nvs_get_u16("antenna", &type);
        at_reply_ok(cmd->name, "%u", type);
        return;
    }

    int type = atoi(cmd->argv[0]);
    if (type != 0 && type != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (type == 1) {
        at_reply_error(cmd->name, 0); /* doc: "reason: 0-not supported" -- no antenna switch on this board */
        return;
    }
    m2m_nvs_set_u16("antenna", (uint16_t)type);
    at_reply_ok(cmd->name, "%u", type);
}
