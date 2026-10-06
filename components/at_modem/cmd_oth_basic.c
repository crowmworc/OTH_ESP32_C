/* AT*OTH* Basic AT Commands (OTH-AT Essentials Ch.2). AT/ATE are shared
 * with M2M-AT (cmd_special.c). MIB/SETMIB live in cmd_oth_mib.c;
 * FWUPGRADE and UARTPROTO (Optional) are not provided. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_app_desc.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_wifi.h"

#include "at_commands.h"
#include "at_commands_oth.h"
#include "at_response.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_wifi.h"
#include "oth_platform.h"

/* AT*OTH*SWVER=? -- "<version>", Major.Minor (PROJECT_VER, e.g. 01.00). */
void cmd_oth_swver(const at_command_t *cmd)
{
    at_reply_ok(cmd->name, "%s", esp_app_get_description()->version);
}

/* AT*OTH*MAC=? -- same aa:bb:cc:dd:ee:ff reply as SYS_MAC. */
void cmd_oth_mac(const at_command_t *cmd)
{
    cmd_sys_mac(cmd);
}

/* AT*OTH*RESET=<mode> -- 0: boot from RAM, 1: boot from flash. This module
 * always boots from flash, so both restart it. */
void cmd_oth_reset(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

void at_oth_factory_ssid(char *out, size_t outsz)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, outsz, "OTH_%02X%02X%02X", mac[3], mac[4], mac[5]);
}

/* AT*OTH*FACRESET=<mode> -- 0: initialize NV items; 1: also start in SoftAP
 * mode after the next reboot (the factory SoftAP: OTH_xxxxxx, open,
 * channel 1 -- not started when the build forbids an open SoftAP). The
 * module is not restarted. */
void cmd_oth_facreset(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    oth_aws_forget(); /* AWS certificate / root CA files live outside NV memory */
    at_sys_nv_erase();
    if (cmd->argv[0][0] == '1') {
        char ssid[16];
        at_oth_factory_ssid(ssid, sizeof(ssid));
        m2m_nvs_set_u16("apm_type", 2);
        m2m_nvs_set_u16("apm_target", 1); /* APMODE_TARGET_AP */
        m2m_nvs_set_str("apm_ssid", ssid);
        m2m_nvs_set_str("apm_pw", "");
        m2m_nvs_set_u16("apm_ch", 1);
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*EVTDEL -- 0: notification messages on, 1: off. Kept in NV memory
 * and applied at boot (at_oth_init()). */
void cmd_oth_evtdel(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t opt = 0;
        m2m_nvs_get_u16("evtdel", &opt);
        at_reply_ok(cmd->name, "%u", opt);
        return;
    }
    if (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    uint16_t opt = (uint16_t)atoi(cmd->argv[0]);
    m2m_nvs_set_u16("evtdel", opt);
    at_event_set_enabled(opt == 0);
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*HWPS -- 0: automatic (modem sleep, default), 1: always off,
 * 2: always on (maximum modem sleep). Stored under SYS_LSLEEP's key in its
 * numbering (1/0/3) so at_wifi_init() reapplies it at boot. *OTH*HWPSIND
 * is not reported: the Wi-Fi driver gives no event when the radio dozes. */
void cmd_oth_hwps(const at_command_t *cmd)
{
    static const uint16_t to_lsleep[] = { 1, 0, 3 };
    if (at_is_query(cmd) || cmd->argc == 0) {
        uint16_t ls = 1;
        if (m2m_nvs_get_u16("lsleep", &ls) != ESP_OK) {
            ls = 1;
        }
        at_reply_ok(cmd->name, "%d", ls == 0 ? 1 : ls == 3 ? 2 : 0);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    if (mode < 0 || mode > 2 || cmd->argv[0][1] != '\0') {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    static const wifi_ps_type_t ps[] = { WIFI_PS_MIN_MODEM, WIFI_PS_NONE, WIFI_PS_MAX_MODEM };
    if (esp_wifi_set_ps(ps[mode]) != ESP_OK) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    m2m_nvs_set_u16("lsleep", to_lsleep[mode]);
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*ANTVER=? / SETANT=<type> -- 0: on-board chip antenna, 1: external
 * u.FL. These boards have only the on-board antenna (see SYS_ANTENNA), so
 * selecting 1 is refused. */
void cmd_oth_antver(const at_command_t *cmd)
{
    uint16_t type = 0;
    m2m_nvs_get_u16("antenna", &type);
    at_reply_ok(cmd->name, "%u", type);
}

void cmd_oth_setant(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strcmp(cmd->argv[0], "0") != 0 && strcmp(cmd->argv[0], "1") != 0)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    if (cmd->argv[0][0] == '1') {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM); /* no antenna switch on this board */
        return;
    }
    m2m_nvs_set_u16("antenna", 0);
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*TXGAIN=<value> -- lower the transmit power by value x 0.25 dB from
 * the 20 dBm maximum (esp_wifi_set_max_tx_power() takes 0.25 dBm units,
 * 8..84). Kept in NV memory and reapplied whenever the radio starts
 * (at_oth_wifi_on_start()). */
void cmd_oth_txgain(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    char *end;
    long v = strtol(cmd->argv[0], &end, 10);
    if (*end != '\0' || v < 0 || v > 76) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    m2m_nvs_set_u16("txgain", (uint16_t)v);
    esp_wifi_set_max_tx_power((int8_t)(84 - v)); /* ESP_ERR_WIFI_NOT_STARTED: applied at start */
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*COUNTRY -- any code the Wi-Fi driver knows (Appendix C's
 * 2.4 GHz channel plans; the module has no 5 GHz radio). */
void cmd_oth_country(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        char cc[4] = "";
        size_t len = sizeof(cc);
        m2m_nvs_get_str("country", cc, &len);
        if (cc[0] == '\0') {
            esp_wifi_get_country_code(cc);
            cc[2] = '\0';
        }
        at_reply_ok(cmd->name, "%s", cc);
        return;
    }
    const char *cc = cmd->argv[0];
    if (strlen(cc) != 2 || esp_wifi_set_country_code(cc, true) != ESP_OK) {
        at_reply_error(cmd->name, OTH_ERR_WIFI_CONFIG_PARAM);
        return;
    }
    m2m_nvs_set_str("country", cc);
    at_reply_ok(cmd->name, NULL);
}
