/* AT*OTH*FWUPGRADE=<bank> -- firmware download over the AT UART with
 * XMODEM (OTH-AT Essentials Ch.2). After the OK the module asks for the
 * image in XMODEM-CRC mode ('C' every 3 s, for up to 60 s), takes 128-byte
 * (SOH) and 1K (STX) blocks, and writes them into the selected flash bank:
 * bank 1 = ota_0, bank 2 = ota_1 (the bank the module is running from is
 * refused). On EOT the image is checked (esp_ota_end()) and, if valid,
 * made the boot image and the module restarts into it (*OTH*DEVICEREADY
 * follows). A failure -- bad image, CAN from the sender, or 10 s without
 * data -- returns to command mode with *OTH*FWUPGRADE:ERROR <code>
 * (1: aborted / timed out, 2: image rejected), a line the guide does not
 * define but a host needs in order to tell the outcome.
 *
 * Like OTA_REQUEST, nothing beyond the ESP-IDF image check verifies the
 * image's origin while Secure Boot is off (EN 18031-1 open item B-01). */

#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "at_commands_oth.h"
#include "at_response.h"
#include "at_event.h"
#include "at_uart.h"

static const char *TAG = "oth_fwup";

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18

#define START_TRIES     20                      /* x 3 s of 'C' */
#define IDLE_TIMEOUT_US (10LL * 1000 * 1000)

static esp_ota_handle_t s_ota;
static const esp_partition_t *s_part;
static esp_timer_handle_t s_timer;
static uint8_t *s_pkt;          /* 3 header + 1024 data + 2 CRC */
static size_t s_pkt_len, s_pkt_need;
static uint8_t s_expect_blk;
static int s_start_tries;
static bool s_started;          /* first block seen */
static volatile int64_t s_last_rx_us;
static volatile bool s_active;

static uint16_t crc16(const uint8_t *d, size_t n)
{
    uint16_t crc = 0;
    while (n--) {
        crc ^= (uint16_t)(*d++) << 8;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static void put(uint8_t b)
{
    at_uart_write((const char *)&b, 1);
}

static void finish(int err)
{
    s_active = false;
    esp_timer_stop(s_timer);
    at_uart_set_raw_sink(NULL);
    free(s_pkt);
    s_pkt = NULL;
    if (err) {
        esp_ota_abort(s_ota);
        at_event_post("FWUPGRADE:ERROR %d", err);
        return;
    }
    if (esp_ota_end(s_ota) != ESP_OK || esp_ota_set_boot_partition(s_part) != ESP_OK) {
        at_event_post("FWUPGRADE:ERROR %d", 2);
        return;
    }
    ESP_LOGI(TAG, "image written to %s, restarting", s_part->label);
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_restart();
}

/* Runs on the UART receive task, one byte at a time. */
static void xmodem_sink(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len && s_active; i++) {
        uint8_t b = data[i];
        s_last_rx_us = esp_timer_get_time();
        if (s_pkt_len == 0) {
            if (b == EOT) {
                put(ACK);
                finish(s_started ? 0 : 1);
                return;
            }
            if (b == CAN) {
                finish(1);
                return;
            }
            if (b != SOH && b != STX) {
                continue; /* line noise between blocks */
            }
            s_pkt_need = 3 + (b == STX ? 1024 : 128) + 2;
        }
        s_pkt[s_pkt_len++] = b;
        if (s_pkt_len < s_pkt_need) {
            continue;
        }
        size_t dlen = s_pkt_need - 5;
        s_pkt_len = 0;
        uint16_t got = (uint16_t)(s_pkt[3 + dlen] << 8 | s_pkt[4 + dlen]);
        if ((uint8_t)(s_pkt[1] + s_pkt[2]) != 0xFF || crc16(s_pkt + 3, dlen) != got) {
            put(NAK);
            continue;
        }
        if (s_pkt[1] == (uint8_t)(s_expect_blk - 1) && s_started) {
            put(ACK); /* our ACK was lost: the sender repeated the block */
            continue;
        }
        if (s_pkt[1] != s_expect_blk) {
            put(CAN);
            put(CAN);
            finish(1);
            return;
        }
        if (esp_ota_write(s_ota, s_pkt + 3, dlen) != ESP_OK) {
            put(CAN);
            put(CAN);
            finish(2);
            return;
        }
        s_started = true;
        s_expect_blk++;
        put(ACK);
    }
}

/* 1 s tick: 'C' until the sender starts, then the idle watchdog. */
static void tick_cb(void *arg)
{
    (void)arg;
    if (!s_active) {
        return;
    }
    int64_t idle = esp_timer_get_time() - s_last_rx_us;
    if (!s_started) {
        if (idle >= 3000000) {
            if (++s_start_tries > START_TRIES) {
                finish(1);
                return;
            }
            s_last_rx_us = esp_timer_get_time();
            put('C');
        }
    } else if (idle > IDLE_TIMEOUT_US) {
        finish(1);
    }
}

void cmd_oth_fwupgrade(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strcmp(cmd->argv[0], "1") != 0 && strcmp(cmd->argv[0], "2") != 0)) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    if (s_active) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    esp_partition_subtype_t sub = cmd->argv[0][0] == '1' ? ESP_PARTITION_SUBTYPE_APP_OTA_0
                                                         : ESP_PARTITION_SUBTYPE_APP_OTA_1;
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_APP, sub, NULL);
    if (!s_part || s_part == esp_ota_get_running_partition()) {
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM); /* no such bank, or the running one */
        return;
    }
    s_pkt = malloc(3 + 1024 + 2);
    if (!s_pkt) {
        at_reply_error(cmd->name, OTH_ERR_OUT_OF_MEMORY);
        return;
    }
    /* sequential: sectors are erased as the image arrives, not up front */
    if (esp_ota_begin(s_part, OTA_WITH_SEQUENTIAL_WRITES, &s_ota) != ESP_OK) {
        free(s_pkt);
        s_pkt = NULL;
        at_reply_error(cmd->name, OTH_ERR_GENERAL_PARAM);
        return;
    }
    if (!s_timer) {
        const esp_timer_create_args_t a = {.callback = tick_cb, .name = "oth_fwup"};
        esp_timer_create(&a, &s_timer);
    }
    s_pkt_len = 0;
    s_expect_blk = 1;
    s_start_tries = 0;
    s_started = false;
    s_active = true;
    at_reply_ok(cmd->name, NULL);
    s_last_rx_us = esp_timer_get_time();
    at_uart_set_raw_sink(xmodem_sink);
    put('C');
    esp_timer_start_periodic(s_timer, 1000 * 1000);
}
