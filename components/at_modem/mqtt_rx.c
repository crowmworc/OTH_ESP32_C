#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

#include "mqtt_rx.h"

static const char *TAG = "mqtt_rx";

void mqtt_rx_reset(mqtt_rx_t *rx)
{
    free(rx->buf);
    rx->buf = NULL;
    rx->data = NULL;
    rx->len = 0;
    rx->total = 0;
    rx->skipping = false;
}

mqtt_rx_result_t mqtt_rx_feed(mqtt_rx_t *rx, const esp_mqtt_event_t *ev)
{
    if (ev->data_len < 0 || ev->total_data_len < 0) {
        return MQTT_RX_PENDING;
    }
    size_t total = (size_t)ev->total_data_len;
    size_t off = ev->current_data_offset > 0 ? (size_t)ev->current_data_offset : 0;
    size_t dlen = (size_t)ev->data_len;

    if (off == 0) {
        /* first fragment: a new message (drops any unfinished one) */
        mqtt_rx_reset(rx);
        size_t tlen = ev->topic_len > 0 ? (size_t)ev->topic_len : 0;
        if (tlen > sizeof(rx->topic) - 1) {
            tlen = sizeof(rx->topic) - 1;
        }
        memcpy(rx->topic, ev->topic, tlen);
        rx->topic[tlen] = '\0';
        rx->total = total;
        if (total > MQTT_RX_MAX) {
            ESP_LOGW(TAG, "message on \"%s\" is %u bytes, over %d: not passed on", rx->topic,
                     (unsigned)total, MQTT_RX_MAX);
            rx->skipping = dlen < total; /* skip its remaining fragments */
            return MQTT_RX_TOO_BIG;
        }
        if (dlen >= total) {
            /* whole message in one fragment: hand out esp-mqtt's own buffer */
            rx->data = (const uint8_t *)ev->data;
            rx->len = total;
            return MQTT_RX_DONE;
        }
        rx->buf = malloc(total);
        if (!rx->buf) {
            ESP_LOGW(TAG, "no memory for a %u-byte message on \"%s\"", (unsigned)total, rx->topic);
            rx->skipping = true;
            return MQTT_RX_TOO_BIG;
        }
    } else if (rx->skipping || !rx->buf || total != rx->total) {
        if (off + dlen >= total) {
            rx->skipping = false;
        }
        return MQTT_RX_PENDING; /* the rest of a skipped message, or a stray fragment */
    }

    if (off + dlen > rx->total) {
        dlen = rx->total - off;
    }
    memcpy(rx->buf + off, ev->data, dlen);
    rx->len = off + dlen;
    if (rx->len < rx->total) {
        return MQTT_RX_PENDING;
    }
    rx->data = rx->buf; /* freed by mqtt_rx_reset() */
    return MQTT_RX_DONE;
}
