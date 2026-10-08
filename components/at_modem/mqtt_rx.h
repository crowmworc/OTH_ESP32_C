#pragma once

/* Reassembly of incoming MQTT messages (MQTT_RECV:IND, AWS_MSG:DONE).
 * esp-mqtt hands a message larger than its receive buffer over in several
 * MQTT_EVENT_DATA fragments, and only the first carries the topic; the
 * handlers used to pass on that first fragment alone, so a large JSON
 * reached the host cut short. One mqtt_rx_t per client collects the
 * fragments until the message is whole. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mqtt_client.h"

/* Largest message passed on to the host; a larger one is refused as a whole
 * (the handler reports it) rather than delivered in part. */
#define MQTT_RX_MAX 16384

typedef enum {
    MQTT_RX_PENDING, /* more fragments to come (or a too-large message being skipped) */
    MQTT_RX_DONE,    /* rx->topic / rx->data / rx->len hold the whole message */
    MQTT_RX_TOO_BIG, /* rx->topic / rx->total name a message over MQTT_RX_MAX (reported once) */
} mqtt_rx_result_t;

typedef struct {
    char topic[129];
    const uint8_t *data; /* valid after MQTT_RX_DONE until mqtt_rx_reset() / the next feed */
    size_t len;
    size_t total;
    uint8_t *buf;        /* heap, only while a fragmented message is collected */
    bool skipping;
} mqtt_rx_t;

mqtt_rx_result_t mqtt_rx_feed(mqtt_rx_t *rx, const esp_mqtt_event_t *ev);

/* Frees the collected message: call once a DONE message is passed on, and
 * when the client is stopped (drops a partly collected one). */
void mqtt_rx_reset(mqtt_rx_t *rx);
