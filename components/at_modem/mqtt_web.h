#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Web UI (cmd_httpd.c) integration for the MQTT client (cmd_mqtt.c).
 * Always operates on link_id 0 -- the web UI has a single "MQTT Broker"
 * screen, unlike AT*M2M*MQTT_CONF's 4 numbered profiles. */

typedef struct {
    bool configured;
    bool connected;
    int scheme; /* 0-mqtt,1-mqtts,2-ws,3-wss */
    char host[64];
    int port;
    char client_id[65];
    char user[65];
    bool has_password;
    bool has_cert;
} mqtt_web_status_t;

/* Fills *out with link 0's current config/connection state. Always
 * succeeds (an unconfigured link just reports configured=false). */
void mqtt_web_get_status(mqtt_web_status_t *out);

/* Tears down any existing link-0 client (equivalent to MQTT_CLEAN, silent
 * if none exists), applies the new config, and starts connecting
 * (equivalent to MQTT_CONF followed by MQTT_CONN). Returns false only for
 * invalid arguments or an immediate esp-mqtt init/start failure -- actual
 * connect success/failure is asynchronous, reflected in the "connected"
 * field of a later mqtt_web_get_status() call. cert_name is optional
 * (NULL/empty for no TLS cert). */
bool mqtt_web_configure_and_connect(int scheme, const char *host, int port,
                                     const char *client_id, const char *user,
                                     const char *password, const char *cert_name);

#ifdef __cplusplus
}
#endif
