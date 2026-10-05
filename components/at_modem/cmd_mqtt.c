/* AT*M2M*MQTT_CONF/ALPN/CONN/PUB/SUB/CLEAN -- MQTT client (doc Ch.6.4), on
 * esp-mqtt (esp_mqtt_client). Unlike net_link.c's raw sockets, esp-mqtt
 * already owns its own background task, reconnect logic, and (for
 * mqtts/wss) TLS session, so this file just tracks the doc's 4
 * configuration profiles (link_id 0-3, doc: "shared with the MQTT client
 * commands" -- a separate namespace from net_link.c's socket links, not
 * the same physical resource) and maps esp-mqtt's events onto the Ch.7
 * notifications.
 *
 * Doc quirk handled specially: AT*M2M*MQTT_PUB's <data> example
 * ("{""power"":""on""}") escapes an embedded quote by *doubling* it, a
 * different convention from every other command's parser (at_parser.c's
 * tokenizer has no escape handling at all) -- MQTT_PUB is registered
 * `raw` and hand-parsed here instead of using the generic tokenizer.
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_crt_bundle.h"
#include "mqtt_client.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "at_uart.h"
#include "fs_store.h"
#include "mqtt_web.h"
#include "sdkconfig.h"

#define MQTT_MAX_LINKS 4
#define MQTT_MAX_SUBS  10

typedef struct {
    bool used;
    char topic[128];
    int qos;
} mqtt_sub_t;

typedef struct {
    bool configured;
    int scheme; /* 0-mqtt,1-mqtts,2-ws,3-wss */
    char host[64];
    int port;
    char path[64];
    char client_id[65];
    char user[65];
    char password[65];
    char cert_name[32];
    int alpn_count;
    char alpn[5][32];
    const char *alpn_ptrs[6];

    esp_mqtt_client_handle_t client;
    atomic_bool clean_requested; /* set right before esp_mqtt_client_stop() by
                                   * MQTT_CLEAN, so the event handler can tell
                                   * a host-requested clean apart from an
                                   * unsolicited loss (only the latter gets
                                   * MQTT_DISCONN:IND, mirroring WF_DISCONN). */
    atomic_bool connected; /* mirrors MQTT_EVENT_CONNECTED/DISCONNECTED/ERROR,
                             * for mqtt_web_get_status() (cmd_httpd.c) -- the
                             * AT command side already gets this via the
                             * MQTT_CONN:IND/DONE notifications instead. */
    mqtt_sub_t subs[MQTT_MAX_SUBS];
    char *cert_pem; /* heap-owned, sized to the actual loaded cert_name file --
                      * esp-mqtt keeps this raw pointer in its client config
                      * and re-reads it on every reconnect (it does not copy
                      * the string), so it must stay valid for the client's
                      * whole lifetime; freed alongside the client (clean/
                      * reconnect teardown below), not right after connect.
                      * Per-link (not a single shared scratch buffer) because
                      * up to MQTT_MAX_LINKS clients can be live at once with
                      * different certs -- a shared buffer would let a second
                      * link's connect silently corrupt a first link's
                      * already-live TLS identity on its next reconnect. */
} mqtt_link_t;

static mqtt_link_t s_links[MQTT_MAX_LINKS];

/* Loads cert_name into a fresh heap buffer sized to its actual content (a
 * combined CA+client-cert+key bundle may be several KB; a lone cert or key
 * is usually well under 1KB) -- caller owns the result and must free() it
 * once the client that was handed the pointer is torn down. */
static char *load_cert_alloc(const char *cert_name)
{
    if (!cert_name || !cert_name[0]) {
        return NULL;
    }
    return fs_store_read_alloc(cert_name, NULL);
}

/* EN 18031-1 GEC-6: shared by MQTT_CONF and the web MQTT form -- rejects
 * values the link fields would otherwise silently truncate, an out-of-range
 * port and an unusable cert_name, instead of connecting with mangled
 * settings. NULL optional fields count as empty. */
static bool field_fits(const char *v, size_t cap, bool required)
{
    size_t len = v ? strlen(v) : 0;
    return len < cap && (!required || len > 0);
}

static bool fields_valid(const char *host, int port, const char *path, const char *client_id,
                         const char *user, const char *password, const char *cert_name)
{
    mqtt_link_t *l = &s_links[0];
    return field_fits(host, sizeof(l->host), true) && port > 0 && port <= 65535 &&
           field_fits(path, sizeof(l->path), false) && field_fits(client_id, sizeof(l->client_id), true) &&
           field_fits(user, sizeof(l->user), false) && field_fits(password, sizeof(l->password), false) &&
           (!cert_name || !cert_name[0] || fs_store_name_valid(cert_name));
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    (void)base;
    int link_id = (int)(intptr_t)handler_args;
    mqtt_link_t *l = &s_links[link_id];
    esp_mqtt_event_handle_t event = event_data;

    switch (event_id) {
    case MQTT_EVENT_CONNECTED:
        atomic_store(&l->connected, true);
        at_event_post("MQTT_CONN:IND %d %d %s %d %s %d", link_id, l->scheme, l->host, l->port,
                      l->path[0] ? l->path : "", 1);
        at_event_post("MQTT_CONN:DONE");
        break;

    case MQTT_EVENT_DISCONNECTED:
        atomic_store(&l->connected, false);
        if (!atomic_exchange(&l->clean_requested, false)) {
            at_event_post("MQTT_DISCONN:IND %d", link_id);
        }
        break;

    case MQTT_EVENT_ERROR: {
        atomic_store(&l->connected, false);
        /* doc reason codes: 2-could not reach the broker, 3-TLS handshake
         * failed, 4-broker rejected the connection (bad credentials) --
         * esp-mqtt's error_handle distinguishes exactly these three cases. */
        int reason = 2;
        if (event->error_handle) {
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
                reason = 4;
            } else if (event->error_handle->esp_tls_stack_err != 0) {
                reason = 3;
            }
        }
        at_event_post("MQTT_CONN:ERROR %d", reason);
        break;
    }

    case MQTT_EVENT_DATA:
        /* A message split across multiple MQTT_EVENT_DATA fragments
         * (total_data_len > data_len) only carries the topic on its first
         * fragment; continuation fragments are dropped rather than
         * reassembled -- a scope simplification for large messages. */
        if (event->topic_len > 0) {
            char topic[129];
            int tlen = event->topic_len < 128 ? event->topic_len : 128;
            memcpy(topic, event->topic, (size_t)tlen);
            topic[tlen] = '\0';

            char header[200];
            int hlen = snprintf(header, sizeof(header), AT_TAG "MQTT_RECV:IND %d %s %d ",
                                 link_id, topic, event->data_len);
            if (hlen > 0 && (size_t)hlen < sizeof(header)) {
                at_uart_write_atomic2(header, (size_t)hlen, event->data, (size_t)event->data_len);
                at_uart_write("\r\n", 2);
            }
        }
        break;

    default:
        break;
    }
}

/* AT*M2M*MQTT_CONF -- doc's Query form ("=?") takes no link_id despite
 * there being 4 profiles; resolved by accepting an optional trailing
 * link_id (default 0) the same way NET_DHCP's non-standard query is
 * handled. Set's optional [path]/[user_name]/[password]/[cert_name] sit in
 * fixed positions per the doc's own worked example (pass "" for unused
 * ones), not the end of the arg list. */
void cmd_mqtt_conf(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        int link_id = (cmd->argc >= 2) ? atoi(cmd->argv[1]) : 0;
        if (link_id < 0 || link_id >= MQTT_MAX_LINKS) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        mqtt_link_t *l = &s_links[link_id];
        if (!l->configured) {
            at_reply_error(cmd->name, AT_ERR_STATE);
            return;
        }
        at_reply_ok(cmd->name, "%d %s %d %s %s %s %s", l->scheme, l->host, l->port,
                    l->path, l->client_id, l->user, l->cert_name);
        return;
    }

    if (cmd->argc < 6) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    int scheme = atoi(cmd->argv[1]);
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS || scheme < 0 || scheme > 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    if (l->client) {
        at_reply_error(cmd->name, AT_ERR_STATE); /* run MQTT_CLEAN first */
        return;
    }

    if (!fields_valid(cmd->argv[2], atoi(cmd->argv[3]), cmd->argv[4], cmd->argv[5],
                      cmd->argc >= 7 ? cmd->argv[6] : NULL, cmd->argc >= 8 ? cmd->argv[7] : NULL,
                      cmd->argc >= 9 ? cmd->argv[8] : NULL)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    l->scheme = scheme;
    strlcpy(l->host, cmd->argv[2], sizeof(l->host));
    l->port = atoi(cmd->argv[3]);
    strlcpy(l->path, cmd->argv[4], sizeof(l->path));
    strlcpy(l->client_id, cmd->argv[5], sizeof(l->client_id));
    l->user[0] = '\0';
    l->password[0] = '\0';
    l->cert_name[0] = '\0';
    if (cmd->argc >= 7) {
        strlcpy(l->user, cmd->argv[6], sizeof(l->user));
    }
    if (cmd->argc >= 8) {
        strlcpy(l->password, cmd->argv[7], sizeof(l->password));
    }
    if (cmd->argc >= 9) {
        strlcpy(l->cert_name, cmd->argv[8], sizeof(l->cert_name));
    }
    l->configured = true;
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*MQTT_ALPN=<link_id> <count> [alpn1] [alpn2] ... */
void cmd_mqtt_alpn(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    int count = atoi(cmd->argv[1]);
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS || count < 0 || count > 5) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    l->alpn_count = count;
    for (int i = 0; i < count; i++) {
        if (cmd->argc >= 3 + i) {
            strlcpy(l->alpn[i], cmd->argv[2 + i], sizeof(l->alpn[i]));
        } else {
            l->alpn[i][0] = '\0';
        }
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*MQTT_CONN=<link_id> [keep_alive] */
void cmd_mqtt_conn(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    if (!l->configured) {
        at_reply_error(cmd->name, 1); /* doc: 1-<link_id> not configured */
        return;
    }
    if (l->client) {
        at_reply_error(cmd->name, 5); /* doc: 5-already connected */
        return;
    }

    int keep_alive = (cmd->argc >= 2) ? atoi(cmd->argv[1]) : 120;
    if (keep_alive < 0 || keep_alive > 7200) {
        keep_alive = 120;
    }

    esp_mqtt_transport_t transport;
    switch (l->scheme) {
    case 0: transport = MQTT_TRANSPORT_OVER_TCP; break;
    case 1: transport = MQTT_TRANSPORT_OVER_SSL; break;
    case 2: transport = MQTT_TRANSPORT_OVER_WS;  break;
    case 3: transport = MQTT_TRANSPORT_OVER_WSS; break;
    default:
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    esp_mqtt_client_config_t config = {0};
    config.broker.address.hostname = l->host;
    config.broker.address.port = (uint32_t)l->port;
    config.broker.address.transport = transport;
    if (l->path[0]) {
        config.broker.address.path = l->path;
    }
    config.credentials.client_id = l->client_id;
    if (l->user[0]) {
        config.credentials.username = l->user;
    }
    if (l->password[0]) {
        config.credentials.authentication.password = l->password;
    }
    config.session.keepalive = keep_alive;

    if (transport == MQTT_TRANSPORT_OVER_SSL || transport == MQTT_TRANSPORT_OVER_WSS) {
        if (l->alpn_count > 0) {
            for (int i = 0; i < l->alpn_count; i++) {
                l->alpn_ptrs[i] = l->alpn[i];
            }
            l->alpn_ptrs[l->alpn_count] = NULL;
            config.broker.verification.alpn_protos = l->alpn_ptrs;
        }
        /* cert_name (doc: one filename) may hold a private CA cert (for
         * verifying a broker that isn't in the public bundle), a client
         * cert+key pair (mutual TLS), or both concatenated -- mbedtls finds
         * each PEM block by its own header, so the same buffer can serve
         * every field that applies. No cert_name at all falls back to the
         * doc's "server-only validation" default: the public CA bundle. */
        l->cert_pem = load_cert_alloc(l->cert_name);
        if (l->cert_pem) {
            config.broker.verification.certificate = l->cert_pem;
            if (strstr(l->cert_pem, "PRIVATE KEY")) {
                config.credentials.authentication.certificate = l->cert_pem;
                config.credentials.authentication.key = l->cert_pem;
            }
        } else {
            config.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
        }
    }

    l->client = esp_mqtt_client_init(&config);
    if (!l->client) {
        free(l->cert_pem);
        l->cert_pem = NULL;
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    esp_mqtt_client_register_event(l->client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void *)(intptr_t)link_id);
    atomic_store(&l->clean_requested, false);

    if (esp_mqtt_client_start(l->client) != ESP_OK) {
        esp_mqtt_client_destroy(l->client);
        l->client = NULL;
        free(l->cert_pem);
        l->cert_pem = NULL;
        at_reply_error(cmd->name, 2); /* doc: 2-could not reach the broker */
        return;
    }
    at_reply_ok(cmd->name, NULL);
    /* MQTT_CONN:IND/DONE follow asynchronously from mqtt_event_handler(). */
}

/* AT*M2M*MQTT_STATUS=? -- Query only. Reports every *configured* link
 * (matching NET_STATUS's "every open link" pattern for net_link.c's
 * sockets, a separate namespace -- see the file header comment). Fills a
 * gap MQTT_CONF's own query doesn't cover: MQTT_CONF=? reports static
 * config only, never whether the link is actually connected right now --
 * previously only discoverable via the MQTT_CONN:IND/MQTT_DISCONN:IND
 * notifications, which a host that just booted or missed one has no way
 * to recover. */
void cmd_mqtt_status(const at_command_t *cmd)
{
    for (int link_id = 0; link_id < MQTT_MAX_LINKS; link_id++) {
        mqtt_link_t *l = &s_links[link_id];
        if (!l->configured) {
            continue;
        }
        at_reply_line("MQTT_STATUS:IND %d %d %d %d %s %d",
                      link_id, 1, atomic_load(&l->connected) ? 1 : 0,
                      l->scheme, l->host, l->port);
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*MQTT_PUB=<link_id> <topic> <data> <qos> <retain> [timeout_ms] --
 * registered `raw`; <topic>/<data> may be quoted with doc's doubled-quote
 * escaping ("" -> literal "), unlike every other command's parser. */
static char *parse_quoted_or_plain(char **pp)
{
    char *p = *pp;
    while (*p == ' ') {
        p++;
    }
    if (*p != '"') {
        char *start = p;
        while (*p && *p != ' ') {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
        *pp = p;
        return start;
    }
    p++;
    char *out = p;
    char *write = p;
    while (*p) {
        if (*p == '"') {
            if (*(p + 1) == '"') {
                *write++ = '"';
                p += 2;
                continue;
            }
            p++;
            break;
        }
        *write++ = *p++;
    }
    *write = '\0';
    while (*p == ' ') {
        p++;
    }
    *pp = p;
    return out;
}

void cmd_mqtt_pub(const at_command_t *cmd)
{
    char *p = cmd->raw_params;
    if (!p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    while (*p == ' ') {
        p++;
    }
    char *link_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    if (*p) {
        *p++ = '\0';
    }
    char *topic = parse_quoted_or_plain(&p);
    char *data = parse_quoted_or_plain(&p);
    char *qos_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    if (*p) {
        *p++ = '\0';
    }
    while (*p == ' ') {
        p++;
    }
    char *retain_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    if (*p) {
        *p = '\0';
    }

    int link_id = atoi(link_tok);
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS || !*topic) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    if (!l->client) {
        at_reply_error(cmd->name, AT_ERR_STATE); /* doc: 1-not connected */
        return;
    }
    int qos = *qos_tok ? atoi(qos_tok) : 0;
    int retain = *retain_tok ? atoi(retain_tok) : 0;

    if (esp_mqtt_client_publish(l->client, topic, data, 0, qos, retain) < 0) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*MQTT_SUB -- Query lists active subscriptions; Set subscribes
 * (cmd=0) or unsubscribes (cmd=1). */
void cmd_mqtt_sub(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        for (int li = 0; li < MQTT_MAX_LINKS; li++) {
            for (int i = 0; i < MQTT_MAX_SUBS; i++) {
                if (s_links[li].subs[i].used) {
                    at_reply_line("MQTT_SUB:IND %d 0 %s %d", li, s_links[li].subs[i].topic,
                                  s_links[li].subs[i].qos);
                }
            }
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (cmd->argc < 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int op = atoi(cmd->argv[0]);
    int link_id = atoi(cmd->argv[1]);
    const char *topic = cmd->argv[2];
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    if (!l->client) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }

    if (op == 0) {
        for (int i = 0; i < MQTT_MAX_SUBS; i++) {
            if (l->subs[i].used && strcmp(l->subs[i].topic, topic) == 0) {
                at_reply_error(cmd->name, 2); /* doc: 2-already subscribe */
                return;
            }
        }
        int slot = -1;
        for (int i = 0; i < MQTT_MAX_SUBS; i++) {
            if (!l->subs[i].used) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            at_reply_error(cmd->name, AT_ERR_GENERIC); /* doc caps 10 topics at once */
            return;
        }
        int qos = (cmd->argc >= 4) ? atoi(cmd->argv[3]) : 0;
        if (esp_mqtt_client_subscribe(l->client, topic, qos) < 0) {
            at_reply_error(cmd->name, AT_ERR_GENERIC);
            return;
        }
        strlcpy(l->subs[slot].topic, topic, sizeof(l->subs[slot].topic));
        l->subs[slot].qos = qos;
        l->subs[slot].used = true;
    } else if (op == 1) {
        bool found = false;
        for (int i = 0; i < MQTT_MAX_SUBS; i++) {
            if (l->subs[i].used && strcmp(l->subs[i].topic, topic) == 0) {
                l->subs[i].used = false;
                found = true;
                break;
            }
        }
        if (!found) {
            at_reply_error(cmd->name, 1); /* doc: 1-no subscribe */
            return;
        }
        esp_mqtt_client_unsubscribe(l->client, topic);
    } else {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*MQTT_CLEAN=<link_id> */
void cmd_mqtt_clean(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= MQTT_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    mqtt_link_t *l = &s_links[link_id];
    if (!l->client) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }

    atomic_store(&l->clean_requested, true);
    esp_mqtt_client_stop(l->client);
    esp_mqtt_client_destroy(l->client);
    l->client = NULL;
    free(l->cert_pem);
    l->cert_pem = NULL;
    memset(l->subs, 0, sizeof(l->subs));

    at_reply_ok(cmd->name, NULL);
    at_event_post("MQTT_CLEAN:DONE");
}

/* ---- Web UI (cmd_httpd.c) integration -- always link_id 0. See mqtt_web.h.
 * The OTH-AT build has its own (cmd_oth_mqtt.c). */
#if !CONFIG_AT_MODEM_CMDSET_OTH

void mqtt_web_get_status(mqtt_web_status_t *out)
{
    mqtt_link_t *l = &s_links[0];
    memset(out, 0, sizeof(*out));
    out->configured = l->configured;
    out->connected = atomic_load(&l->connected);
    out->scheme = l->scheme;
    strlcpy(out->host, l->host, sizeof(out->host));
    out->port = l->port;
    strlcpy(out->client_id, l->client_id, sizeof(out->client_id));
    strlcpy(out->user, l->user, sizeof(out->user));
    out->has_password = l->password[0] != '\0';
    out->has_cert = l->cert_name[0] != '\0';
}

bool mqtt_web_configure_and_connect(int scheme, const char *host, int port,
                                     const char *client_id, const char *user,
                                     const char *password, const char *cert_name)
{
    if (scheme < 0 || scheme > 3 || !fields_valid(host, port, "", client_id, user, password, cert_name)) {
        return false;
    }
    mqtt_link_t *l = &s_links[0];

    /* Tear down any existing connection/config first -- the web UI's
     * "Save & Test Connection" is a single idempotent action, unlike
     * MQTT_CONF/MQTT_CONN's stricter one-shot state machine. */
    if (l->client) {
        atomic_store(&l->clean_requested, true);
        esp_mqtt_client_stop(l->client);
        esp_mqtt_client_destroy(l->client);
        l->client = NULL;
        free(l->cert_pem);
        l->cert_pem = NULL;
        memset(l->subs, 0, sizeof(l->subs));
    }

    l->scheme = scheme;
    strlcpy(l->host, host, sizeof(l->host));
    l->port = port;
    l->path[0] = '\0';
    strlcpy(l->client_id, client_id, sizeof(l->client_id));
    strlcpy(l->user, user ? user : "", sizeof(l->user));
    strlcpy(l->password, password ? password : "", sizeof(l->password));
    strlcpy(l->cert_name, cert_name ? cert_name : "", sizeof(l->cert_name));
    l->alpn_count = 0;
    l->configured = true;

    esp_mqtt_transport_t transport;
    switch (scheme) {
    case 0: transport = MQTT_TRANSPORT_OVER_TCP; break;
    case 1: transport = MQTT_TRANSPORT_OVER_SSL; break;
    case 2: transport = MQTT_TRANSPORT_OVER_WS;  break;
    case 3: transport = MQTT_TRANSPORT_OVER_WSS; break;
    default: return false;
    }

    esp_mqtt_client_config_t config = {0};
    config.broker.address.hostname = l->host;
    config.broker.address.port = (uint32_t)l->port;
    config.broker.address.transport = transport;
    config.credentials.client_id = l->client_id;
    if (l->user[0]) {
        config.credentials.username = l->user;
    }
    if (l->password[0]) {
        config.credentials.authentication.password = l->password;
    }
    config.session.keepalive = 120;

    if (transport == MQTT_TRANSPORT_OVER_SSL || transport == MQTT_TRANSPORT_OVER_WSS) {
        l->cert_pem = load_cert_alloc(l->cert_name);
        if (l->cert_pem) {
            config.broker.verification.certificate = l->cert_pem;
            if (strstr(l->cert_pem, "PRIVATE KEY")) {
                config.credentials.authentication.certificate = l->cert_pem;
                config.credentials.authentication.key = l->cert_pem;
            }
        } else {
            config.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
        }
    }

    l->client = esp_mqtt_client_init(&config);
    if (!l->client) {
        free(l->cert_pem);
        l->cert_pem = NULL;
        return false;
    }
    esp_mqtt_client_register_event(l->client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void *)(intptr_t)0);
    atomic_store(&l->clean_requested, false);
    atomic_store(&l->connected, false);

    if (esp_mqtt_client_start(l->client) != ESP_OK) {
        esp_mqtt_client_destroy(l->client);
        l->client = NULL;
        free(l->cert_pem);
        l->cert_pem = NULL;
        return false;
    }
    return true;
    /* MQTT_EVENT_CONNECTED/DISCONNECTED/ERROR update l->connected
     * asynchronously -- poll mqtt_web_get_status() to observe it. */
}
#endif
