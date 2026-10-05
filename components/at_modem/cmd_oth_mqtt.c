/* AT*OTH*MQTT_* -- OTH-AT MQTT AT Command Set (one client, on esp-mqtt).
 *
 * The client is described by indexed settings (MQTT volume Sec.2.1), kept
 * in NV memory under "mq<index>"; 106/107 are RAM-only overrides of the
 * publish/subscribe topics 6/7. MQTT_CERT's file selection is RAM-only too
 * (the guide reselects it after a Wi-Fi reset).
 *
 * Connection persistence (index 11):
 *   0  MQTT_PUB connects if needed, publishes, then closes the connection
 *   1  the connection stays up after a publish
 *   2  one persistent connection, opened automatically whenever the module
 *      obtains an IP address (will message and keep-alive apply here)
 * Once connected the module subscribes to the configured topic by itself,
 * and esp-mqtt reconnects (and this file resubscribes) after a lost link.
 *
 * Notifications: MQTT_PUB_IND / MQTT_SUB_IND OK 1 (connected), 2
 * (disconnected), 3 (published); ERROR with the Appendix A.1 codes
 * (15 connection failed, 16 refused, ...). MQTT_SUB_RECV:<len> <data>.
 *
 * TLS option (index 2): 4 (TLS 1.2, negotiated up to 1.3) only. 1 (SSL
 * 3.0) and 2 (TLS 1.0) are refused with error 7 -- this firmware does not
 * offer those protocol versions (EN 18031-1, open review item). The broker
 * is verified against MQTT_CERT's CA file, else the public CA bundle.
 *
 * In this build the web UI's MQTT screen drives this client too
 * (mqtt_web_* at the end). */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_crt_bundle.h"
#include "esp_mac.h"
#include "mqtt_client.h"

#include "at_commands_oth.h"
#include "at_cmdset.h"
#include "at_response.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_uart.h"
#include "at_wifi.h"
#include "fs_store.h"
#include "mqtt_web.h"

#define MQ_ERR_PARAM   2
#define MQ_ERR_MEM     3
#define MQ_ERR_TLS     7
#define MQ_ERR_CONNECT 15
#define MQ_ERR_REFUSED 16

/* index -> max length (strings) or -1 (number); 0 = reserved */
static int field_max(int idx)
{
    switch (idx) {
    case 0: case 10: case 12: case 13: return 31;
    case 4: return 47;
    case 5: return 63;
    case 6: case 7: case 106: case 107: return 127;
    case 1: case 2: case 8: case 9: case 11: case 14: return -1;
    default: return 0;
    }
}

static char s_pub_topic_rt[128]; /* 106 */
static char s_sub_topic_rt[128]; /* 107 */
static char s_ca_file[32], s_cert_file[32], s_key_file[32];

static esp_mqtt_client_handle_t s_client;
static char *s_ca_pem, *s_cert_pem, *s_key_pem; /* kept for the client's lifetime */
static atomic_bool s_connected;
static atomic_bool s_closing;   /* host/mode-0 close: report "2" but no error */
static bool s_subscribed_topic;
static int s_pending_pub_mid = -1;

/* client config strings (esp-mqtt keeps the pointers) */
static char s_host[32], s_client_id[32], s_user[48], s_pass[64], s_will_topic[32], s_will_msg[32];

static void key_of(int idx, char key[8])
{
    snprintf(key, 8, "mq%d", idx);
}

static void get_setting(int idx, char *out, size_t cap)
{
    if (idx == 106 || idx == 107) {
        strlcpy(out, idx == 106 ? s_pub_topic_rt : s_sub_topic_rt, cap);
        return;
    }
    char key[8];
    key_of(idx, key);
    size_t len = cap;
    m2m_nvs_get_str(key, out, &len);
}

static int get_num(int idx, int def)
{
    char v[12] = "";
    get_setting(idx, v, sizeof(v));
    return v[0] ? atoi(v) : def;
}

static void topic(int idx, char *out, size_t cap)
{
    get_setting(idx + 100, out, cap); /* the RAM override wins */
    if (!out[0]) {
        get_setting(idx, out, cap);
    }
}

/* ---- client ---------------------------------------------------------------- */

static void post_ind(bool sub_side, bool ok, int code)
{
    at_event_post("MQTT_%s_IND:%s %d", sub_side ? "SUB" : "PUB", ok ? "OK" : "ERROR", code);
}

static void subscribe_configured(void)
{
    char t[128];
    topic(7, t, sizeof(t));
    s_subscribed_topic = false;
    if (t[0] && esp_mqtt_client_subscribe(s_client, t, get_num(9, 0)) >= 0) {
        s_subscribed_topic = true;
    }
}

static char *s_rx_buf;
static size_t s_rx_len;

static void deliver(const char *data, size_t len)
{
    if (!at_event_enabled()) {
        return;
    }
    char head[40];
    int n = snprintf(head, sizeof(head), AT_TAG "MQTT_SUB_RECV:%u ", (unsigned)len);
    at_uart_write_atomic2(head, (size_t)n, data, len);
    at_uart_write("\r\n", 2);
}

static void mqtt_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    (void)args;
    (void)base;
    esp_mqtt_event_handle_t ev = data;
    switch (id) {
    case MQTT_EVENT_CONNECTED:
        atomic_store(&s_connected, true);
        subscribe_configured();
        if (!s_subscribed_topic) {
            post_ind(false, true, 1); /* no topic: report it on the publisher side */
        }
        break;
    case MQTT_EVENT_SUBSCRIBED:
        post_ind(true, true, 1);
        break;
    case MQTT_EVENT_PUBLISHED:
        if (ev->msg_id == s_pending_pub_mid) {
            s_pending_pub_mid = -1;
            post_ind(false, true, 3);
            if (get_num(11, 0) == 0) {
                atomic_store(&s_closing, true);
                esp_mqtt_client_disconnect(s_client);
            }
        }
        break;
    case MQTT_EVENT_DISCONNECTED:
        if (atomic_exchange(&s_connected, false) || atomic_load(&s_closing)) {
            post_ind(s_subscribed_topic, true, 2);
        }
        atomic_store(&s_closing, false);
        break;
    case MQTT_EVENT_ERROR:
        if (ev->error_handle && ev->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
            post_ind(false, false, MQ_ERR_REFUSED);
        } else if (!atomic_load(&s_connected)) {
            post_ind(false, false, MQ_ERR_CONNECT);
        }
        break;
    case MQTT_EVENT_DATA:
        if (ev->data_len == ev->total_data_len) {
            deliver(ev->data, (size_t)ev->data_len);
        } else {
            /* a large message arrives in fragments: reassemble (up to 8 KB) */
            if (ev->current_data_offset == 0) {
                free(s_rx_buf);
                s_rx_len = 0;
                s_rx_buf = ev->total_data_len <= 8192 ? malloc((size_t)ev->total_data_len) : NULL;
            }
            if (s_rx_buf && s_rx_len + (size_t)ev->data_len <= (size_t)ev->total_data_len) {
                memcpy(s_rx_buf + s_rx_len, ev->data, (size_t)ev->data_len);
                s_rx_len += (size_t)ev->data_len;
                if (s_rx_len == (size_t)ev->total_data_len) {
                    deliver(s_rx_buf, s_rx_len);
                    free(s_rx_buf);
                    s_rx_buf = NULL;
                }
            }
        }
        break;
    default:
        break;
    }
}

static void client_destroy(void)
{
    if (s_client) {
        atomic_store(&s_closing, true);
        esp_mqtt_client_stop(s_client);
        esp_mqtt_client_destroy(s_client);
        s_client = NULL;
    }
    atomic_store(&s_connected, false);
    atomic_store(&s_closing, false);
    free(s_ca_pem);
    free(s_cert_pem);
    free(s_key_pem);
    s_ca_pem = s_cert_pem = s_key_pem = NULL;
}

static char *load_file(const char *name)
{
    return name[0] ? fs_store_read_alloc(name, NULL) : NULL;
}

/* Builds and starts the client from the current settings. 0 or A.1 code. */
static int client_start(void)
{
    client_destroy();
    get_setting(0, s_host, sizeof(s_host));
    int port = get_num(1, 0);
    int tls = get_num(2, 0);
    if (!s_host[0] || port <= 0 || port > 65535) {
        return MQ_ERR_PARAM;
    }
    if (tls != 0 && tls != 4) {
        return MQ_ERR_TLS;
    }
    get_setting(10, s_client_id, sizeof(s_client_id));
    if (!s_client_id[0]) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(s_client_id, sizeof(s_client_id), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3],
                 mac[4], mac[5]);
    }
    get_setting(4, s_user, sizeof(s_user));
    get_setting(5, s_pass, sizeof(s_pass));

    esp_mqtt_client_config_t cfg = {0};
    cfg.broker.address.hostname = s_host;
    cfg.broker.address.port = (uint32_t)port;
    cfg.broker.address.transport = tls ? MQTT_TRANSPORT_OVER_SSL : MQTT_TRANSPORT_OVER_TCP;
    cfg.credentials.client_id = s_client_id;
    if (s_user[0]) {
        cfg.credentials.username = s_user;
    }
    if (s_pass[0]) {
        cfg.credentials.authentication.password = s_pass;
    }
    cfg.session.keepalive = 120;
    /* persistence 0 closes after each publish: no reconnecting behind the
     * host's back, the next MQTT_PUB reopens it */
    cfg.network.disable_auto_reconnect = get_num(11, 0) == 0;
    if (get_num(11, 0) == 2) {
        cfg.session.keepalive = get_num(14, 120);
        get_setting(12, s_will_topic, sizeof(s_will_topic));
        get_setting(13, s_will_msg, sizeof(s_will_msg));
        if (s_will_topic[0]) {
            cfg.session.last_will.topic = s_will_topic;
            cfg.session.last_will.msg = s_will_msg;
        }
    }
    if (tls) {
        s_ca_pem = load_file(s_ca_file);
        s_cert_pem = load_file(s_cert_file);
        s_key_pem = load_file(s_key_file);
        if (s_ca_pem) {
            cfg.broker.verification.certificate = s_ca_pem;
        } else {
            cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
        }
        if (s_cert_pem && s_key_pem) {
            cfg.credentials.authentication.certificate = s_cert_pem;
            cfg.credentials.authentication.key = s_key_pem;
        }
    }
    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) {
        client_destroy();
        return MQ_ERR_MEM;
    }
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_handler, NULL);
    if (esp_mqtt_client_start(s_client) != ESP_OK) {
        client_destroy();
        return MQ_ERR_CONNECT;
    }
    return 0;
}

/* Called on IPALLOCATED (cmd_oth_wifi.c): persistence mode 2 connects. */
void at_oth_mqtt_on_ip(void)
{
    if (get_num(11, 0) == 2 && !s_client) {
        client_start();
    }
}

/* ---- commands ----------------------------------------------------------------- */

/* AT*OTH*MQTT_GET=<index> -- value or null; the password (5) reads back
 * masked (open EN 18031-1 review item). */
void cmd_oth_mqtt_get(const at_command_t *cmd)
{
    int idx = cmd->argc >= 1 ? atoi(cmd->argv[0]) : -1;
    if (cmd->argc < 1 || field_max(idx) == 0) {
        at_reply_error(cmd->name, -1);
        return;
    }
    char v[128] = "";
    get_setting(idx, v, sizeof(v));
    at_reply_ok(cmd->name, "%s", !v[0] ? "null" : idx == 5 ? "********" : v);
}

static bool number_ok(int idx, const char *v)
{
    char *end;
    long n = strtol(v, &end, 10);
    if (*end || end == v) {
        return false;
    }
    switch (idx) {
    case 1: return n > 0 && n <= 65535;
    case 2: return n == 0 || n == 1 || n == 2 || n == 4;
    case 8: case 9: case 11: return n >= 0 && n <= 2;
    case 14: return n >= 0 && n <= 65535;
    default: return false;
    }
}

/* AT*OTH*MQTT_SET=<index> <value> */
void cmd_oth_mqtt_set(const at_command_t *cmd)
{
    int idx = cmd->argc >= 1 ? atoi(cmd->argv[0]) : -1;
    int max = field_max(idx);
    if (cmd->argc < 2 || max == 0) {
        at_reply_error(cmd->name, -1);
        return;
    }
    const char *v = cmd->argv[1];
    if (max < 0 ? !number_ok(idx, v) : (int)strlen(v) > max) {
        at_reply_error(cmd->name, -1);
        return;
    }
    if (idx == 2 && (atoi(v) == 1 || atoi(v) == 2)) {
        at_reply_error(cmd->name, -1); /* SSL 3.0 / TLS 1.0 not offered */
        return;
    }
    if (idx == 106 || idx == 107) {
        strlcpy(idx == 106 ? s_pub_topic_rt : s_sub_topic_rt, v, sizeof(s_pub_topic_rt));
    } else {
        char key[8];
        key_of(idx, key);
        m2m_nvs_set_str(key, v);
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*MQTT_CERT=<ca_file> <cert_file> <key_file> -- NULL for none. */
void cmd_oth_mqtt_cert(const at_command_t *cmd)
{
    if (cmd->argc < 3) {
        at_reply_error(cmd->name, -1);
        return;
    }
    char *dst[3] = { s_ca_file, s_cert_file, s_key_file };
    for (int i = 0; i < 3; i++) {
        const char *f = cmd->argv[i];
        bool none = strcasecmp(f, "NULL") == 0;
        if (!none && (strlen(f) >= sizeof(s_ca_file) || !fs_store_exists(f))) {
            at_reply_error(cmd->name, -1);
            return;
        }
    }
    for (int i = 0; i < 3; i++) {
        strlcpy(dst[i], strcasecmp(cmd->argv[i], "NULL") == 0 ? "" : cmd->argv[i], sizeof(s_ca_file));
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*MQTT_CONNECT -- needs an IP address and a broker; the outcome
 * follows as MQTT_SUB_IND / MQTT_PUB_IND. */
void cmd_oth_mqtt_connect(const at_command_t *cmd)
{
    if (!at_wifi_sta_is_connected()) {
        at_reply_error(cmd->name, MQ_ERR_CONNECT);
        return;
    }
    int err = client_start();
    if (err) {
        at_reply_error(cmd->name, err);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*MQTT_PUB=3 <message> -- raw: the message may contain spaces. To
 * topic 106/6 at QoS 8; result MQTT_PUB_IND:OK 3 (an empty message: ERROR
 * 2). Without a connection one is opened first (persistence 0/1). */
void cmd_oth_mqtt_pub(const at_command_t *cmd)
{
    char *p = cmd->raw_params;
    while (p && *p == ' ') {
        p++;
    }
    if (!p || p[0] != '3' || (p[1] != '\0' && p[1] != ' ')) {
        at_reply_error(cmd->name, MQ_ERR_PARAM);
        return;
    }
    const char *msg = p[1] ? p + 2 : "";
    char t[128];
    topic(6, t, sizeof(t));
    at_reply_ok(cmd->name, NULL);
    if (!msg[0] || !t[0]) {
        post_ind(false, false, MQ_ERR_PARAM);
        return;
    }
    if (!atomic_load(&s_connected)) {
        int err = !at_wifi_sta_is_connected() ? MQ_ERR_CONNECT
                  : !s_client                 ? client_start()
                  : esp_mqtt_client_reconnect(s_client) == ESP_OK ? 0 : MQ_ERR_CONNECT;
        if (err) {
            post_ind(false, false, err);
            return;
        }
        /* wait for the connection (esp-mqtt connects in its own task) */
        for (int i = 0; i < 100 && !atomic_load(&s_connected); i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (!atomic_load(&s_connected)) {
            post_ind(false, false, MQ_ERR_CONNECT);
            return;
        }
    }
    int qos = get_num(8, 0);
    int mid = esp_mqtt_client_publish(s_client, t, msg, (int)strlen(msg), qos, 0);
    if (mid < 0) {
        post_ind(false, false, MQ_ERR_CONNECT);
        return;
    }
    if (qos == 0) {
        post_ind(false, true, 3); /* QoS 0 has no acknowledgement */
        if (get_num(11, 0) == 0) {
            atomic_store(&s_closing, true);
            esp_mqtt_client_disconnect(s_client);
        }
    } else {
        s_pending_pub_mid = mid;
    }
}

/* AT*OTH*MQTT_SUB -- topic 107/7 at QoS 9; MQTT_SUB_IND:OK 1 on SUBACK. */
void cmd_oth_mqtt_sub(const at_command_t *cmd)
{
    char t[128];
    topic(7, t, sizeof(t));
    if (!t[0]) {
        at_reply_error(cmd->name, MQ_ERR_PARAM);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    if (!atomic_load(&s_connected) || esp_mqtt_client_subscribe(s_client, t, get_num(9, 0)) < 0) {
        post_ind(true, false, MQ_ERR_CONNECT);
        return;
    }
    s_subscribed_topic = true;
}

/* ---- web UI (cmd_httpd.c) -- see mqtt_web.h ------------------------------------ */

void mqtt_web_get_status(mqtt_web_status_t *out)
{
    memset(out, 0, sizeof(*out));
    char v[64] = "";
    get_setting(0, out->host, sizeof(out->host));
    out->configured = out->host[0] != '\0';
    out->connected = atomic_load(&s_connected);
    out->scheme = get_num(2, 0) ? 1 : 0;
    out->port = get_num(1, 0);
    get_setting(10, out->client_id, sizeof(out->client_id));
    get_setting(4, out->user, sizeof(out->user));
    get_setting(5, v, sizeof(v));
    out->has_password = v[0] != '\0';
    out->has_cert = s_ca_file[0] != '\0';
}

/* scheme 0: mqtt, 1: mqtts (ws/wss are not part of OTH-AT). cert_name, when
 * given, becomes the CA file (and the client cert/key when it holds a
 * private key, as on the M2M-AT screen). */
bool mqtt_web_configure_and_connect(int scheme, const char *host, int port,
                                     const char *client_id, const char *user,
                                     const char *password, const char *cert_name)
{
    if ((scheme != 0 && scheme != 1) || !host || !host[0] || strlen(host) > 31 || port <= 0 || port > 65535 ||
        (client_id && strlen(client_id) > 31) || (user && strlen(user) > 47) ||
        (password && strlen(password) > 63) || (cert_name && cert_name[0] && !fs_store_exists(cert_name))) {
        return false;
    }
    char num[8];
    m2m_nvs_set_str("mq0", host);
    snprintf(num, sizeof(num), "%d", port);
    m2m_nvs_set_str("mq1", num);
    m2m_nvs_set_str("mq2", scheme ? "4" : "0");
    m2m_nvs_set_str("mq10", client_id ? client_id : "");
    m2m_nvs_set_str("mq4", user ? user : "");
    m2m_nvs_set_str("mq5", password ? password : "");
    s_ca_file[0] = s_cert_file[0] = s_key_file[0] = '\0';
    if (cert_name && cert_name[0]) {
        strlcpy(s_ca_file, cert_name, sizeof(s_ca_file));
        char *pem = fs_store_read_alloc(cert_name, NULL);
        if (pem && strstr(pem, "PRIVATE KEY")) {
            strlcpy(s_cert_file, cert_name, sizeof(s_cert_file));
            strlcpy(s_key_file, cert_name, sizeof(s_key_file));
        }
        free(pem);
    }
    return client_start() == 0;
}
