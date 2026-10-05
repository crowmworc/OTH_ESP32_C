/* AT*OTH*AWS_GET / AWS_SEND, *OTH*AWS_IND / AWS_RECV -- OTH-AT AWS IoT
 * volume. The module runs the whole connection pipeline itself; the host
 * only publishes attribute JSON and receives cloud messages.
 *
 * The guide's pairing / authentication servers and topic scheme are not
 * specified, so they are mapped onto AWS IoT's own documented mechanisms
 * (the same ones the M2M-AT build's AWS_PROVISION uses):
 *
 *   "pairing"       -- the pairing package, files stored on the module
 *                      (HTTP_DOWNLOAD or the web TLS screen):
 *                        aws_conf.json  {"endpoint": "...-ats.iot.<region>
 *                                        .amazonaws.com", "template": "<fleet
 *                                        provisioning template>",
 *                                        "parameters": {...}}
 *                        aws_claim.pem  claim certificate + private key
 *   "authenticate"  -- Fleet Provisioning by Claim: with the claim
 *                      certificate the module obtains its own device
 *                      certificate and key and registers its Thing (once;
 *                      kept in NV memory as aws_cert.pem / aws_key.pem).
 *   root CA         -- the public CA bundle (Amazon Trust Services).
 *   topics          -- AWS_SEND=<apiNo> publishes to <thing>/up/<apiNo>;
 *                      messages on <thing>/down/<apiNo> arrive as
 *                      AWS_RECV:<apiNo> <len> <json>.
 *
 * The pipeline starts whenever the module obtains an IP address (and on
 * AWS_SEND=A100), reporting CONFIG, AUTHENTICATE, CERTIFICATE, PRIVATE_KEY,
 * ROOTCA and CONNECT through *OTH*AWS_IND. A lost connection reports
 * DISCONNECT ERROR 2; esp-mqtt reconnects by itself. A5XX (firmware
 * upgrade over the cloud) is not handled by the module: its payload format
 * is not specified -- such messages are passed to the host like any other.
 * AWS_GET 3-5/7 (authentication/root-CA URLs, token) have no counterpart
 * and read null; 10/11 (MCU version/checksum) belong to an MCU_READY
 * command and FOTA flow the guide does not define, and read null. */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_crt_bundle.h"
#include "mqtt_client.h"
#include "cJSON.h"

#include "at_commands_oth.h"
#include "at_cmdset.h"
#include "at_response.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_uart.h"
#include "at_wifi.h"
#include "fs_store.h"

#define CONF_FILE  "aws_conf.json"
#define CLAIM_FILE "aws_claim.pem"
#define CERT_FILE  "aws_cert.pem" /* same names as M2M-AT AWS_PROVISION */
#define KEY_FILE   "aws_key.pem"

/* Appendix A */
#define E_MEM        1
#define E_RELEASED   2
#define E_CONFIG     3
#define E_AUTH_TO    100
#define E_AUTH_RESP  101
#define E_CERT_FAIL  112
#define E_KEY_FAIL   115
#define E_MQTT_INIT  200
#define E_MQTT_CONN  201
#define E_MQTT_SUB   210
#define E_MQTT_PUB   211

static char s_endpoint[128];
static char s_thing[65];
static char s_template[64];
static char s_params[256];

static esp_mqtt_client_handle_t s_client;
static char *s_cert_pem, *s_key_pem;
static atomic_bool s_connected;
static TaskHandle_t s_task;
static int s_send_mid = -1;

static void ind(const char *stage, int code)
{
    if (code) {
        at_event_post("AWS_IND:%s ERROR %d", stage, code);
    } else {
        at_event_post("AWS_IND:%s OK 0", stage);
    }
}

/* ---- CONFIG: the pairing package -------------------------------------------- */

static int load_config(void)
{
    char *json = fs_store_read_alloc(CONF_FILE, NULL);
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    free(json);
    const cJSON *ep = root ? cJSON_GetObjectItem(root, "endpoint") : NULL;
    const cJSON *tp = root ? cJSON_GetObjectItem(root, "template") : NULL;
    const cJSON *pr = root ? cJSON_GetObjectItem(root, "parameters") : NULL;
    int err = 0;
    if (!cJSON_IsString(ep) || !ep->valuestring[0] || strlen(ep->valuestring) >= sizeof(s_endpoint)) {
        err = E_CONFIG;
    } else {
        strlcpy(s_endpoint, ep->valuestring, sizeof(s_endpoint));
        strlcpy(s_template, cJSON_IsString(tp) ? tp->valuestring : "", sizeof(s_template));
        char *p = cJSON_IsObject(pr) ? cJSON_PrintUnformatted(pr) : NULL;
        strlcpy(s_params, p ? p : "{}", sizeof(s_params));
        free(p);
    }
    cJSON_Delete(root);
    size_t len = sizeof(s_thing);
    m2m_nvs_get_str("aws_thing", s_thing, &len);
    return err;
}

/* ---- AUTHENTICATE: Fleet Provisioning by Claim --------------------------------
 * Same exchange as cmd_aws.c's provision_worker() (whose hardware-found
 * lessons apply: the certificate response arrives in several MQTT_EVENT_DATA
 * fragments and is ~3.5 KB, the ownership token is ~460 characters). */

typedef struct {
    SemaphoreHandle_t connected, msg;
    char topic[160];
    char payload[6144];
    size_t len;
} prov_ctx_t;

static void prov_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    (void)base;
    prov_ctx_t *c = args;
    esp_mqtt_event_handle_t ev = data;
    if (id == MQTT_EVENT_CONNECTED) {
        xSemaphoreGive(c->connected);
    } else if (id == MQTT_EVENT_DATA) {
        if (ev->current_data_offset == 0) {
            int tl = ev->topic_len < (int)sizeof(c->topic) - 1 ? ev->topic_len : (int)sizeof(c->topic) - 1;
            memcpy(c->topic, ev->topic, (size_t)tl);
            c->topic[tl] = '\0';
            c->len = 0;
        }
        if (c->len + (size_t)ev->data_len < sizeof(c->payload)) {
            memcpy(c->payload + c->len, ev->data, (size_t)ev->data_len);
            c->len += (size_t)ev->data_len;
        }
        if (ev->current_data_offset + ev->data_len >= ev->total_data_len) {
            c->payload[c->len] = '\0';
            xSemaphoreGive(c->msg);
        }
    }
}

static bool wait_msg(prov_ctx_t *c)
{
    return xSemaphoreTake(c->msg, pdMS_TO_TICKS(15000)) == pdTRUE && !strstr(c->topic, "rejected");
}

/* Returns 0, or the stage code: E_AUTH_TO / E_AUTH_RESP (claim connection
 * or a rejected request), E_CERT_FAIL / E_KEY_FAIL (storing the result). */
static int provision(void)
{
    char *claim = fs_store_read_alloc(CLAIM_FILE, NULL);
    prov_ctx_t *c = calloc(1, sizeof(*c));
    if (!claim || !c || !s_template[0]) {
        free(claim);
        free(c);
        return !c ? E_MEM : E_CONFIG;
    }
    c->connected = xSemaphoreCreateBinary();
    c->msg = xSemaphoreCreateBinary();
    int err = 0;
    char *cert = NULL, *key = NULL, *token = NULL;

    esp_mqtt_client_config_t cfg = {0};
    cfg.broker.address.hostname = s_endpoint;
    cfg.broker.address.port = 8883;
    cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;
    cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.credentials.client_id = "oth-fleet-provision";
    cfg.credentials.authentication.certificate = claim;
    cfg.credentials.authentication.key = claim;
    esp_mqtt_client_handle_t cl = esp_mqtt_client_init(&cfg);
    if (!cl) {
        err = E_MEM;
        goto out;
    }
    esp_mqtt_client_register_event(cl, ESP_EVENT_ANY_ID, prov_handler, c);
    if (esp_mqtt_client_start(cl) != ESP_OK || xSemaphoreTake(c->connected, pdMS_TO_TICKS(15000)) != pdTRUE) {
        err = E_AUTH_TO;
        goto stop;
    }
    esp_mqtt_client_subscribe(cl, "$aws/certificates/create/json/accepted", 1);
    esp_mqtt_client_subscribe(cl, "$aws/certificates/create/json/rejected", 1);
    esp_mqtt_client_publish(cl, "$aws/certificates/create/json", "{}", 2, 1, 0);
    if (!wait_msg(c)) {
        err = E_AUTH_RESP;
        goto stop;
    }
    {
        cJSON *r = cJSON_Parse(c->payload);
        const cJSON *jc = r ? cJSON_GetObjectItem(r, "certificatePem") : NULL;
        const cJSON *jk = r ? cJSON_GetObjectItem(r, "privateKey") : NULL;
        const cJSON *jt = r ? cJSON_GetObjectItem(r, "certificateOwnershipToken") : NULL;
        if (cJSON_IsString(jc) && cJSON_IsString(jk) && cJSON_IsString(jt)) {
            cert = strdup(jc->valuestring);
            key = strdup(jk->valuestring);
            token = strdup(jt->valuestring);
        }
        cJSON_Delete(r);
        if (!cert || !key || !token) {
            err = E_AUTH_RESP;
            goto stop;
        }
    }
    char t_ok[160], t_rej[160], t_req[160];
    snprintf(t_ok, sizeof(t_ok), "$aws/provisioning-templates/%s/provision/json/accepted", s_template);
    snprintf(t_rej, sizeof(t_rej), "$aws/provisioning-templates/%s/provision/json/rejected", s_template);
    snprintf(t_req, sizeof(t_req), "$aws/provisioning-templates/%s/provision/json", s_template);
    esp_mqtt_client_subscribe(cl, t_ok, 1);
    esp_mqtt_client_subscribe(cl, t_rej, 1);
    {
        cJSON *body = cJSON_CreateObject();
        cJSON_AddStringToObject(body, "certificateOwnershipToken", token);
        cJSON *params = cJSON_Parse(s_params);
        cJSON_AddItemToObject(body, "parameters", params ? params : cJSON_CreateObject());
        char *s = cJSON_PrintUnformatted(body);
        esp_mqtt_client_publish(cl, t_req, s, 0, 1, 0);
        free(s);
        cJSON_Delete(body);
    }
    if (!wait_msg(c)) {
        err = E_AUTH_RESP;
        goto stop;
    }
    {
        cJSON *r = cJSON_Parse(c->payload);
        const cJSON *jn = r ? cJSON_GetObjectItem(r, "thingName") : NULL;
        if (cJSON_IsString(jn)) {
            strlcpy(s_thing, jn->valuestring, sizeof(s_thing));
        } else {
            err = E_AUTH_RESP;
        }
        cJSON_Delete(r);
    }
    if (!err) {
        if (!fs_store_write(CERT_FILE, cert, strlen(cert))) {
            err = E_CERT_FAIL;
        } else if (!fs_store_write(KEY_FILE, key, strlen(key))) {
            err = E_KEY_FAIL;
        } else {
            m2m_nvs_set_str("aws_thing", s_thing);
        }
    }
stop:
    esp_mqtt_client_stop(cl);
    esp_mqtt_client_destroy(cl);
out:
    if (key) {
        memset(key, 0, strlen(key));
    }
    free(cert);
    free(key);
    free(token);
    vSemaphoreDelete(c->connected);
    vSemaphoreDelete(c->msg);
    free(c);
    free(claim);
    return err;
}

/* ---- CONNECT and the message flow ------------------------------------------------ */

static void deliver(const char *topic, int tlen, const char *data, int len)
{
    /* <thing>/down/<apiNo> */
    const char *api = NULL;
    for (int i = tlen - 1; i >= 0; i--) {
        if (topic[i] == '/') {
            api = topic + i + 1;
            break;
        }
    }
    int alen = api ? (int)(topic + tlen - api) : 0;
    if (!alen || alen > 16 || !at_event_enabled()) {
        return;
    }
    char head[64];
    int n = snprintf(head, sizeof(head), AT_TAG "AWS_RECV:%.*s %d ", alen, api, len);
    at_uart_write_atomic2(head, (size_t)n, data, (size_t)len);
    at_uart_write("\r\n", 2);
}

static char s_rx_topic[128];
static int s_rx_tlen;
static char *s_rx_buf;
static int s_rx_len;

static void aws_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    (void)args;
    (void)base;
    esp_mqtt_event_handle_t ev = data;
    switch (id) {
    case MQTT_EVENT_CONNECTED: {
        bool first = !atomic_exchange(&s_connected, true);
        char t[96];
        snprintf(t, sizeof(t), "%s/down/+", s_thing);
        if (esp_mqtt_client_subscribe(s_client, t, 1) < 0) {
            ind("CONNECT", E_MQTT_SUB);
        } else if (first) {
            ind("CONNECT", 0);
        }
        break;
    }
    case MQTT_EVENT_DISCONNECTED:
        if (atomic_exchange(&s_connected, false)) {
            ind("DISCONNECT", E_RELEASED);
        }
        break;
    case MQTT_EVENT_PUBLISHED:
        if (ev->msg_id == s_send_mid) {
            s_send_mid = -1;
            at_event_post("AWS_IND:SEND OK");
        }
        break;
    case MQTT_EVENT_DATA:
        if (ev->current_data_offset == 0) {
            s_rx_tlen = ev->topic_len < (int)sizeof(s_rx_topic) ? ev->topic_len : (int)sizeof(s_rx_topic);
            memcpy(s_rx_topic, ev->topic, (size_t)s_rx_tlen);
            free(s_rx_buf);
            s_rx_buf = NULL;
            s_rx_len = 0;
            if (ev->data_len == ev->total_data_len) {
                deliver(s_rx_topic, s_rx_tlen, ev->data, ev->data_len);
                break;
            }
            s_rx_buf = ev->total_data_len <= 8192 ? malloc((size_t)ev->total_data_len) : NULL;
        }
        if (s_rx_buf && s_rx_len + ev->data_len <= ev->total_data_len) {
            memcpy(s_rx_buf + s_rx_len, ev->data, (size_t)ev->data_len);
            s_rx_len += ev->data_len;
            if (s_rx_len == ev->total_data_len) {
                deliver(s_rx_topic, s_rx_tlen, s_rx_buf, s_rx_len);
                free(s_rx_buf);
                s_rx_buf = NULL;
            }
        }
        break;
    default:
        break;
    }
}

static void client_close(void)
{
    if (s_client) {
        esp_mqtt_client_stop(s_client);
        esp_mqtt_client_destroy(s_client);
        s_client = NULL;
    }
    atomic_store(&s_connected, false);
    free(s_cert_pem);
    free(s_key_pem);
    s_cert_pem = s_key_pem = NULL;
}

static void pipeline_task(void *arg)
{
    (void)arg;
    client_close();
    int err = load_config();
    ind("CONFIG", err);
    if (err) {
        goto done;
    }
    if (!s_thing[0] || !fs_store_exists(CERT_FILE) || !fs_store_exists(KEY_FILE)) {
        err = provision();
        ind("AUTHENTICATE", err == E_CERT_FAIL || err == E_KEY_FAIL ? 0 : err);
        if (err && err != E_CERT_FAIL && err != E_KEY_FAIL) {
            goto done;
        }
    } else {
        ind("AUTHENTICATE", 0); /* already provisioned */
    }
    s_cert_pem = fs_store_read_alloc(CERT_FILE, NULL);
    ind("CERTIFICATE", s_cert_pem ? 0 : E_CERT_FAIL);
    s_key_pem = s_cert_pem ? fs_store_read_alloc(KEY_FILE, NULL) : NULL;
    if (s_cert_pem) {
        ind("PRIVATE_KEY", s_key_pem ? 0 : E_KEY_FAIL);
    }
    if (!s_cert_pem || !s_key_pem) {
        goto done;
    }
    ind("ROOTCA", 0); /* public CA bundle, always present */

    esp_mqtt_client_config_t cfg = {0};
    cfg.broker.address.hostname = s_endpoint;
    cfg.broker.address.port = 8883;
    cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;
    cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.credentials.client_id = s_thing;
    cfg.credentials.authentication.certificate = s_cert_pem;
    cfg.credentials.authentication.key = s_key_pem;
    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) {
        ind("CONNECT", E_MQTT_INIT);
        goto done;
    }
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, aws_handler, NULL);
    if (esp_mqtt_client_start(s_client) != ESP_OK) {
        ind("CONNECT", E_MQTT_CONN);
        goto done;
    }
    for (int i = 0; i < 200 && !atomic_load(&s_connected); i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (!atomic_load(&s_connected)) {
        ind("CONNECT", E_MQTT_CONN); /* esp-mqtt keeps retrying in the background */
    }
done:
    s_task = NULL;
    vTaskDelete(NULL);
}

static void pipeline_start(void)
{
    if (s_task || !fs_store_exists(CONF_FILE)) {
        return; /* not paired: nothing to do */
    }
    /* provision() keeps its 6 KB message buffer on the heap; the TLS
     * handshakes run in esp-mqtt's own task */
    xTaskCreate(pipeline_task, "oth_aws", 8192, NULL, 5, &s_task);
}

/* Called on IPALLOCATED (cmd_wifi.c). */
void at_oth_aws_on_ip(void)
{
    if (!s_client) {
        pipeline_start();
    }
}

/* ---- commands --------------------------------------------------------------------- */

/* AT*OTH*AWS_GET=<index> */
void cmd_oth_aws_get(const at_command_t *cmd)
{
    int idx = cmd->argc >= 1 ? atoi(cmd->argv[0]) : -1;
    if (s_endpoint[0] == '\0') {
        load_config();
    }
    switch (cmd->argc >= 1 ? idx : -1) {
    case 0:
        at_reply_ok(cmd->name, "%s", s_endpoint[0] ? s_endpoint : "null");
        return;
    case 1:
        at_reply_ok(cmd->name, "%s", s_endpoint[0] ? "8883" : "null");
        return;
    case 2:
        at_reply_ok(cmd->name, "%s", s_thing[0] ? s_thing : "null");
        return;
    case 6: {
        /* <id>-ats.iot.<region>.amazonaws.com */
        const char *p = strstr(s_endpoint, ".iot.");
        const char *e = p ? strstr(p + 5, ".amazonaws.com") : NULL;
        if (p && e) {
            at_reply_ok(cmd->name, "%.*s", (int)(e - (p + 5)), p + 5);
        } else {
            at_reply_ok(cmd->name, "null");
        }
        return;
    }
    case 3: case 4: case 5: case 7: case 10: case 11:
        at_reply_ok(cmd->name, "null");
        return;
    default:
        at_reply_error(cmd->name, -1);
        return;
    }
}

/* AT*OTH*AWS_SEND=<apiNo> <attribute> -- raw: the JSON may contain spaces.
 * A100 (connection request) restarts the pipeline instead of publishing. */
void cmd_oth_aws_send(const at_command_t *cmd)
{
    char *p = cmd->raw_params;
    while (p && *p == ' ') {
        p++;
    }
    char *api = p;
    while (p && *p && *p != ' ') {
        p++;
    }
    if (!p || p == api || p - api > 16) {
        at_reply_error(cmd->name, -1);
        return;
    }
    bool has_body = *p != '\0';
    if (has_body) {
        *p++ = '\0';
    }
    if (strcmp(api, "A100") == 0) {
        at_reply_ok(cmd->name, NULL);
        client_close();
        pipeline_start();
        return;
    }
    if (!has_body || !*p) {
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    if (!atomic_load(&s_connected)) {
        at_event_post("AWS_IND:SEND ERROR %d", E_RELEASED);
        return;
    }
    char t[96];
    snprintf(t, sizeof(t), "%s/up/%s", s_thing, api);
    int mid = esp_mqtt_client_publish(s_client, t, p, (int)strlen(p), 1, 0);
    if (mid < 0) {
        at_event_post("AWS_IND:SEND ERROR %d", E_MQTT_PUB);
        return;
    }
    s_send_mid = mid;
}
