/* AT*OTH*AWS_GET / AWS_SET / AWS_SEND / MCU_READY, *OTH*AWS_IND / AWS_RECV
 * -- OTH-AT AWS IoT volume, as an OTH Platform based client. The module runs
 * the whole connection pipeline itself; the host only publishes attribute
 * JSON and receives cloud messages.
 *
 * Settings (AWS_GET indexes, kept in NV memory): the pairing server
 * (oth_pairing.c) stores 0 MQTT endpoint, 1 port, 3 authentication server
 * URL, 4/5 root CA URLs and 6 region; 7 token comes from the
 * authentication server; 2 client ID is "<MAC>" before and "<MAC>_<token>"
 * after authentication; 10 MCU version comes from MCU_READY, 11 MCU
 * checksum from the MCU firmware upgrade. AWS_SET writes 0/1/3-7 directly
 * (development use). The topic model / group are MIB 18 / 19 (SETMIB).
 *
 * Pipeline, started when the station obtains an IP address (or by
 * AWS_SEND=A100), each stage reported as *OTH*AWS_IND:<stage> OK 0 or
 * ERROR <code> (Appendix A):
 *   CONFIG        endpoint, MIB 18/19 present (else 3)
 *   AUTHENTICATE  GET <auth>/register/token/<MAC> -> {"body":{"token"}}
 *   CERTIFICATE   GET <auth>/register/auth/<MAC>/<token> ->
 *   PRIVATE_KEY     {"body":{"deviceCert","privateKey"}}
 *                 Token, certificate and key are kept (key in encrypted NV
 *                 memory), so later connections skip the server.
 *   ROOTCA        root CA 1 (else 2) downloaded once and kept; with no URL
 *                 the public CA bundle is used.
 *   CONNECT       MQTT over TLS; on every (re)connection the module
 *                 subscribes to the Control topic and publishes A100.
 * A dropped connection reports DISCONNECT ERROR 2; esp-mqtt reconnects.
 *
 * Topics: <root>/{Conn|Event|Control|Lwt}/<group>/<model>/<clientId>
 * (<root> = Kconfig AT_MODEM_OTH_TOPIC_ROOT). Every message is
 *   {"header":{"deviceId":<clientId>,"sndDate":"yyyyMMddHHmmssSSS"},
 *    "values":{"apiNo","apiGroup","deviceGroup","modelId",...,"attributes"}}
 * A100/A102 go to Conn, the rest to Event; the LWT is A102 on Lwt.
 *
 * Inbound (Control topic, header.deviceId must be ours): the module itself
 * answers A502 (version request -> A500), runs A511/A531 (module firmware)
 * and A521 (MCU firmware) upgrades -- none of these reach the host. A001
 * (certificate renewal) and A101 (deregistration: A102, credentials and NV
 * memory erased, reboot) are acted on and also passed to the host. All
 * others arrive as AWS_RECV:<apiNo> <len> <attributes> (or the flat values
 * fields when there is no "attributes" object). */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mqtt_client.h"
#include "cJSON.h"

#include "at_commands.h"
#include "at_commands_oth.h"
#include "at_cmdset.h"
#include "at_response.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_uart.h"
#include "at_wifi.h"
#include "fs_store.h"
#include "oth_platform.h"
#include "sdkconfig.h"

static const char *TAG = "oth_aws";

#define ROOTCA_FILE "aws_rootca.pem"
#define CERT_FILE   "aws_cert.pem"
#define KEY_FILE    "aws_key.pem" /* holds a private key: kept in encrypted NV memory */

#define HTTP_MAX_BODY 8192

/* Appendix A */
#define E_MEM        1
#define E_RELEASED   2
#define E_CONFIG     3
#define E_AUTH_TO    100
#define E_AUTH_RESP  101
#define E_CERT_TO    111
#define E_CERT_FAIL  112
#define E_KEY_FAIL   115
#define E_CA_TO      117
#define E_CA_FAIL    118
#define E_MQTT_INIT  200
#define E_MQTT_CONN  201
#define E_MQTT_SUB   210
#define E_MQTT_PUB   211

typedef struct {
    char endpoint[128];
    uint16_t port;
    char auth[160];
    char ca1[192];
    char ca2[192];
    char region[8];
    char token[64];
    char model[17]; /* MIB 18 */
    char group[33]; /* MIB 19 */
    char mac[13];   /* station MAC, upper-case hex */
    char client_id[80];
} aws_conf_t;

static aws_conf_t s_c;
static char s_mcu_ver[16];
static char s_mcu_crc[12];
static bool s_mcu_changed;

static char s_t_conn[160], s_t_event[160], s_t_control[160], s_t_lwt[160];
static char *s_lwt_msg;

static esp_mqtt_client_handle_t s_client;
static char *s_ca_pem, *s_cert_pem, *s_key_pem;
static atomic_bool s_connected;
static TaskHandle_t s_task;

static void ind(const char *stage, int code)
{
    if (code) {
        at_event_post("AWS_IND:%s ERROR %d", stage, code);
    } else {
        at_event_post("AWS_IND:%s OK 0", stage);
    }
}

/* ---- settings ------------------------------------------------------------------ */

static void nv_str(const char *key, char *out, size_t cap)
{
    size_t len = cap;
    out[0] = '\0';
    if (m2m_nvs_get_str(key, out, &len) != ESP_OK) {
        out[0] = '\0';
    }
}

static void build_client_id(void)
{
    if (s_c.token[0]) {
        snprintf(s_c.client_id, sizeof(s_c.client_id), "%s_%s", s_c.mac, s_c.token);
    } else {
        strlcpy(s_c.client_id, s_c.mac, sizeof(s_c.client_id));
    }
}

static void build_topics(void)
{
    const char *r = CONFIG_AT_MODEM_OTH_TOPIC_ROOT;
    snprintf(s_t_conn, sizeof(s_t_conn), "%s/Conn/%s/%s/%s", r, s_c.group, s_c.model, s_c.client_id);
    snprintf(s_t_event, sizeof(s_t_event), "%s/Event/%s/%s/%s", r, s_c.group, s_c.model, s_c.client_id);
    snprintf(s_t_control, sizeof(s_t_control), "%s/Control/%s/%s/%s", r, s_c.group, s_c.model, s_c.client_id);
    snprintf(s_t_lwt, sizeof(s_t_lwt), "%s/Lwt/%s/%s/%s", r, s_c.group, s_c.model, s_c.client_id);
}

static void load_conf(void)
{
    nv_str("aws_ep", s_c.endpoint, sizeof(s_c.endpoint));
    s_c.port = 8883;
    m2m_nvs_get_u16("aws_port", &s_c.port);
    nv_str("aws_auth", s_c.auth, sizeof(s_c.auth));
    nv_str("aws_ca1", s_c.ca1, sizeof(s_c.ca1));
    nv_str("aws_ca2", s_c.ca2, sizeof(s_c.ca2));
    nv_str("aws_region", s_c.region, sizeof(s_c.region));
    nv_str("aws_token", s_c.token, sizeof(s_c.token));
    nv_str("c37", s_c.model, sizeof(s_c.model)); /* MIB 18 */
    nv_str("c38", s_c.group, sizeof(s_c.group)); /* MIB 19 */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_c.mac, sizeof(s_c.mac), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
    build_client_id();
    build_topics();
}

static void drop_credentials(void)
{
    m2m_nvs_set_str("aws_token", "");
    fs_store_remove(CERT_FILE);
    fs_store_remove(KEY_FILE);
}

void oth_aws_forget(void)
{
    drop_credentials();
    fs_store_remove(ROOTCA_FILE);
}

/* ---- message envelope ----------------------------------------------------------- */

/* values.apiGroup from the API number: A1xx connection 000, A5xx firmware
 * 005, status/sensor/error/parameter messages 001-004 by their third digit
 * (A11x/A21x 001 ... A14x/A24x 004). */
static const char *api_group(const char *api)
{
    static char g[4];
    if (strlen(api) < 4 || api[0] != 'A') {
        return "000";
    }
    if (api[1] == '5') {
        return "005";
    }
    if ((api[1] == '1' || api[1] == '2') && api[2] >= '1' && api[2] <= '4') {
        snprintf(g, sizeof(g), "00%c", api[2]);
        return g;
    }
    return "000";
}

static void snd_date(char *buf, size_t cap)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    snprintf(buf, cap, "%04d%02d%02d%02d%02d%02d%03d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

/* New message; *values receives the "values" object for extra fields. */
static cJSON *msg_new(const char *api, cJSON **values)
{
    char date[24];
    snd_date(date, sizeof(date));
    cJSON *root = cJSON_CreateObject();
    cJSON *h = cJSON_AddObjectToObject(root, "header");
    cJSON_AddStringToObject(h, "deviceId", s_c.client_id);
    cJSON_AddStringToObject(h, "sndDate", date);
    cJSON *v = cJSON_AddObjectToObject(root, "values");
    cJSON_AddStringToObject(v, "apiNo", api);
    cJSON_AddStringToObject(v, "apiGroup", api_group(api));
    cJSON_AddStringToObject(v, "deviceGroup", s_c.group);
    cJSON_AddStringToObject(v, "modelId", s_c.model);
    if (values) {
        *values = v;
    }
    return root;
}

/* Publishes (QoS 1) and frees msg; returns the message id or -1. */
static int msg_publish(cJSON *msg, const char *topic)
{
    char *s = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    int mid = -1;
    if (s && s_client && atomic_load(&s_connected)) {
        mid = esp_mqtt_client_publish(s_client, topic, s, 0, 1, 0);
    }
    cJSON_free(s);
    return mid;
}

static void add_versions(cJSON *values)
{
    char v01[12];
    snprintf(v01, sizeof(v01), "%d", oth_fota_wifi_version());
    cJSON *a = cJSON_AddObjectToObject(values, "attributes");
    cJSON_AddStringToObject(a, "V01", v01);
    cJSON_AddStringToObject(a, "V02", s_mcu_ver);
}

void oth_aws_publish_fw_progress(const char *api_no, const char *fw_cd, const char *err_cd, const char *fw_ver)
{
    cJSON *v;
    cJSON *m = msg_new(api_no, &v);
    cJSON_AddStringToObject(v, "fwCd", fw_cd);
    cJSON_AddStringToObject(v, "errCd", err_cd);
    cJSON *a = cJSON_AddObjectToObject(v, "attributes");
    cJSON_AddStringToObject(a, strcmp(api_no, "A520") == 0 ? "V02" : "V01", fw_ver ? fw_ver : "");
    msg_publish(m, s_t_event);
}

const char *oth_aws_mcu_version(void)
{
    return s_mcu_ver;
}

void oth_aws_note_mcu_updated(uint32_t crc)
{
    s_mcu_changed = true;
    snprintf(s_mcu_crc, sizeof(s_mcu_crc), "%lu", (unsigned long)crc);
}

/* ---- authentication server -------------------------------------------------------- */

/* GET url; *out gets the parsed "body" object's owner (caller deletes).
 * Returns 0, -1 (no answer) or -2 (error status / not the expected JSON). */
static int http_get_body(const char *url, cJSON **root_out, cJSON **body_out)
{
    *root_out = *body_out = NULL;
    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = 15000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t cl = esp_http_client_init(&cfg);
    if (!cl) {
        return -1;
    }
    int rc = -1;
    char *buf = NULL;
    if (esp_http_client_open(cl, 0) == ESP_OK) {
        esp_http_client_fetch_headers(cl);
        int status = esp_http_client_get_status_code(cl);
        buf = malloc(HTTP_MAX_BODY + 1);
        int n = 0;
        while (buf && n < HTTP_MAX_BODY) {
            int r = esp_http_client_read(cl, buf + n, HTTP_MAX_BODY - n);
            if (r <= 0) {
                break;
            }
            n += r;
        }
        rc = -2;
        if (buf && status == 200) {
            buf[n] = '\0';
            cJSON *root = cJSON_Parse(buf);
            cJSON *body = root ? cJSON_GetObjectItemCaseSensitive(root, "body") : NULL;
            if (cJSON_IsObject(body)) {
                *root_out = root;
                *body_out = body;
                rc = 0;
            } else {
                cJSON_Delete(root);
            }
        } else if (!buf) {
            rc = -1;
        }
        esp_http_client_close(cl);
    }
    esp_http_client_cleanup(cl);
    free(buf);
    return rc;
}

/* GET url -> body.deviceCert / body.privateKey, checked and stored.
 * Reports CERTIFICATE and PRIVATE_KEY; returns true when both are stored. */
static bool fetch_device_cert(const char *url)
{
    cJSON *root, *body;
    int rc = http_get_body(url, &root, &body);
    if (rc) {
        ind("CERTIFICATE", rc == -1 ? E_CERT_TO : E_CERT_FAIL);
        return false;
    }
    const cJSON *cert = cJSON_GetObjectItemCaseSensitive(body, "deviceCert");
    const cJSON *key = cJSON_GetObjectItemCaseSensitive(body, "privateKey");
    char why[48];
    bool ok = false;
    if (!cJSON_IsString(cert) ||
        !fs_store_check_pem_strength(cert->valuestring, strlen(cert->valuestring), why, sizeof(why)) ||
        !fs_store_write(CERT_FILE, cert->valuestring, strlen(cert->valuestring))) {
        ind("CERTIFICATE", E_CERT_FAIL);
    } else {
        ind("CERTIFICATE", 0);
        if (!cJSON_IsString(key) ||
            !fs_store_check_pem_strength(key->valuestring, strlen(key->valuestring), why, sizeof(why)) ||
            !fs_store_write(KEY_FILE, key->valuestring, strlen(key->valuestring))) {
            ind("PRIVATE_KEY", E_KEY_FAIL);
        } else {
            ind("PRIVATE_KEY", 0);
            ok = true;
        }
    }
    if (cJSON_IsString(key)) {
        memset(key->valuestring, 0, strlen(key->valuestring));
    }
    cJSON_Delete(root);
    return ok;
}

/* AUTHENTICATE, CERTIFICATE, PRIVATE_KEY -- from NV memory when this
 * module already holds a token, certificate and key. */
static bool obtain_credentials(void)
{
    if (s_c.token[0] && fs_store_exists(CERT_FILE) && fs_store_exists(KEY_FILE)) {
        ind("AUTHENTICATE", 0);
        ind("CERTIFICATE", 0);
        ind("PRIVATE_KEY", 0);
        return true;
    }
    if (!s_c.auth[0]) {
        ind("AUTHENTICATE", E_CONFIG);
        return false;
    }
    char url[320];
    snprintf(url, sizeof(url), "%s/register/token/%s", s_c.auth, s_c.mac);
    cJSON *root, *body;
    int rc = http_get_body(url, &root, &body);
    const cJSON *tok = rc ? NULL : cJSON_GetObjectItemCaseSensitive(body, "token");
    if (!cJSON_IsString(tok) || !tok->valuestring[0] || strlen(tok->valuestring) >= sizeof(s_c.token)) {
        cJSON_Delete(root);
        ind("AUTHENTICATE", rc == -1 ? E_AUTH_TO : E_AUTH_RESP);
        return false;
    }
    strlcpy(s_c.token, tok->valuestring, sizeof(s_c.token));
    cJSON_Delete(root);
    m2m_nvs_set_str("aws_token", s_c.token);
    build_client_id();
    build_topics();
    ind("AUTHENTICATE", 0);

    snprintf(url, sizeof(url), "%s/register/auth/%s/%s", s_c.auth, s_c.mac, s_c.token);
    return fetch_device_cert(url);
}

/* ---- root CA -------------------------------------------------------------------------- */

static int download_ca(const char *url)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = 15000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t cl = esp_http_client_init(&cfg);
    if (!cl) {
        return E_MEM;
    }
    int err = E_CA_TO;
    char *buf = NULL;
    if (esp_http_client_open(cl, 0) == ESP_OK) {
        esp_http_client_fetch_headers(cl);
        err = E_CA_FAIL;
        buf = malloc(HTTP_MAX_BODY + 1);
        int n = 0;
        while (buf && n < HTTP_MAX_BODY) {
            int r = esp_http_client_read(cl, buf + n, HTTP_MAX_BODY - n);
            if (r <= 0) {
                break;
            }
            n += r;
        }
        char why[48];
        if (buf && esp_http_client_get_status_code(cl) == 200) {
            buf[n] = '\0';
            if (strstr(buf, "-----BEGIN CERTIFICATE-----") &&
                fs_store_check_pem_strength(buf, (size_t)n, why, sizeof(why)) &&
                fs_store_write(ROOTCA_FILE, buf, (size_t)n)) {
                err = 0;
            }
        }
        esp_http_client_close(cl);
    }
    esp_http_client_cleanup(cl);
    free(buf);
    return err;
}

static int obtain_root_ca(void)
{
    if (!fs_store_exists(ROOTCA_FILE) && (s_c.ca1[0] || s_c.ca2[0])) {
        int err = s_c.ca1[0] ? download_ca(s_c.ca1) : E_CA_FAIL;
        if (err && s_c.ca2[0]) {
            err = download_ca(s_c.ca2);
        }
        if (err) {
            return err;
        }
    }
    s_ca_pem = fs_store_read_alloc(ROOTCA_FILE, NULL); /* NULL: public CA bundle */
    return 0;
}

/* ---- inbound messages --------------------------------------------------------------- */

static void to_host(const char *api, const char *json)
{
    if (!at_event_enabled()) {
        return;
    }
    char head[48];
    int n = snprintf(head, sizeof(head), AT_TAG "AWS_RECV:%s %d ", api, (int)strlen(json));
    at_uart_write_atomic2(head, (size_t)n, json, strlen(json));
    at_uart_write("\r\n", 2);
}

static void report_values(const char *api, cJSON *values)
{
    cJSON *attrs = cJSON_GetObjectItemCaseSensitive(values, "attributes");
    cJSON *flat = NULL;
    if (!attrs) {
        /* requests carry their fields directly under "values" */
        flat = cJSON_CreateObject();
        for (cJSON *it = values->child; it; it = it->next) {
            if (strcmp(it->string, "apiNo") && strcmp(it->string, "apiGroup") &&
                strcmp(it->string, "deviceGroup") && strcmp(it->string, "modelId")) {
                cJSON_AddItemToObject(flat, it->string, cJSON_Duplicate(it, true));
            }
        }
        attrs = flat;
    }
    char *s = cJSON_PrintUnformatted(attrs);
    if (s) {
        to_host(api, s);
        cJSON_free(s);
    }
    cJSON_Delete(flat);
}

static const char *jstr(const cJSON *obj, const char *name)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

static void pipeline_start(void);

/* A001: new certificate/key from <auth>/register/cert/renew/<clientId>,
 * optional new root CA URLs (values.caUrl array), then reconnect. */
static void renew_task(void *arg)
{
    char *ca = arg; /* "<url1>\n<url2>" or NULL */
    if (ca) {
        char *nl = strchr(ca, '\n');
        if (nl) {
            *nl = '\0';
            m2m_nvs_set_str("aws_ca2", nl + 1);
        }
        m2m_nvs_set_str("aws_ca1", ca);
        fs_store_remove(ROOTCA_FILE);
        free(ca);
    }
    if (s_c.auth[0]) {
        char url[320];
        snprintf(url, sizeof(url), "%s/register/cert/renew/%s", s_c.auth, s_c.client_id);
        if (fetch_device_cert(url)) {
            pipeline_start();
        }
    }
    vTaskDelete(NULL);
}

/* A101: deregistration -- A102, then credentials and NV memory erased
 * (FACRESET=0) and a reboot. */
static void deregister_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(3000));
    msg_publish(msg_new("A102", NULL), s_t_conn);
    vTaskDelay(pdMS_TO_TICKS(500));
    oth_aws_forget();
    at_sys_nv_erase();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

static void handle_inbound(const char *data, int len)
{
    cJSON *root = cJSON_ParseWithLength(data, (size_t)len);
    const cJSON *h = root ? cJSON_GetObjectItemCaseSensitive(root, "header") : NULL;
    const char *dev = h ? jstr(h, "deviceId") : NULL;
    cJSON *values = root ? cJSON_GetObjectItemCaseSensitive(root, "values") : NULL;
    const char *api = cJSON_IsObject(values) ? jstr(values, "apiNo") : NULL;
    if (!dev || strcmp(dev, s_c.client_id) != 0 || !api || strlen(api) > 8) {
        cJSON_Delete(root);
        return;
    }

    if (strcmp(api, "A502") == 0) {
        cJSON *v;
        cJSON *m = msg_new("A500", &v);
        add_versions(v);
        msg_publish(m, s_t_event);
    } else if (strcmp(api, "A511") == 0 || strcmp(api, "A531") == 0) {
        const char *ver = jstr(values, "wifiVer"), *url = jstr(values, "wifiUrl");
        const char *enc = jstr(values, "wifiEncUrl");
        if (ver && (url || enc)) {
            oth_fota_wifi_install(ver, url, enc, jstr(values, "wifiEncKey"), jstr(values, "wifiHash"));
        }
    } else if (strcmp(api, "A521") == 0) {
        const char *ver = jstr(values, "mcuVer"), *url = jstr(values, "mcuUrl");
        const char *enc = jstr(values, "mcuEncUrl");
        if (ver && (url || enc)) {
            oth_fota_mcu_install(ver, url, enc, jstr(values, "mcuEncKey"), jstr(values, "mcuHash"));
        }
    } else {
        report_values(api, values);
        if (strcmp(api, "A001") == 0) {
            const cJSON *arr = cJSON_GetObjectItemCaseSensitive(values, "caUrl");
            const cJSON *u1 = cJSON_IsArray(arr) ? cJSON_GetArrayItem(arr, 0) : NULL;
            const cJSON *u2 = cJSON_IsArray(arr) ? cJSON_GetArrayItem(arr, 1) : NULL;
            char *ca = NULL;
            if (cJSON_IsString(u1) && strlen(u1->valuestring) < sizeof(s_c.ca1)) {
                const char *s2 = cJSON_IsString(u2) && strlen(u2->valuestring) < sizeof(s_c.ca2)
                                     ? u2->valuestring : NULL;
                if (asprintf(&ca, s2 ? "%s\n%s" : "%s", u1->valuestring, s2) < 0) {
                    ca = NULL;
                }
            }
            if (xTaskCreate(renew_task, "oth_aws_renew", 6144, ca, 5, NULL) != pdPASS) {
                free(ca);
            }
        } else if (strcmp(api, "A101") == 0) {
            xTaskCreate(deregister_task, "oth_aws_dereg", 4096, NULL, 5, NULL);
        }
    }
    cJSON_Delete(root);
}

/* ---- MQTT connection ------------------------------------------------------------------ */

static void on_connected(void)
{
    if (esp_mqtt_client_subscribe(s_client, s_t_control, 1) < 0) {
        ind("CONNECT", E_MQTT_SUB);
        return;
    }
    cJSON *v;
    cJSON *m = msg_new("A100", &v);
    cJSON_AddStringToObject(v, "versionChangeW", oth_fota_take_version_changed() ? "true" : "false");
    cJSON_AddStringToObject(v, "versionChangeM", s_mcu_changed ? "true" : "false");
    s_mcu_changed = false;
    add_versions(v);
    ind("CONNECT", msg_publish(m, s_t_conn) < 0 ? E_MQTT_PUB : 0);
}

static char *s_rx_buf;
static int s_rx_len;

static void aws_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    (void)args;
    (void)base;
    esp_mqtt_event_handle_t ev = data;
    switch (id) {
    case MQTT_EVENT_CONNECTED:
        atomic_store(&s_connected, true);
        on_connected();
        break;
    case MQTT_EVENT_DISCONNECTED:
        if (atomic_exchange(&s_connected, false)) {
            ind("DISCONNECT", E_RELEASED);
        }
        break;
    case MQTT_EVENT_DATA:
        if (ev->current_data_offset == 0) {
            free(s_rx_buf);
            s_rx_buf = NULL;
            s_rx_len = 0;
            if (ev->data_len == ev->total_data_len) {
                handle_inbound(ev->data, ev->data_len);
                break;
            }
            s_rx_buf = ev->total_data_len <= HTTP_MAX_BODY ? malloc((size_t)ev->total_data_len) : NULL;
        }
        if (s_rx_buf && s_rx_len + ev->data_len <= ev->total_data_len) {
            memcpy(s_rx_buf + s_rx_len, ev->data, (size_t)ev->data_len);
            s_rx_len += ev->data_len;
            if (s_rx_len == ev->total_data_len) {
                handle_inbound(s_rx_buf, s_rx_len);
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
    free(s_ca_pem);
    free(s_cert_pem);
    free(s_key_pem);
    free(s_lwt_msg);
    s_ca_pem = s_cert_pem = s_key_pem = s_lwt_msg = NULL;
}

#define RETRY_US (60LL * 1000 * 1000)
static esp_timer_handle_t s_retry_timer;

static void pipeline_task(void *arg)
{
    (void)arg;
    bool retry = true;
    client_close();
    load_conf();
    int err = (!s_c.endpoint[0] || !s_c.model[0] || !s_c.group[0]) ? E_CONFIG : 0;
    ind("CONFIG", err);
    if (err) {
        retry = false; /* waits for the settings (SETMIB / pairing) */
        goto done;
    }
    at_sntp_ensure_synced(0); /* sndDate needs the clock: start syncing now */
    if (!obtain_credentials()) {
        goto done;
    }
    s_cert_pem = fs_store_read_alloc(CERT_FILE, NULL);
    s_key_pem = fs_store_read_alloc(KEY_FILE, NULL);
    if (!s_cert_pem || !s_key_pem) {
        ind("CONNECT", E_MEM);
        goto done;
    }
    err = obtain_root_ca();
    ind("ROOTCA", err);
    if (err) {
        goto done;
    }
    at_sntp_ensure_synced(5000);

    cJSON *lwt = msg_new("A102", NULL);
    s_lwt_msg = cJSON_PrintUnformatted(lwt);
    cJSON_Delete(lwt);

    esp_mqtt_client_config_t cfg = {0};
    cfg.broker.address.hostname = s_c.endpoint;
    cfg.broker.address.port = s_c.port;
    cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;
    if (s_ca_pem) {
        cfg.broker.verification.certificate = s_ca_pem;
    } else {
        cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    }
    static const char *alpn[] = { "x-amzn-mqtt-ca", NULL }; /* AWS IoT MQTT over port 443 */
    if (s_c.port == 443) {
        cfg.broker.verification.alpn_protos = alpn;
    }
    cfg.credentials.client_id = s_c.client_id;
    cfg.credentials.authentication.certificate = s_cert_pem;
    cfg.credentials.authentication.key = s_key_pem;
    cfg.session.last_will.topic = s_t_lwt;
    cfg.session.last_will.msg = s_lwt_msg;
    cfg.session.last_will.qos = 1;
    cfg.buffer.size = 2048;
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
    /* a server that did not answer is tried again a minute later while the
     * station stays connected (an established client reconnects itself) */
    if (!s_client && retry && s_retry_timer && at_wifi_sta_is_connected()) {
        esp_timer_start_once(s_retry_timer, RETRY_US);
    }
    s_task = NULL;
    vTaskDelete(NULL);
}

static bool paired(void)
{
    char ep[sizeof(s_c.endpoint)];
    nv_str("aws_ep", ep, sizeof(ep));
    return ep[0] != '\0';
}

static void retry_cb(void *arg)
{
    (void)arg;
    if (!s_client && at_wifi_sta_is_connected()) {
        pipeline_start();
    }
}

static void pipeline_start(void)
{
    if (!s_retry_timer) {
        const esp_timer_create_args_t t = { .callback = retry_cb, .name = "oth_aws_retry" };
        esp_timer_create(&t, &s_retry_timer);
    }
    esp_timer_stop(s_retry_timer);
    if (s_task || !paired()) {
        return; /* not paired: nothing to do */
    }
    if (xTaskCreate(pipeline_task, "oth_aws", 8192, NULL, 5, &s_task) != pdPASS) {
        s_task = NULL;
        ESP_LOGE(TAG, "no memory for the AWS task");
    }
}

/* Called on IPALLOCATED (cmd_wifi.c). */
void at_oth_aws_on_ip(void)
{
    if (!s_client) {
        pipeline_start();
    }
}

void oth_aws_set_server_info(const char *rootca1_url, const char *rootca2_url, const char *auth_url,
                             const char *endpoint, uint16_t port, uint8_t region)
{
    client_close();
    if (rootca1_url) {
        m2m_nvs_set_str("aws_ca1", rootca1_url);
    }
    if (rootca2_url) {
        m2m_nvs_set_str("aws_ca2", rootca2_url);
    }
    if (auth_url) {
        m2m_nvs_set_str("aws_auth", auth_url);
    }
    if (endpoint) {
        m2m_nvs_set_str("aws_ep", endpoint);
    }
    if (port) {
        m2m_nvs_set_u16("aws_port", port);
    }
    if (region) {
        char r[8];
        snprintf(r, sizeof(r), "%u", region); /* 1: Americas, 2: Europe, 3: Korea */
        m2m_nvs_set_str("aws_region", r);
    }
    oth_aws_forget(); /* a new server: authenticate again */
}

/* ---- commands ------------------------------------------------------------------------- */

/* AT*OTH*AWS_GET=<index> -- Section 2.1; "null" when not assigned. */
void cmd_oth_aws_get(const at_command_t *cmd)
{
    if (!s_task && !s_client) {
        load_conf(); /* else: the values the live connection uses */
    }
    char *end = NULL;
    long idx = cmd->argc >= 1 ? strtol(cmd->argv[0], &end, 10) : -1;
    if (cmd->argc < 1 || *end != '\0') {
        at_reply_error(cmd->name, -1);
        return;
    }
    char port[8];
    snprintf(port, sizeof(port), "%u", s_c.port);
    const char *v;
    switch (idx) {
    case 0:  v = s_c.endpoint; break;
    case 1:  v = s_c.endpoint[0] ? port : ""; break;
    case 2:  v = s_c.client_id; break;
    case 3:  v = s_c.auth; break;
    case 4:  v = s_c.ca1; break;
    case 5:  v = s_c.ca2; break;
    case 6:  v = s_c.region; break;
    case 7:  v = s_c.token; break;
    case 10: v = s_mcu_ver; break;
    case 11: v = s_mcu_crc; break;
    default:
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, "%s", v[0] ? v : "null");
}

/* AT*OTH*AWS_SET=<index> <value> -- writes AWS_GET 0/1/3-7 (development
 * use; normally provisioned by pairing); "null" clears a value (port: back
 * to 8883). Changing the authentication server
 * or token drops the stored credentials, a root CA URL the stored root CA;
 * applies on the next connection (AWS_SEND=A100 or the next IP address). */
void cmd_oth_aws_set(const at_command_t *cmd)
{
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, -1);
        return;
    }
    char *end = NULL;
    long idx = strtol(cmd->argv[0], &end, 10);
    const char *v = cmd->argv[1];
    if (strcmp(v, "null") == 0) {
        v = idx == 1 ? "8883" : "";
    }
    size_t len = strlen(v);
    if (*end != '\0') {
        at_reply_error(cmd->name, -1);
        return;
    }
    switch (idx) {
    case 0:
        if (len >= sizeof(s_c.endpoint)) goto bad;
        m2m_nvs_set_str("aws_ep", v);
        break;
    case 1: {
        long p = strtol(v, &end, 10);
        if (*end != '\0' || p < 1 || p > 65535) goto bad;
        m2m_nvs_set_u16("aws_port", (uint16_t)p);
        break;
    }
    case 3:
        if (len >= sizeof(s_c.auth)) goto bad;
        m2m_nvs_set_str("aws_auth", v);
        drop_credentials();
        break;
    case 4: case 5:
        if (len >= sizeof(s_c.ca1)) goto bad;
        m2m_nvs_set_str(idx == 4 ? "aws_ca1" : "aws_ca2", v);
        fs_store_remove(ROOTCA_FILE);
        break;
    case 6:
        if (len >= sizeof(s_c.region)) goto bad;
        m2m_nvs_set_str("aws_region", v);
        break;
    case 7:
        if (len >= sizeof(s_c.token)) goto bad;
        drop_credentials();
        m2m_nvs_set_str("aws_token", v);
        break;
    default:
        goto bad;
    }
    if (!s_task && !s_client) {
        load_conf(); /* else: the values the live connection uses */
    }
    at_reply_ok(cmd->name, NULL);
    return;
bad:
    at_reply_error(cmd->name, -1);
}

/* AT*OTH*MCU_READY=<version> -- the host reports its firmware version after
 * every DEVICEREADY (AWS_GET 10, A100/A500 V02, pairing device info). */
void cmd_oth_mcu_ready(const at_command_t *cmd)
{
    if (cmd->argc < 1 || strlen(cmd->argv[0]) >= sizeof(s_mcu_ver)) {
        at_reply_error(cmd->name, -1);
        return;
    }
    strlcpy(s_mcu_ver, cmd->argv[0], sizeof(s_mcu_ver));
    at_reply_ok(cmd->name, NULL);
}

/* AT*OTH*AWS_SEND=<apiNo> <attribute> -- raw: the JSON may contain spaces.
 * The attribute JSON goes into the message envelope as values.attributes;
 * A100 (connection request) restarts the pipeline instead. */
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
    if (!p || p == api || p - api > 8) {
        at_reply_error(cmd->name, -1);
        return;
    }
    if (*p) {
        *p++ = '\0';
    }
    if (strcmp(api, "A100") == 0) {
        at_reply_ok(cmd->name, NULL);
        client_close();
        pipeline_start();
        return;
    }
    while (*p == ' ') {
        p++;
    }
    cJSON *attrs = cJSON_Parse(*p ? p : "{}");
    if (!cJSON_IsObject(attrs)) {
        cJSON_Delete(attrs);
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    if (!atomic_load(&s_connected)) {
        cJSON_Delete(attrs);
        at_event_post("AWS_IND:SEND ERROR %d", E_RELEASED);
        return;
    }
    cJSON *v;
    cJSON *m = msg_new(api, &v);
    cJSON_AddItemToObject(v, "attributes", attrs);
    bool conn = strcmp(api, "A102") == 0;
    if (msg_publish(m, conn ? s_t_conn : s_t_event) < 0) {
        at_event_post("AWS_IND:SEND ERROR %d", E_MQTT_PUB);
    } else {
        at_event_post("AWS_IND:SEND OK"); /* as the guide's examples show */
    }
}
