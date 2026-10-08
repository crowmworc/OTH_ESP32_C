/* AT*M2M*AWS_* -- AWS IoT Core client (doc Ch.6.5), on esp-mqtt + AWS IoT's
 * standard Fleet Provisioning by Claim topics.
 *
 * Two provisioning paths exist in the doc: AT*M2M*AWS_PAIR (a custom
 * "provisioning service" -- its actual HTTP protocol, request/response
 * shapes, and auth are never specified anywhere in the doc, so it can't be
 * implemented against anything real) and AT*M2M*AWS_CLAIMCERT +
 * AT*M2M*AWS_PROVISION (AWS IoT's own Fleet Provisioning by Claim, fully
 * specified via its documented $aws/certificates/create and
 * $aws/provisioning-templates/... MQTT topics -- a standard AWS service,
 * not something to invent). This file implements the latter fully;
 * AT*M2M*AWS_PAIR is a stub that reports "never paired" / errors on Set.
 *
 * [2026-09-14] Decided rather than pending: AT*M2M*AWS_PAIR (and
 * AT*M2M*AWS_CERT's op=FETCH, which depends on it) is deprecated in favor
 * of Fleet Provisioning by Claim, not implemented -- see the "Note
 * (deprecated)" callouts added to both commands in M2M-AT Command Set.docx
 * v1.3. The stub stays as-is (reporting an honest "not paired" rather than
 * being removed), since the doc still defines the command and some caller
 * out there may still probe it expecting a defined response shape rather
 * than an unknown-command error.
 *
 * Doc gap handled by design decision: AT*M2M*AWS_PROVISION needs to know
 * the AWS IoT account endpoint to open the claim-cert MQTT connection, but
 * its own signature (<link_id> <template_name> [parameters_json]) has no
 * room for one, and it's a fixed per-account value (identical for every
 * device in a fleet), not something negotiated per-command. Stored via
 * AT*M2M*SYS_CONF index 10 (see cmd_sys.c) rather than inventing a new
 * command or silently repurposing AT*M2M*MQTT_CONF. AT*M2M*AWS_CONN reads
 * the same stored endpoint once a certificate is provisioned.
 *
 * AWS's own server certs (Amazon Trust Services / Starfield roots) are
 * already covered by the public CA bundle already enabled for HTTP/MQTT
 * (Phase 3/4), so ongoing AT*M2M*AWS_CONN connections verify the broker
 * via esp_crt_bundle_attach() like everything else -- only the one-time
 * claim connection in AT*M2M*AWS_PROVISION uses the CA file from
 * AT*M2M*AWS_CLAIMCERT explicitly, matching the doc's own file reference.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_event.h"
#include "esp_crt_bundle.h"
#include "mqtt_client.h"
#include "mqtt_rx.h"
#include "cJSON.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "at_uart.h"
#include "at_nvs_kv.h"
#include "fs_store.h"

#define AWS_MAX_LINKS  4
#define AWS_MAX_SUBS   10
#define AWS_CERT_FILE  "aws_cert.pem" /* fixed SPIFFS filenames -- doc gives */
#define AWS_KEY_FILE   "aws_key.pem"  /* AWS_PROVISION no filename params, unlike NET_HTTPDOWNLOAD */

typedef struct {
    bool used;
    char topic[128];
    int qos;
} aws_sub_t;

typedef struct {
    esp_mqtt_client_handle_t client;
    atomic_bool clean_requested;
    aws_sub_t subs[AWS_MAX_SUBS];
    /* All three heap-owned; NULL when unused. esp-mqtt keeps these as raw
     * pointers in its client config and re-reads them on every reconnect
     * (it never copies the string), so they must outlive the client --
     * freed alongside it (cmd_aws_disc() below, provision_worker()'s
     * failure paths), not right after connect. ca_pem stays NULL for a
     * cmd_aws_conn() link (built-in CA bundle); only a kept-alive
     * provisioning client (see provision_worker()) sets it. */
    char *ca_pem;
    char *cert_pem;
    char *key_pem;
} aws_link_t;

static aws_link_t s_links[AWS_MAX_LINKS];
static mqtt_rx_t s_rx[AWS_MAX_LINKS]; /* incoming-message reassembly, see mqtt_rx.h */

/* AT*M2M*AWS_CLAIMCERT state */
static struct {
    bool configured;
    char ca[32];
    char cert[32];
    char key[32];
} s_claimcert;

/* AT*M2M*AWS_CERT state -- one global identity, not per-link (the doc's
 * Query form takes no link_id: there's one AWS IoT "Thing" certificate,
 * used to open however many of the 4 links are wanted). */
static struct {
    int state; /* 0 none,1 present,2 expiring (unused -- see cmd_aws_cert) */
    char thing_name[65];
    char endpoint[128];
} s_aws;

static TaskHandle_t s_provision_task;

/* ---- AT*M2M*AWS_CLAIMCERT ------------------------------------------- */

void cmd_aws_claimcert(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        if (!s_claimcert.configured) {
            at_reply_error(cmd->name, AT_ERR_STATE);
            return;
        }
        at_reply_ok(cmd->name, "\"%s\" \"%s\" \"%s\"", s_claimcert.ca, s_claimcert.cert, s_claimcert.key);
        return;
    }
    if (cmd->argc < 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (!fs_store_exists(cmd->argv[0]) || !fs_store_exists(cmd->argv[1]) || !fs_store_exists(cmd->argv[2])) {
        at_reply_error(cmd->name, 1); /* doc: 1-referenced file not found on the module */
        return;
    }
    strlcpy(s_claimcert.ca, cmd->argv[0], sizeof(s_claimcert.ca));
    strlcpy(s_claimcert.cert, cmd->argv[1], sizeof(s_claimcert.cert));
    strlcpy(s_claimcert.key, cmd->argv[2], sizeof(s_claimcert.key));
    s_claimcert.configured = true;
    at_reply_ok(cmd->name, NULL);
}

/* ---- AT*M2M*AWS_PAIR (stub, see file header) ------------------------- */

void cmd_aws_pair(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        at_reply_ok(cmd->name, "0 \"\""); /* always "not paired" -- this path isn't implemented */
        return;
    }
    at_reply_error(cmd->name, 2); /* doc: 2-could not reach the pairing server (closest fit: none exists yet) */
}

/* ---- AT*M2M*AWS_PROVISION -------------------------------------------- */

/* Sized to the actual file content rather than a fixed worst-case buffer --
 * for the cert/key material a live MQTT client keeps a raw pointer to for as
 * long as it's connected (see aws_link_t's own comment). Caller owns the
 * result. */
static char *load_file_alloc(const char *filename)
{
    return fs_store_read_alloc(filename, NULL);
}

/* The device private key lands in encrypted NVS (fs_store routes any
 * "PRIVATE KEY" content there). */
static bool save_file(const char *filename, const char *data)
{
    return fs_store_write(filename, data, strlen(data));
}

/* Hands MQTT_EVENT_CONNECTED/DATA off to the blocked provision_worker task
 * via two binary semaphores -- one message exchange (subscribe, publish,
 * wait for the accepted/rejected reply) at a time, so no queueing needed.
 *
 * AWS's create/json response bundles a cert PEM + private key PEM + an
 * ownership token into one JSON object, escaped (each "\n" becomes two
 * bytes) -- easily 3-4KB, well past esp-mqtt's per-chunk MQTT_EVENT_DATA
 * size, so it always arrives split across multiple fragments (only the
 * first of which carries topic_len > 0, same convention cmd_mqtt.c's
 * MQTT_RECV:IND relies on). This handler used to only capture that first
 * fragment and signal done immediately, silently handing the worker a
 * truncated JSON payload that failed to parse -- reported to the host as
 * a misleading "request rejected" (ERROR 3) instead of a size problem. */
typedef struct {
    SemaphoreHandle_t connected_sem;
    SemaphoreHandle_t msg_sem;
    char topic[160];
    char payload[6144];
    int payload_len;
} provision_ctx_t;

static void provision_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    (void)base;
    provision_ctx_t *ctx = handler_args;
    esp_mqtt_event_handle_t event = event_data;

    if (event_id == MQTT_EVENT_CONNECTED) {
        xSemaphoreGive(ctx->connected_sem);
    } else if (event_id == MQTT_EVENT_DATA) {
        if (event->topic_len > 0) {
            int tlen = event->topic_len < (int)sizeof(ctx->topic) - 1 ? event->topic_len : (int)sizeof(ctx->topic) - 1;
            memcpy(ctx->topic, event->topic, (size_t)tlen);
            ctx->topic[tlen] = '\0';
            ctx->payload_len = 0;
        }
        int room = (int)sizeof(ctx->payload) - 1 - ctx->payload_len;
        int dlen = event->data_len < room ? event->data_len : room;
        if (dlen > 0) {
            memcpy(ctx->payload + ctx->payload_len, event->data, (size_t)dlen);
            ctx->payload_len += dlen;
        }
        ctx->payload[ctx->payload_len] = '\0';
        if (event->current_data_offset + event->data_len >= event->total_data_len) {
            xSemaphoreGive(ctx->msg_sem); /* last (or only) fragment of this message */
        }
    }
}

typedef struct {
    int link_id;
    char template_name[65];
    char parameters_json[256];
} provision_job_t;

/* Forward-declared: defined further down with cmd_aws_conn(), but
 * provision_worker() (below) needs to hand a just-provisioned link over to
 * it -- see the success path's comment for why. */
static void aws_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);

static void provision_worker(void *arg)
{
    provision_job_t *job = arg;
    esp_mqtt_client_handle_t client = NULL;
    provision_ctx_t ctx = {0};
    ctx.connected_sem = xSemaphoreCreateBinary();
    ctx.msg_sem = xSemaphoreCreateBinary();

    /* Heap-allocated (not this file's old fixed 2200-byte statics) so the
     * claim identity only costs RAM while a provisioning attempt (or the
     * client it hands off to a link on success -- see below) is actually
     * using it. Freed on every failure path below; on success, ownership
     * transfers into s_links[job->link_id] instead of being freed here. */
    char *ca_pem = NULL, *claim_cert_pem = NULL, *claim_key_pem = NULL;
    char *new_cert_pem = NULL, *new_key_pem = NULL; /* transient: saved to
        SPIFFS below then freed -- never referenced by a live client. */

    if (!s_claimcert.configured ||
        !(ca_pem = load_file_alloc(s_claimcert.ca)) ||
        !(claim_cert_pem = load_file_alloc(s_claimcert.cert)) ||
        !(claim_key_pem = load_file_alloc(s_claimcert.key))) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 1); /* doc: 1-AWS_CLAIMCERT not configured */
        goto done;
    }

    char endpoint[128] = "";
    size_t elen = sizeof(endpoint);
    m2m_nvs_get_str("c10", endpoint, &elen); /* SYS_CONF index 10, see cmd_sys.c */
    if (!endpoint[0]) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 1);
        goto done;
    }

    at_event_post("AWS_PROVISION:IND CONNECTING %d", job->link_id);

    esp_mqtt_client_config_t config = {0};
    config.broker.address.hostname = endpoint;
    config.broker.address.port = 8883;
    config.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;
    config.broker.verification.certificate = ca_pem;
    config.credentials.client_id = "m2m-fleet-provision";
    config.credentials.authentication.certificate = claim_cert_pem;
    config.credentials.authentication.key = claim_key_pem;

    client = esp_mqtt_client_init(&config);
    if (!client) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 2);
        goto done;
    }
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, provision_event_handler, &ctx);
    if (esp_mqtt_client_start(client) != ESP_OK ||
        xSemaphoreTake(ctx.connected_sem, pdMS_TO_TICKS(15000)) != pdTRUE) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 2); /* doc: 2-TLS handshake with the claim cert failed */
        goto stop_client;
    }

    at_event_post("AWS_PROVISION:IND REQUESTING_CERT %d", job->link_id);
    esp_mqtt_client_subscribe(client, "$aws/certificates/create/json/accepted", 1);
    esp_mqtt_client_subscribe(client, "$aws/certificates/create/json/rejected", 1);
    esp_mqtt_client_publish(client, "$aws/certificates/create/json", "{}", 2, 1, 0);

    if (xSemaphoreTake(ctx.msg_sem, pdMS_TO_TICKS(15000)) != pdTRUE || strstr(ctx.topic, "rejected")) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 3); /* doc: 3-certificate request rejected */
        goto stop_client;
    }

    /* 600, not 300: certificateOwnershipToken is an opaque encrypted blob
     * whose length scales with the cert's key size -- observed 464 chars
     * for a 2048-bit RSA cert. A truncated token still round-trips through
     * every JSON parse/serialize step below without any error, so it was
     * silently corrupted and AWS legitimately rejected it at the
     * provisioning-template step (surfaced here as ERROR 4, which reads
     * like a template/permissions problem but wasn't one). */
    char token[600] = "";
    {
        cJSON *root = cJSON_Parse(ctx.payload);
        if (!root) {
            at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 3);
            goto stop_client;
        }
        const cJSON *cert_j = cJSON_GetObjectItem(root, "certificatePem");
        const cJSON *key_j = cJSON_GetObjectItem(root, "privateKey");
        const cJSON *token_j = cJSON_GetObjectItem(root, "certificateOwnershipToken");
        if (!cJSON_IsString(cert_j) || !cJSON_IsString(key_j) || !cJSON_IsString(token_j)) {
            cJSON_Delete(root);
            at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 3);
            goto stop_client;
        }
        new_cert_pem = strdup(cert_j->valuestring);
        new_key_pem = strdup(key_j->valuestring);
        strlcpy(token, token_j->valuestring, sizeof(token));
        cJSON_Delete(root);
        if (!new_cert_pem || !new_key_pem) {
            at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 3);
            goto stop_client;
        }
    }

    at_event_post("AWS_PROVISION:IND REGISTERING %d", job->link_id);
    char topic_accepted[160], topic_rejected[160], topic_provision[160];
    snprintf(topic_accepted, sizeof(topic_accepted), "$aws/provisioning-templates/%s/provision/json/accepted", job->template_name);
    snprintf(topic_rejected, sizeof(topic_rejected), "$aws/provisioning-templates/%s/provision/json/rejected", job->template_name);
    snprintf(topic_provision, sizeof(topic_provision), "$aws/provisioning-templates/%s/provision/json", job->template_name);
    esp_mqtt_client_subscribe(client, topic_accepted, 1);
    esp_mqtt_client_subscribe(client, topic_rejected, 1);

    {
        cJSON *body = cJSON_CreateObject();
        cJSON_AddStringToObject(body, "certificateOwnershipToken", token);
        cJSON *params = job->parameters_json[0] ? cJSON_Parse(job->parameters_json) : NULL;
        cJSON_AddItemToObject(body, "parameters", params ? params : cJSON_CreateObject());
        char *body_str = cJSON_PrintUnformatted(body);
        esp_mqtt_client_publish(client, topic_provision, body_str, 0, 1, 0);
        free(body_str);
        cJSON_Delete(body);
    }

    if (xSemaphoreTake(ctx.msg_sem, pdMS_TO_TICKS(15000)) != pdTRUE || strstr(ctx.topic, "rejected")) {
        at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 4); /* doc: 4-template rejected or parameters invalid */
        goto stop_client;
    }

    {
        cJSON *root = cJSON_Parse(ctx.payload);
        const cJSON *thing_j = root ? cJSON_GetObjectItem(root, "thingName") : NULL;
        if (!cJSON_IsString(thing_j)) {
            if (root) {
                cJSON_Delete(root);
            }
            at_event_post("AWS_PROVISION:ERROR %d %d", job->link_id, 4);
            goto stop_client;
        }
        strlcpy(s_aws.thing_name, thing_j->valuestring, sizeof(s_aws.thing_name));
        cJSON_Delete(root);
    }

    save_file(AWS_CERT_FILE, new_cert_pem);
    save_file(AWS_KEY_FILE, new_key_pem);
    free(new_cert_pem);
    free(new_key_pem);
    strlcpy(s_aws.endpoint, endpoint, sizeof(s_aws.endpoint));
    s_aws.state = 1;

    /* Doc: "the link stays connected under the permanent identity" -- keep
     * this same MQTT connection (now holding a real, permanent AWS IoT
     * certificate) as job->link_id's active AWS link, rather than
     * disconnecting and making the host reconnect via AWS_CONN.
     *
     * This used to just store `client` into s_links[] and fall through to
     * deleting ctx/its semaphores and this task -- leaving
     * provision_event_handler() (registered above with &ctx as its
     * handler_args) as the client's ONLY event handler indefinitely. Since
     * this client is deliberately kept alive past this task's lifetime, any
     * later MQTT event on it (an AWS_SUB delivery, a disconnect, ...) would
     * have called back into a deleted task's stack and given already-
     * deleted semaphores -- a real use-after-free, and it also meant
     * cmd_aws_pub()/cmd_aws_sub() traffic on this link would never actually
     * produce the AWS_MSG:DONE/AWS_CONN:ERROR notifications, since only
     * aws_event_handler() (cmd_aws_conn()'s handler) posts those. Every
     * hardware verification of AWS_PUB/AWS_SUB on record used a separate,
     * fresh AT*M2M*AWS_CONN with the new device certificate instead of this
     * path, so this bug was never actually exercised. Fixed by swapping in
     * the same handler cmd_aws_conn() uses before this task (and ctx) goes
     * away, so this link behaves identically to one opened via AWS_CONN. */
    esp_mqtt_client_unregister_event(client, ESP_EVENT_ANY_ID, provision_event_handler);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, aws_event_handler, (void *)(intptr_t)job->link_id);
    s_links[job->link_id].client = client;
    /* ca_pem/claim_cert_pem/claim_key_pem ownership transfers to the link --
     * this client keeps using them (see aws_link_t's comment) -- freed later
     * by cmd_aws_disc(), not here. */
    s_links[job->link_id].ca_pem = ca_pem;
    s_links[job->link_id].cert_pem = claim_cert_pem;
    s_links[job->link_id].key_pem = claim_key_pem;
    at_event_post("AWS_PROVISION:DONE %d \"%s\"", job->link_id, s_aws.thing_name);
    vSemaphoreDelete(ctx.connected_sem);
    vSemaphoreDelete(ctx.msg_sem);
    free(job);
    s_provision_task = NULL;
    vTaskDelete(NULL);
    return;

stop_client:
    esp_mqtt_client_stop(client);
    esp_mqtt_client_destroy(client);
done:
    /* Every path reaching here is a failure before (or instead of) the
     * success path's ownership transfer above, so these are all still ours
     * to free (free(NULL) is a no-op for whichever weren't allocated yet). */
    free(ca_pem);
    free(claim_cert_pem);
    free(claim_key_pem);
    free(new_cert_pem);
    free(new_key_pem);
    vSemaphoreDelete(ctx.connected_sem);
    vSemaphoreDelete(ctx.msg_sem);
    free(job);
    s_provision_task = NULL;
    vTaskDelete(NULL);
}

/* AT*M2M*AWS_PROVISION=<link_id> <template_name> [parameters_json] */
void cmd_aws_provision(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        /* doc: 0-not provisioned, 1-provisioning in progress, 2-provisioned */
        at_reply_ok(cmd->name, "%d", s_aws.state == 1 ? 2 : (s_provision_task ? 1 : 0));
        return;
    }
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= AWS_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (s_links[link_id].client) {
        at_reply_error(cmd->name, 5); /* doc: 5-<link_id> already connected */
        return;
    }
    if (s_provision_task) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }

    provision_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    job->link_id = link_id;
    strlcpy(job->template_name, cmd->argv[1], sizeof(job->template_name));
    if (cmd->argc >= 3) {
        strlcpy(job->parameters_json, cmd->argv[2], sizeof(job->parameters_json));
    }

    /* 16384, not 8192: provision_ctx_t's payload buffer alone is 6144 bytes
     * (see provision_event_handler) and lives on this task's stack as a
     * local -- 8192 wasn't enough headroom for that plus the function's
     * other locals and call frames, and crashed with a stack protection
     * fault the first time this path actually ran end to end. */
    if (xTaskCreate(provision_worker, "aws_provision", 16384, job, 5, &s_provision_task) != pdPASS) {
        free(job);
        s_provision_task = NULL;
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* ---- AT*M2M*AWS_CERT --------------------------------------------------
 * op=FETCH belongs to the AT*M2M*AWS_PAIR custom-pairing path (not
 * implemented, see above) -- since a device only ever gets here via
 * AWS_PROVISION in this implementation, FETCH always reports "not paired
 * yet", which is honestly what's true. */
void cmd_aws_cert(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        at_reply_ok(cmd->name, "%d \"%s\" \"%s\" %d", s_aws.state, s_aws.thing_name, s_aws.endpoint, 0);
        return;
    }
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        fs_store_remove(AWS_CERT_FILE);
        fs_store_remove(AWS_KEY_FILE);
        s_aws.state = 0;
        s_aws.thing_name[0] = '\0';
        s_aws.endpoint[0] = '\0';
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (strcasecmp(cmd->argv[0], "FETCH") == 0) {
        at_reply_error(cmd->name, 1); /* doc: 1-not paired yet -- run AT*M2M*AWS_PAIR first */
        return;
    }
    at_reply_error(cmd->name, AT_ERR_ARG);
}

/* ---- AT*M2M*AWS_CONN/DISC/PUB/SUB -------------------------------------
 * All operate on the certificate provisioned above; server verification
 * uses the public CA bundle (AWS's ATS roots are in it, same as Phase 3/4)
 * rather than a separately-stored CA, since AWS_CLAIMCERT's CA is only for
 * the one-time claim connection. */

static void aws_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    (void)base;
    int link_id = (int)(intptr_t)handler_args;
    esp_mqtt_event_handle_t event = event_data;

    switch (event_id) {
    case MQTT_EVENT_CONNECTED:
        at_event_post("AWS_CONN:DONE %d", link_id);
        break;
    case MQTT_EVENT_ERROR: {
        /* doc: 10-TLS handshake failed, 11-MQTT CONNACK rejected */
        int reason = (event->error_handle &&
                      event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED)
                         ? 11 : 10;
        at_event_post("AWS_CONN:ERROR %d %d", link_id, reason);
        break;
    }
    case MQTT_EVENT_DATA: {
        /* Doc's AWS_MSG example puts the payload on its own line after the
         * DONE header, like NET_RECV/MQTT_RECV -- raw bytes, not
         * byte-stuffed. A fragmented message is collected whole first
         * (mqtt_rx.c); one over MQTT_RX_MAX is reported as AWS_MSG:ERROR. */
        mqtt_rx_t *rx = &s_rx[link_id];
        mqtt_rx_result_t r = mqtt_rx_feed(rx, event);
        if (r == MQTT_RX_TOO_BIG) {
            at_event_post("AWS_MSG:ERROR %d \"%s\" %u", link_id, rx->topic, (unsigned)rx->total);
        } else if (r == MQTT_RX_DONE) {
            char header[200];
            int hlen = snprintf(header, sizeof(header), AT_TAG "AWS_MSG:DONE %d \"%s\" %u\r\n",
                                 link_id, rx->topic, (unsigned)rx->len);
            if (hlen > 0 && (size_t)hlen < sizeof(header)) {
                at_uart_write_atomic2(header, (size_t)hlen, (const char *)rx->data, rx->len);
            }
            mqtt_rx_reset(rx);
        }
        break;
    }
    default:
        break;
    }
}

/* AT*M2M*AWS_CONN=<link_id> [port_mode] */
void cmd_aws_conn(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= AWS_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (s_links[link_id].client) {
        at_reply_error(cmd->name, 12); /* doc: 12-<link_id> already connected */
        return;
    }
    if (s_aws.state != 1) {
        at_reply_error(cmd->name, 1); /* doc: 1-not paired yet -- here: no certificate provisioned yet */
        return;
    }

    char *cert_pem = load_file_alloc(AWS_CERT_FILE);
    char *key_pem = load_file_alloc(AWS_KEY_FILE);
    if (!cert_pem || !key_pem) {
        free(cert_pem);
        free(key_pem);
        at_reply_error(cmd->name, 5); /* doc: 5-local storage error */
        return;
    }

    int port_mode = (cmd->argc >= 2) ? atoi(cmd->argv[1]) : 0;
    static const char *k_alpn[] = {"x-amzn-mqtt-ca", NULL};

    esp_mqtt_client_config_t config = {0};
    config.broker.address.hostname = s_aws.endpoint;
    config.broker.address.port = (port_mode == 1) ? 443 : 8883;
    config.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;
    config.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    if (port_mode == 1) {
        config.broker.verification.alpn_protos = k_alpn;
    }
    config.credentials.client_id = s_aws.thing_name;
    config.credentials.authentication.certificate = cert_pem;
    config.credentials.authentication.key = key_pem;

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&config);
    if (!client) {
        free(cert_pem);
        free(key_pem);
        at_reply_error(cmd->name, 10);
        return;
    }
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, aws_event_handler, (void *)(intptr_t)link_id);
    atomic_store(&s_links[link_id].clean_requested, false);

    if (esp_mqtt_client_start(client) != ESP_OK) {
        esp_mqtt_client_destroy(client);
        free(cert_pem);
        free(key_pem);
        at_reply_error(cmd->name, 10);
        return;
    }
    s_links[link_id].client = client;
    s_links[link_id].cert_pem = cert_pem; /* freed by cmd_aws_disc() -- see aws_link_t's comment */
    s_links[link_id].key_pem = key_pem;
    at_reply_ok(cmd->name, NULL);
    /* AWS_CONN:DONE follows asynchronously from aws_event_handler(). */
}

/* AT*M2M*AWS_DISC=<link_id> */
void cmd_aws_disc(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= AWS_MAX_LINKS || !s_links[link_id].client) {
        at_reply_error(cmd->name, 1); /* doc: 1-<link_id> not connected */
        return;
    }
    atomic_store(&s_links[link_id].clean_requested, true);
    esp_mqtt_client_stop(s_links[link_id].client);
    esp_mqtt_client_destroy(s_links[link_id].client);
    s_links[link_id].client = NULL;
    free(s_links[link_id].ca_pem);
    free(s_links[link_id].cert_pem);
    free(s_links[link_id].key_pem);
    s_links[link_id].ca_pem = s_links[link_id].cert_pem = s_links[link_id].key_pem = NULL;
    memset(s_links[link_id].subs, 0, sizeof(s_links[link_id].subs));
    at_reply_ok(cmd->name, NULL);
    at_event_post("AWS_DISC:DONE %d", link_id);
}

/* AT*M2M*AWS_PUB=<link_id> <topic> <qos> <retain> <data_len>, followed by
 * the raw payload as a separate write once the module echoes "> " (doc's
 * own worked example, distinct from every other command's single-line
 * shape) -- see at_uart_read_raw(). */
void cmd_aws_pub(const at_command_t *cmd)
{
    if (cmd->argc < 5) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    const char *topic = cmd->argv[1];
    int qos = atoi(cmd->argv[2]);
    int retain = atoi(cmd->argv[3]);
    long data_len = atol(cmd->argv[4]);
    if (link_id < 0 || link_id >= AWS_MAX_LINKS || qos < 0 || qos > 1 || retain != 0) {
        at_reply_error(cmd->name, 2); /* doc: 2-qos=2 or retain=1 requested (folded into general arg check) */
        return;
    }
    if (data_len < 0 || data_len > 8192) {
        at_reply_error(cmd->name, 3); /* doc: 3-<data_len> too large (also covers the negative-length case) */
        return;
    }
    if (!s_links[link_id].client) {
        at_reply_error(cmd->name, 1); /* doc: 1-not connected */
        return;
    }

    at_uart_write_str(AT_TAG "AWS_PUB:OK\r\n> ");

    static uint8_t buf[8192];
    if (!at_uart_read_raw(buf, (size_t)data_len, 10000)) {
        return; /* doc defines no specific error for a payload timeout; OK was already sent */
    }

    int msg_id = esp_mqtt_client_publish(s_links[link_id].client, topic, (const char *)buf, (int)data_len, qos, 0);
    if (qos >= 1) {
        if (msg_id >= 0) {
            at_event_post("AWS_PUB:DONE %d", link_id);
        } else {
            at_event_post("AWS_PUB:ERROR %d", AT_ERR_GENERIC);
        }
    }
}

/* AT*M2M*AWS_SUB -- doc's Query is glued "=?<link_id>" (no space, unlike
 * every other Query in this doc); Set: <link_id> <topic> <qos>, or
 * "DEL <link_id> <topic>" to unsubscribe. */
void cmd_aws_sub(const at_command_t *cmd)
{
    if (cmd->argc >= 1 && cmd->argv[0][0] == '?') {
        int link_id = cmd->argv[0][1] ? atoi(cmd->argv[0] + 1) : 0;
        if (link_id >= 0 && link_id < AWS_MAX_LINKS) {
            for (int i = 0; i < AWS_MAX_SUBS; i++) {
                if (s_links[link_id].subs[i].used) {
                    at_reply_line("AWS_SUB:IND %d %s %d", link_id, s_links[link_id].subs[i].topic,
                                  s_links[link_id].subs[i].qos);
                }
            }
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        if (cmd->argc < 3) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        int link_id = atoi(cmd->argv[1]);
        const char *topic = cmd->argv[2];
        if (link_id < 0 || link_id >= AWS_MAX_LINKS || !s_links[link_id].client) {
            at_reply_error(cmd->name, 1);
            return;
        }
        bool found = false;
        for (int i = 0; i < AWS_MAX_SUBS; i++) {
            if (s_links[link_id].subs[i].used && strcmp(s_links[link_id].subs[i].topic, topic) == 0) {
                s_links[link_id].subs[i].used = false;
                found = true;
                break;
            }
        }
        if (!found) {
            at_reply_error(cmd->name, 2); /* doc: 2-not subscribed to <topic> */
            return;
        }
        esp_mqtt_client_unsubscribe(s_links[link_id].client, topic);
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (cmd->argc < 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int link_id = atoi(cmd->argv[0]);
    const char *topic = cmd->argv[1];
    int qos = atoi(cmd->argv[2]);
    if (link_id < 0 || link_id >= AWS_MAX_LINKS || !s_links[link_id].client) {
        at_reply_error(cmd->name, 1);
        return;
    }
    int slot = -1;
    for (int i = 0; i < AWS_MAX_SUBS; i++) {
        if (!s_links[link_id].subs[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0 || esp_mqtt_client_subscribe(s_links[link_id].client, topic, qos) < 0) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    strlcpy(s_links[link_id].subs[slot].topic, topic, sizeof(s_links[link_id].subs[slot].topic));
    s_links[link_id].subs[slot].qos = qos;
    s_links[link_id].subs[slot].used = true;
    at_reply_ok(cmd->name, NULL);
}
