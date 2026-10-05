/* AT*M2M*NET_HTTPSET/HTTPHEADER/HTTPGET/HTTPPOST/HTTPDOWNLOAD/HTTPSTOP --
 * HTTP client (doc Ch.6.2), on esp_http_client. HTTPS is supported "for
 * free" via esp_crt_bundle_attach() (the full public-CA bundle is already
 * enabled in sdkconfig) -- this is a different, simpler problem than
 * NET_CONN/NET_SERVER's raw-socket SSL support in net_link.c, since
 * esp_http_client owns its own TLS session internally.
 *
 * GET/POST/DOWNLOAD run on a dedicated one-shot worker task rather than
 * inline in the AT command handler: a request can legitimately take up to
 * NET_HTTPSET's 600s timeout, and blocking the single AT dispatcher task
 * for that long would freeze the entire command interface (unlike the
 * short bounded waits used elsewhere, e.g. NET_CONN's 10s). Only one
 * request may be in flight at a time (doc doesn't define concurrent HTTP
 * sessions); AT*M2M*NET_HTTPSTOP cooperatively cancels it by setting a
 * flag the worker checks between esp_http_client_read() calls -- returning
 * an error from the ON_DATA event handler does NOT actually abort
 * esp_http_client_perform() in this esp-idf version (checked against
 * esp_http_client.c), hence the manual open/write/fetch_headers/read loop
 * instead of the simpler esp_http_client_perform().
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_http_client.h"
#include "esp_crt_bundle.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "at_uart.h"
#include "fs_store.h"

#define HTTP_MAX_HEADERS 5
#define HTTP_BODY_CAP    8192 /* response body cap for GET/POST, matches NET_SEND's payload cap */
#define DL_RAM_MAX       (16 * 1024) /* NET_HTTPDOWNLOAD: files up to this are buffered, see http_worker() */
#define KEY_TAIL         16          /* bytes kept across chunks when scanning for "PRIVATE KEY-----" */

typedef struct {
    bool used;
    char key[32];
    char value[128];
} http_header_t;

static int s_content_type = 0;     /* 0-form,1-json,3-binary,4-text (doc default 0) */
static bool s_https_default = false;
static int s_timeout_s = 30;
static http_header_t s_headers[HTTP_MAX_HEADERS];

static TaskHandle_t s_worker_task;
static atomic_bool s_abort_requested = false;

static const char *content_type_str(void)
{
    switch (s_content_type) {
    case 1:  return "application/json";
    case 3:  return "application/octet-stream";
    case 4:  return "text/plain";
    default: return "application/x-www-form-urlencoded";
    }
}

static void apply_stored_headers(esp_http_client_handle_t client)
{
    for (int i = 0; i < HTTP_MAX_HEADERS; i++) {
        if (s_headers[i].used) {
            esp_http_client_set_header(client, s_headers[i].key, s_headers[i].value);
        }
    }
}

/* Doc examples give URLs both with a scheme ("https://...") and without
 * ("192.168.0.10/api/temp") -- a bare host:path uses NET_HTTPSET's scheme
 * default. */
static void normalize_url(const char *in, char *out, size_t out_size)
{
    if (strncasecmp(in, "http://", 7) == 0 || strncasecmp(in, "https://", 8) == 0) {
        strlcpy(out, in, out_size);
    } else {
        snprintf(out, out_size, "%s://%s", s_https_default ? "https" : "http", in);
    }
}

/* Doc's HTTP command examples inconsistently mix ',' and ' ' as the param
 * separator across NET_HTTPGET/HTTPDOWNLOAD (and sometimes quote a field,
 * sometimes not) -- tolerate either separator and optional quoting rather
 * than pick one and reject the other's worked example. */
static char *next_flex_token(char **pp)
{
    char *p = *pp;
    while (*p == ' ' || *p == ',') {
        p++;
    }
    if (!*p) {
        *pp = p;
        return NULL;
    }
    char *start;
    if (*p == '"') {
        p++;
        start = p;
        char *end = strchr(p, '"');
        if (end) {
            *end = '\0';
            p = end + 1;
        } else {
            p += strlen(p);
        }
    } else {
        start = p;
        while (*p && *p != ' ' && *p != ',') {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
    }
    *pp = p;
    return start;
}

typedef enum { HTTP_OP_GET, HTTP_OP_POST, HTTP_OP_DOWNLOAD } http_op_t;

typedef struct {
    http_op_t op;
    char url[513];
    char filename[64];   /* HTTP_OP_DOWNLOAD only */
    uint8_t *post_data;  /* HTTP_OP_POST only, malloc'd */
    size_t post_len;
} http_job_t;

static const char *op_cmd_name(http_op_t op)
{
    switch (op) {
    case HTTP_OP_GET:      return "NET_HTTPGET";
    case HTTP_OP_POST:     return "NET_HTTPPOST";
    default:               return "NET_HTTPDOWNLOAD";
    }
}

static void http_worker(void *arg)
{
    http_job_t *job = arg;
    const char *name = op_cmd_name(job->op);

    esp_http_client_config_t config = {
        .url = job->url,
        .timeout_ms = s_timeout_s * 1000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .method = (job->op == HTTP_OP_POST) ? HTTP_METHOD_POST : HTTP_METHOD_GET,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        at_event_post("%s:ERROR %d", name, AT_ERR_GENERIC);
        goto cleanup_job;
    }
    apply_stored_headers(client);
    if (job->op == HTTP_OP_POST) {
        esp_http_client_set_header(client, "Content-Type", content_type_str());
    }

    bool ok = (esp_http_client_open(client, (job->op == HTTP_OP_POST) ? (int)job->post_len : 0) == ESP_OK);
    if (ok && job->op == HTTP_OP_POST && job->post_len > 0) {
        ok = esp_http_client_write(client, (const char *)job->post_data, (int)job->post_len) >= 0;
    }
    int status = 0;
    if (ok) {
        esp_http_client_fetch_headers(client); /* return value (content-length) unused: we size our own buffer */
        status = esp_http_client_get_status_code(client);
    }

    if (!ok) {
        at_event_post("%s:ERROR %d", name, 4); /* Appendix C: ERR_CONNECTION_ESTABLISHMENT */
        esp_http_client_cleanup(client);
        goto cleanup_job;
    }

    bool aborted = false;
    if (job->op == HTTP_OP_DOWNLOAD) {
        /* A file up to DL_RAM_MAX is received whole into RAM and stored via
         * fs_store_write(), so a private key goes straight to encrypted NVS
         * and never touches plain SPIFFS (EN 18031-1 SSM-3). Only a larger
         * file -- too big to be a key file -- is streamed to SPIFFS, and it
         * is refused (reason 5) if it turns out to hold a private key. */
        char path[64];
        fs_store_path(job->filename, path, sizeof(path));
        char *ram = malloc(DL_RAM_MAX);
        size_t ram_len = 0;
        FILE *f = NULL;
        bool write_ok = (ram != NULL), has_key = false;
        static char win[KEY_TAIL + 1024];
        size_t tail_len = 0;
        while (write_ok) {
            if (atomic_load(&s_abort_requested)) {
                aborted = true;
                break;
            }
            char *buf = win + KEY_TAIL;
            int n = esp_http_client_read(client, buf, 1024);
            if (n < 0) {
                write_ok = false;
                break;
            }
            if (n == 0) {
                break;
            }
            if (!f && ram_len + (size_t)n <= DL_RAM_MAX) {
                memcpy(ram + ram_len, buf, (size_t)n);
                ram_len += (size_t)n;
                continue;
            }
            if (!f) {
                f = fopen(path, "wb");
                if (!f || fwrite(ram, 1, ram_len, f) != ram_len) {
                    write_ok = false;
                    break;
                }
                has_key = fs_store_is_secret(job->filename, ram, ram_len);
                tail_len = ram_len < KEY_TAIL ? ram_len : KEY_TAIL;
                memcpy(win + KEY_TAIL - tail_len, ram + ram_len - tail_len, tail_len);
            }
            /* Look for a key header across the chunk boundary too. */
            has_key = has_key || fs_store_is_secret(job->filename, win + KEY_TAIL - tail_len, tail_len + (size_t)n);
            if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) {
                write_ok = false;
                break;
            }
            tail_len = (size_t)n < KEY_TAIL ? (size_t)n : KEY_TAIL;
            memmove(win + KEY_TAIL - tail_len, buf + n - tail_len, tail_len);
        }
        if (f) {
            fclose(f);
        }

        char why[80];
        int err = 0;
        if (aborted || !write_ok) {
            err = aborted ? -1 : AT_ERR_GENERIC;
        } else if (f) {
            /* EN 18031-1 CCK-1 / SSM-3: no key in plain SPIFFS, no weak cert. */
            if (has_key || !fs_store_check_key_strength(job->filename, why, sizeof(why))) {
                err = 5;
            }
        } else if (!fs_store_check_pem_strength(ram, ram_len, why, sizeof(why)) ||
                   (fs_store_is_secret(job->filename, ram, ram_len) && ram_len > FS_STORE_SECRET_MAX)) {
            err = 5; /* weak certificate/key, or a private-key file over 8 KB */
        } else if (!fs_store_write(job->filename, ram, ram_len)) {
            err = AT_ERR_GENERIC;
        }
        if (f && err != 0) {
            fs_store_remove(job->filename); /* the partial/refused SPIFFS copy */
        }
        if (ram) {
            memset(ram, 0, ram_len);
            free(ram);
        }
        if (err == -1) {
            at_event_post("NET_HTTPSTOP:DONE");
        } else if (err != 0) {
            at_event_post("%s:ERROR %d", name, err);
        } else {
            at_event_post("%s:DONE", name);
        }
    } else {
        uint8_t *buf = malloc(HTTP_BODY_CAP);
        size_t total = 0;
        if (buf) {
            while (total < HTTP_BODY_CAP) {
                if (atomic_load(&s_abort_requested)) {
                    aborted = true;
                    break;
                }
                int n = esp_http_client_read(client, (char *)buf + total, (int)(HTTP_BODY_CAP - total));
                if (n <= 0) {
                    break;
                }
                total += (size_t)n;
            }
        }

        /* If the buffer filled up exactly, we can't tell from total alone
         * whether the body ended there or was cut off -- probe for one more
         * byte. Silently emitting :DONE with a truncated body would look
         * like a complete, successful response to the host. */
        bool truncated = false;
        if (buf && !aborted && total == HTTP_BODY_CAP) {
            uint8_t probe;
            if (esp_http_client_read(client, (char *)&probe, 1) > 0) {
                truncated = true;
            }
        }

        if (aborted) {
            at_event_post("NET_HTTPSTOP:DONE");
        } else if (truncated) {
            at_event_post("%s:ERROR %d", name, AT_ERR_GENERIC); /* response exceeds this build's body cap */
        } else if (buf) {
            /* Response body is raw bytes, not byte-stuffed (the doc only
             * defines stuffing for NET_SEND/AWS_PUB) -- write it verbatim
             * like NET_RECV:IND does, not through a %s/printf path. */
            char header[64];
            int hlen = snprintf(header, sizeof(header), AT_TAG "%s:IND %d %d ", name, status, (int)total);
            if (hlen > 0 && (size_t)hlen < sizeof(header)) {
                at_uart_write_atomic2(header, (size_t)hlen, (const char *)buf, total);
                at_uart_write("\r\n", 2);
            }
            at_event_post("%s:DONE", name);
        } else {
            at_event_post("%s:ERROR %d", name, AT_ERR_GENERIC);
        }
        free(buf);
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

cleanup_job:
    free(job->post_data);
    free(job);
    atomic_store(&s_abort_requested, false);
    s_worker_task = NULL;
    vTaskDelete(NULL);
}

static bool start_job(http_job_t *job)
{
    if (s_worker_task) {
        return false;
    }
    atomic_store(&s_abort_requested, false);
    if (xTaskCreate(http_worker, "http_worker", 6144, job, 5, &s_worker_task) != pdPASS) {
        s_worker_task = NULL;
        return false;
    }
    return true;
}

/* AT*M2M*NET_HTTPSET=<type> {scheme} [timeout] [response] -- `response`
 * (doc's 4th param, undescribed beyond appearing in the signature) isn't
 * given any meaning anywhere else in the doc; accepted (via argv[3], if
 * present) and ignored. */
void cmd_net_httpset(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int type = atoi(cmd->argv[0]);
    if (type != 0 && type != 1 && type != 3 && type != 4) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    s_content_type = type;
    if (cmd->argc >= 2) {
        s_https_default = (atoi(cmd->argv[1]) == 1);
    }
    if (cmd->argc >= 3) {
        int timeout = atoi(cmd->argv[2]);
        if (timeout >= 1 && timeout <= 600) {
            s_timeout_s = timeout;
        }
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_HTTPHEADER=<cmd> <key> [value] -- cmd: ADD/CLR/DEL. */
void cmd_net_httpheader(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (strcasecmp(cmd->argv[0], "CLR") == 0) {
        memset(s_headers, 0, sizeof(s_headers));
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        if (cmd->argc < 2) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        for (int i = 0; i < HTTP_MAX_HEADERS; i++) {
            if (s_headers[i].used && strcasecmp(s_headers[i].key, cmd->argv[1]) == 0) {
                s_headers[i].used = false;
            }
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (strcasecmp(cmd->argv[0], "ADD") == 0) {
        if (cmd->argc < 3) {
            at_reply_error(cmd->name, AT_ERR_ARG);
            return;
        }
        int slot = -1;
        for (int i = 0; i < HTTP_MAX_HEADERS; i++) {
            if (s_headers[i].used && strcasecmp(s_headers[i].key, cmd->argv[1]) == 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            for (int i = 0; i < HTTP_MAX_HEADERS; i++) {
                if (!s_headers[i].used) {
                    slot = i;
                    break;
                }
            }
        }
        if (slot < 0) {
            at_reply_error(cmd->name, AT_ERR_GENERIC); /* all 5 slots full, doc caps at 5 */
            return;
        }
        strlcpy(s_headers[slot].key, cmd->argv[1], sizeof(s_headers[slot].key));
        strlcpy(s_headers[slot].value, cmd->argv[2], sizeof(s_headers[slot].value));
        s_headers[slot].used = true;
        at_reply_ok(cmd->name, NULL);
        return;
    }
    at_reply_error(cmd->name, AT_ERR_ARG);
}

/* AT*M2M*NET_HTTPGET=<url>[,<recv_mode>] -- recv_mode is accepted but
 * always behaves as the doc's default (0): recv_mode=1's "retrieve
 * separately" companion read command is never actually defined anywhere in
 * this doc (marked "(optional)"), so there's nothing to implement it as. */
void cmd_net_httpget(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (s_worker_task) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }

    char urlbuf[600];
    strlcpy(urlbuf, cmd->argv[0], sizeof(urlbuf));
    char *comma = strchr(urlbuf, ',');
    if (comma) {
        *comma = '\0';
    }

    http_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    job->op = HTTP_OP_GET;
    normalize_url(urlbuf, job->url, sizeof(job->url));

    if (!start_job(job)) {
        free(job);
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_HTTPPOST=<url> [length] [data] -- registered `raw` (like
 * NET_SEND): <data> may itself contain spaces. */
void cmd_net_httppost(const at_command_t *cmd)
{
    if (s_worker_task) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }
    char *p = cmd->raw_params;
    if (!p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    char *url_tok = next_flex_token(&p);
    if (!url_tok) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    while (*p == ' ') {
        p++;
    }
    char *len_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    long body_len = 0;
    char *data = NULL;
    if (*p) {
        *p++ = '\0';
        body_len = atol(len_tok);
        data = p; /* everything else, verbatim */
    } else if (*len_tok) {
        body_len = atol(len_tok);
    }

    http_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    job->op = HTTP_OP_POST;
    normalize_url(url_tok, job->url, sizeof(job->url));
    if (data && body_len > 0) {
        size_t actual_len = strlen(data);
        size_t use_len = ((size_t)body_len < actual_len) ? (size_t)body_len : actual_len;
        job->post_data = malloc(use_len);
        if (job->post_data) {
            memcpy(job->post_data, data, use_len);
            job->post_len = use_len;
        }
    }

    if (!start_job(job)) {
        free(job->post_data);
        free(job);
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_HTTPDOWNLOAD=<url> <filename> [,<timeout_ms>] -- registered
 * `raw` for the tolerant comma/space/quote parsing (see next_flex_token());
 * the optional per-request timeout_ms isn't separately applied (uses
 * NET_HTTPSET's global timeout instead) -- a minor scope simplification. */
void cmd_net_httpdownload(const at_command_t *cmd)
{
    if (s_worker_task) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }
    char *p = cmd->raw_params;
    if (!p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    char *url_tok = next_flex_token(&p);
    char *file_tok = next_flex_token(&p);
    (void)next_flex_token(&p); /* optional timeout_ms, unused */
    if (!url_tok || !file_tok || !fs_store_name_valid(file_tok)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    http_job_t *job = calloc(1, sizeof(*job));
    if (!job) {
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    job->op = HTTP_OP_DOWNLOAD;
    normalize_url(url_tok, job->url, sizeof(job->url));
    strlcpy(job->filename, file_tok, sizeof(job->filename));

    if (!start_job(job)) {
        free(job);
        at_reply_error(cmd->name, AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_FILELIST -- Execute only. Lists every file NET_HTTPDOWNLOAD
 * (or the web UI's cert upload) has stored, with no prior AT command to
 * do so -- a host previously had no way to discover what's already on the
 * module without guessing filenames and probing WF_EAPCERT/MQTT_CONF. */
void cmd_net_filelist(const at_command_t *cmd)
{
    /* static: at_uart_rx (the calling task) only has a 4096-byte stack --
     * 32 * sizeof(fs_store_entry_t) on top of the existing dispatch call
     * stack blew it (Guru Meditation stack protection fault, hardware-
     * confirmed 2026-09-14). Same fix as cmd_wifi.c's WF_EAPCERT cert
     * buffers. */
    static fs_store_entry_t entries[32];
    size_t n = fs_store_list(entries, sizeof(entries) / sizeof(entries[0]));
    for (size_t i = 0; i < n; i++) {
        at_reply_line("NET_FILELIST:IND %s %u", entries[i].name, (unsigned)entries[i].size);
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_FILEINFO=<filename> -- Query-with-parameter. fingerprint is
 * only present when the file parses as a PEM X.509 certificate (silently
 * omitted for keys/PAC blobs/non-cert files, not an error). */
void cmd_net_fileinfo(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (!fs_store_exists(cmd->argv[0])) {
        at_reply_error(cmd->name, 1); /* doc: 1-file not found */
        return;
    }
    size_t size = fs_store_size(cmd->argv[0]);
    char fp[100];
    if (fs_store_cert_fingerprint(cmd->argv[0], fp, sizeof(fp))) {
        at_reply_ok(cmd->name, "%s %u %s", cmd->argv[0], (unsigned)size, fp);
    } else {
        at_reply_ok(cmd->name, "%s %u", cmd->argv[0], (unsigned)size);
    }
}

/* AT*M2M*NET_HTTPSTOP -- cooperative cancel, see file header comment. */
void cmd_net_httpstop(const at_command_t *cmd)
{
    if (!s_worker_task) {
        at_reply_error(cmd->name, 1); /* doc: reason 1-no request to abort */
        return;
    }
    atomic_store(&s_abort_requested, true);
    at_reply_ok(cmd->name, NULL);
    /* NET_HTTPSTOP:DONE follows asynchronously once http_worker() notices
     * the flag and unwinds. */
}
