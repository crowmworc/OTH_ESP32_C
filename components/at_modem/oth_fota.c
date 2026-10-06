/* OTH Platform firmware upgrades ordered over the cloud (cmd_oth_aws.c):
 *
 *   A511 / A531  module firmware -- wifiUrl (plain image) or wifiEncUrl +
 *                wifiEncKey (encrypted image), optional wifiHash (SHA-256
 *                of the plain image, hex). Streamed into the inactive OTA
 *                slot; the image must carry this build's image ID (as for
 *                OTA_REQUEST), then the module reboots into it. The next
 *                A100 reports versionChangeW "true".
 *   A521         MCU firmware -- mcuUrl / mcuEncUrl + mcuEncKey / mcuHash,
 *                staged in the inactive OTA slot (no separate partition
 *                needed; a later module upgrade simply overwrites it) and
 *                relayed to the host in 256-byte blocks:
 *                  *OTH*MOTA_COUNT=<blocks>          staged (0: failed)
 *                  AT*OTH*MOTA_READY                 host ready -> block 0
 *                  *OTH*MOTA_DATA=<no> <len> <data> <crc32>
 *                  AT*OTH*MOTA_DATA                  ack -> next block
 *                  *OTH*MOTA_END=<crc32 of the whole image>
 *                  AT*OTH*MOTA_DATA_END=<error>      0: installed
 *                <data> is byte-stuffed (binary content); CRCs are decimal.
 *                AT*OTH*MOTA_START=<url> stages a plain image the same way
 *                without the cloud.
 * Progress goes to the cloud as A510 / A520: 102 accepted, 201 downloading,
 * 202 downloaded, 301 installing, 900 failed.
 *
 * Encrypted images: AES-256-CBC, key = the first 32 characters of the key
 * string, IV = its first 16 characters, PKCS#7 padding; decrypted and
 * hashed on the fly (images do not fit in RAM), so the target is only
 * committed once the whole stream has checked out. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_rom_crc.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include "at_commands_oth.h"
#include "at_byte_stuffing.h"
#include "at_cmdset.h"
#include "at_event.h"
#include "at_nvs_kv.h"
#include "at_response.h"
#include "at_uart.h"
#include "m2m_version.h"
#include "oth_platform.h"

static const char *TAG = "oth_fota";

#define MOTA_BLOCK 256
#define SECTOR     4096

typedef struct {
    char ver[32];
    char url[256];
    char enc_url[256];
    char key[40];
    char hash[72];
    bool mcu;
    bool cloud; /* ordered over the cloud: progress goes back as A510/A520 */
} fw_req_t;

static volatile bool s_busy; /* one download at a time (both use the inactive slot) */

/* ---- versions ------------------------------------------------------------------ */

int oth_fota_wifi_version(void)
{
    int mm = 0, nn = 0;
    if (sscanf(esp_app_get_description()->version, "%d.%d", &mm, &nn) != 2) {
        return 0;
    }
    return mm * 100 + nn;
}

bool oth_fota_take_version_changed(void)
{
    uint16_t v = 0;
    if (m2m_nvs_get_u16("oth_verchg", &v) == ESP_OK && v) {
        m2m_nvs_set_u16("oth_verchg", 0);
        return true;
    }
    return false;
}

/* ---- download / decrypt / verify ------------------------------------------------------ */

typedef bool (*sink_fn)(void *ctx, const uint8_t *data, size_t len);

static bool hex_digest_matches(const uint8_t d[32], const char *hex)
{
    if (!hex || strlen(hex) != 64) {
        return false;
    }
    char want[65];
    for (int i = 0; i < 32; i++) {
        snprintf(want + i * 2, 3, "%02x", d[i]);
    }
    return strcasecmp(want, hex) == 0;
}

/* Streams url into sink. With key: AES-256-CBC + PKCS#7 removed. With
 * hash: the plain stream must hash to it. */
static bool fetch_stream(const char *url, const char *key, const char *hash, sink_fn sink, void *ctx)
{
    mbedtls_aes_context aes;
    uint8_t iv[16];
    mbedtls_aes_init(&aes);
    if (key) {
        uint8_t k[32] = {0};
        size_t kl = strlen(key);
        if (kl < 16) {
            mbedtls_aes_free(&aes);
            return false;
        }
        memcpy(k, key, kl < 32 ? kl : 32);
        memcpy(iv, key, 16);
        int rc = mbedtls_aes_setkey_dec(&aes, k, 256);
        memset(k, 0, sizeof(k));
        if (rc != 0) {
            mbedtls_aes_free(&aes);
            return false;
        }
    }
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t cl = esp_http_client_init(&cfg);
    uint8_t *in = malloc(1024 + 16), *out = malloc(1024);
    bool ok = false;
    if (cl && in && out && esp_http_client_open(cl, 0) == ESP_OK) {
        esp_http_client_fetch_headers(cl);
        bool err = esp_http_client_get_status_code(cl) != 200;
        size_t carry = 0, total = 0;
        uint8_t held[16];
        bool have_held = false;
        while (!err) {
            int r = esp_http_client_read(cl, (char *)in + carry, 1024 - carry);
            if (r < 0) {
                err = true;
                break;
            }
            if (r == 0) {
                break;
            }
            if (!key) {
                mbedtls_sha256_update(&sha, in, (size_t)r);
                err = !sink(ctx, in, (size_t)r);
                total += (size_t)r;
                continue;
            }
            size_t avail = carry + (size_t)r, whole = avail / 16 * 16;
            if (whole) {
                if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, whole, iv, in, out) != 0) {
                    err = true;
                    break;
                }
                /* the last block may hold padding: release it one round later */
                if (have_held) {
                    mbedtls_sha256_update(&sha, held, 16);
                    err = !sink(ctx, held, 16);
                    total += 16;
                }
                if (!err && whole > 16) {
                    mbedtls_sha256_update(&sha, out, whole - 16);
                    err = !sink(ctx, out, whole - 16);
                    total += whole - 16;
                }
                memcpy(held, out + whole - 16, 16);
                have_held = true;
            }
            carry = avail - whole;
            memmove(in, in + whole, carry);
        }
        if (!err && key) {
            uint8_t pad = have_held ? held[15] : 0;
            err = carry != 0 || pad < 1 || pad > 16;
            for (int i = 0; !err && i < pad; i++) {
                err = held[15 - i] != pad;
            }
            if (!err && pad < 16) {
                mbedtls_sha256_update(&sha, held, 16u - pad);
                err = !sink(ctx, held, 16u - pad);
                total += 16u - pad;
            }
        }
        uint8_t d[32];
        mbedtls_sha256_finish(&sha, d);
        ok = !err && total > 0 && (!hash || !hash[0] || hex_digest_matches(d, hash));
        if (!err && hash && hash[0] && !ok) {
            ESP_LOGW(TAG, "SHA-256 mismatch");
        }
        esp_http_client_close(cl);
    }
    if (cl) {
        esp_http_client_cleanup(cl);
    }
    free(in);
    free(out);
    mbedtls_aes_free(&aes);
    mbedtls_sha256_free(&sha);
    return ok;
}

/* ---- module firmware (A511 / A531) ------------------------------------------------- */

static bool ota_sink(void *ctx, const uint8_t *data, size_t len)
{
    return esp_ota_write(*(esp_ota_handle_t *)ctx, data, len) == ESP_OK;
}

/* Same image-ID rule as OTA_REQUEST: only images of this hardware /
 * command set / customer are installed. */
static bool image_id_ok(const esp_partition_t *p)
{
    m2m_image_id_t id = {0};
    size_t off = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t);
    if (esp_partition_read(p, off, &id, sizeof(id)) != ESP_OK) {
        return false;
    }
    id.id[sizeof(id.id) - 1] = '\0';
    return strcmp(id.id, M2M_FW_IMAGE_ID) == 0;
}

static bool install_wifi(const fw_req_t *r)
{
    const esp_partition_t *p = esp_ota_get_next_update_partition(NULL);
    esp_ota_handle_t h;
    if (!p || esp_ota_begin(p, OTA_SIZE_UNKNOWN, &h) != ESP_OK) {
        return false;
    }
    bool enc = r->enc_url[0] && r->key[0];
    bool ok = fetch_stream(enc ? r->enc_url : r->url, enc ? r->key : NULL, r->hash, ota_sink, &h);
    if (!ok) {
        esp_ota_abort(h);
        return false;
    }
    return esp_ota_end(h) == ESP_OK && image_id_ok(p) && esp_ota_set_boot_partition(p) == ESP_OK;
}

/* ---- MCU firmware staging and relay -------------------------------------------------- */

typedef struct {
    const esp_partition_t *p;
    size_t off, erased;
    uint32_t crc;
} stage_t;

static const esp_partition_t *s_mcu_part;
static size_t s_mcu_len, s_mcu_blocks, s_mcu_next;
static uint32_t s_mcu_crc;
static bool s_mcu_staged, s_mcu_cloud;
static char s_mcu_ver[32];

static bool stage_sink(void *ctx, const uint8_t *data, size_t len)
{
    stage_t *s = ctx;
    if (s->off + len > s->p->size) {
        return false;
    }
    while (s->off + len > s->erased) {
        if (esp_partition_erase_range(s->p, s->erased, SECTOR) != ESP_OK) {
            return false;
        }
        s->erased += SECTOR;
    }
    if (esp_partition_write(s->p, s->off, data, len) != ESP_OK) {
        return false;
    }
    s->crc = esp_rom_crc32_le(s->crc, data, len);
    s->off += len;
    return true;
}

static bool stage_mcu(const fw_req_t *r)
{
    s_mcu_staged = false;
    stage_t s = { .p = esp_ota_get_next_update_partition(NULL) };
    if (!s.p || esp_ota_get_boot_partition() != esp_ota_get_running_partition()) {
        return false; /* the inactive slot holds a module image waiting for the next RESET */
    }
    bool enc = r->enc_url[0] && r->key[0];
    if (!fetch_stream(enc ? r->enc_url : r->url, enc ? r->key : NULL, r->hash, stage_sink, &s)) {
        return false;
    }
    s_mcu_part = s.p;
    s_mcu_len = s.off;
    s_mcu_crc = s.crc;
    s_mcu_blocks = (s_mcu_len + MOTA_BLOCK - 1) / MOTA_BLOCK;
    s_mcu_next = 0;
    s_mcu_staged = true;
    return true;
}

static void send_next_block(void)
{
    if (s_mcu_next >= s_mcu_blocks) {
        at_event_post("MOTA_END=%lu", (unsigned long)s_mcu_crc);
        return;
    }
    size_t off = s_mcu_next * MOTA_BLOCK;
    size_t len = s_mcu_len - off < MOTA_BLOCK ? s_mcu_len - off : MOTA_BLOCK;
    uint8_t raw[MOTA_BLOCK];
    if (esp_partition_read(s_mcu_part, off, raw, len) != ESP_OK) {
        s_mcu_staged = false;
        return;
    }
    static char line[48 + MOTA_BLOCK * 2 + 16];
    int n = snprintf(line, sizeof(line), AT_TAG "MOTA_DATA=%u %u ", (unsigned)s_mcu_next, (unsigned)len);
    n += (int)at_byte_stuff_encode(raw, len, line + n, sizeof(line) - (size_t)n - 16);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " %lu\r\n",
                  (unsigned long)esp_rom_crc32_le(0, raw, len));
    if (at_event_enabled()) {
        at_uart_write(line, (size_t)n);
    }
    s_mcu_next++;
}

/* ---- tasks ------------------------------------------------------------------------- */

static void progress(const fw_req_t *r, const char *fw_cd, const char *err_cd)
{
    if (r->cloud) {
        oth_aws_publish_fw_progress(r->mcu ? "A520" : "A510", fw_cd, err_cd, r->ver);
    }
}

static void fw_task(void *arg)
{
    fw_req_t *r = arg;
    progress(r, "102", "0");
    progress(r, "201", "0");
    bool ok = r->mcu ? stage_mcu(r) : install_wifi(r);
    if (!ok) {
        progress(r, "900", "9");
        if (r->mcu) {
            at_event_post("MOTA_COUNT=0");
        }
    } else {
        progress(r, "202", "0");
        progress(r, "301", "0");
        if (r->mcu) {
            s_mcu_cloud = r->cloud;
            strlcpy(s_mcu_ver, r->ver, sizeof(s_mcu_ver));
            at_event_post("MOTA_COUNT=%u", (unsigned)s_mcu_blocks);
        } else {
            m2m_nvs_set_u16("oth_verchg", 1);
            vTaskDelay(pdMS_TO_TICKS(1000)); /* let the progress messages leave */
            esp_restart();
        }
    }
    memset(r->key, 0, sizeof(r->key));
    free(r);
    s_busy = false;
    vTaskDelete(NULL);
}

static bool fw_start(bool mcu, const char *ver, const char *url, const char *enc_url, const char *key,
                     const char *hash)
{
    if (s_busy) {
        return false;
    }
    fw_req_t *r = calloc(1, sizeof(*r));
    if (!r) {
        return false;
    }
    r->mcu = mcu;
    r->cloud = true;
    strlcpy(r->ver, ver ? ver : "", sizeof(r->ver));
    strlcpy(r->url, url ? url : "", sizeof(r->url));
    strlcpy(r->enc_url, enc_url ? enc_url : "", sizeof(r->enc_url));
    strlcpy(r->key, key ? key : "", sizeof(r->key));
    strlcpy(r->hash, hash ? hash : "", sizeof(r->hash));
    s_busy = true;
    if (xTaskCreate(fw_task, "oth_fw", 8192, r, 5, NULL) != pdPASS) {
        free(r);
        s_busy = false;
        return false;
    }
    return true;
}

void oth_fota_wifi_install(const char *ver, const char *url, const char *enc_url, const char *enc_key,
                           const char *hash)
{
    if (!fw_start(false, ver, url, enc_url, enc_key, hash)) {
        oth_aws_publish_fw_progress("A510", "900", "9", ver);
    }
}

void oth_fota_mcu_install(const char *ver, const char *url, const char *enc_url, const char *enc_key,
                          const char *hash)
{
    if (!fw_start(true, ver, url, enc_url, enc_key, hash)) {
        oth_aws_publish_fw_progress("A520", "900", "9", ver);
    }
}

/* ---- MOTA commands ------------------------------------------------------------------ */

/* AT*OTH*MOTA_START=<url> -- stages a plain MCU image without the cloud;
 * OK, then *OTH*MOTA_COUNT=<blocks>. */
void cmd_oth_mota_start(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (strncasecmp(cmd->argv[0], "http://", 7) && strncasecmp(cmd->argv[0], "https://", 8)) ||
        strlen(cmd->argv[0]) >= sizeof(((fw_req_t *)0)->url)) {
        at_reply_error(cmd->name, -1);
        return;
    }
    if (s_busy) {
        at_reply_error(cmd->name, -1);
        return;
    }
    fw_req_t *r = calloc(1, sizeof(*r)); /* cloud false: no A520 progress */
    if (!r) {
        at_reply_error(cmd->name, -1);
        return;
    }
    r->mcu = true;
    strlcpy(r->url, cmd->argv[0], sizeof(r->url));
    s_busy = true;
    at_reply_ok(cmd->name, NULL);
    if (xTaskCreate(fw_task, "oth_fw", 8192, r, 5, NULL) != pdPASS) {
        free(r);
        s_busy = false;
        at_event_post("MOTA_COUNT=0");
    }
}

/* AT*OTH*MOTA_READY -- the host is ready: block 0 follows. */
void cmd_oth_mota_ready(const at_command_t *cmd)
{
    if (!s_mcu_staged || s_mcu_blocks == 0) {
        at_reply_error(cmd->name, -1);
        return;
    }
    s_mcu_next = 0;
    at_reply_ok(cmd->name, NULL);
    send_next_block();
}

/* AT*OTH*MOTA_DATA -- previous block taken: the next one (or MOTA_END). */
void cmd_oth_mota_data(const at_command_t *cmd)
{
    if (!s_mcu_staged) {
        at_reply_error(cmd->name, -1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
    send_next_block();
}

/* AT*OTH*MOTA_DATA_END=<error> -- the host's result; 0: installed. */
void cmd_oth_mota_data_end(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, -1);
        return;
    }
    int err = atoi(cmd->argv[0]);
    bool cloud = s_mcu_cloud;
    s_mcu_staged = s_mcu_cloud = false;
    at_reply_ok(cmd->name, NULL);
    if (!cloud) {
        return;
    }
    if (err == 0) {
        oth_aws_note_mcu_updated(s_mcu_crc);
    } else {
        char e[8];
        snprintf(e, sizeof(e), "%d", err);
        oth_aws_publish_fw_progress("A520", "900", e, s_mcu_ver);
    }
}
