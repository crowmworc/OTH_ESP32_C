/* AT*M2M*OTA_CHECK/OTA_UPDATE -- firmware OTA (doc Ch.6.6), on esp_https_ota.
 *
 * Doc gap handled by design decision: "<url>: base URL of the OTA image"
 * is vague about what OTA_CHECK actually fetches to learn the server's
 * version without downloading the whole image -- rather than invent a
 * separate manifest-file convention, this points <url> directly at the
 * firmware .bin and uses esp_https_ota_get_img_desc() to read just the
 * embedded esp_app_desc_t header (version string) via a partial download,
 * then esp_https_ota_abort()s without writing anything to flash. The same
 * <url> is then reused verbatim for OTA_UPDATE, matching the doc's
 * examples which pass the identical URL to both commands.
 *
 * Version comparison used to be a plain string-equality check (not numeric):
 * back when PROJECT_VER could be any arbitrary string (e.g. "1"), "differs"
 * was treated as "server is newer" as a documented simplification, not a
 * real version-ordering algorithm. Since 2026-09-26 (M2M_SW Release Naming
 * Guide v2.0 / M2M-AT Command Set Rev 1.4), the version format is fixed at
 * <MM>.<NN> (m2m_version.h's M2M_FW_VERSION == PROJECT_VER, always
 * "01.00"-shaped), so the doc's actual comparison rule ("compared as
 * numbers (MM, then NN); the update is offered only when <server_version>
 * is greater") is now well-defined and implemented for real -- see
 * parse_version_code() below. Falls back to the old string-inequality
 * behavior only if a version string doesn't parse as MM.NN (a malformed
 * server response, or a non-conforming build), rather than failing closed.
 *
 * OTA_UPDATE downloads, flashes, and marks the new image bootable (what
 * esp_https_ota() does), but does *not* reboot into it -- the doc's own
 * text never mentions an automatic reboot, so the host is expected to
 * follow up with AT*M2M*SYS_RST once it's ready to switch over.
 *
 * Doc v2.0 adds OTA_UPDATE reason 5: "downloaded image ID (hardware, AT
 * command set, customer code) does not match the installed image" --
 * compares the target image's own M2M_FW_IMAGE_ID (m2m_version.h,
 * .rodata_custom_desc section, right after esp_app_desc_t in the DROM
 * segment -- same layout esp_ota_get_partition_description() reads
 * esp_app_desc_t from, one struct further) against this running image's.
 * Checked during OTA_CHECK (which already partially downloads the image
 * and aborts without committing anything -- see below), not OTA_UPDATE
 * itself, so a mismatch is caught before any real download/flash attempt.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_partition.h"
#include "esp_crt_bundle.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "m2m_version.h"
#include "at_cmdset.h"

static TaskHandle_t s_ota_task;

/* Set once an OTA_CHECK completes successfully; OTA_UPDATE requires the
 * exact same URL to have been checked first and found newer (doc: "the
 * request is refused when the server image is not newer... run
 * AT*M2M*OTA_CHECK first"). */
static char s_checked_url[513];
static bool s_checked_ok;
static bool s_checked_is_newer;
static bool s_checked_image_id_ok;

/* Reads the target OTA partition's own M2M_FW_IMAGE_ID and compares it
 * against this running image's. Must run after esp_https_ota_get_img_desc()
 * has already pulled in at least the image header + esp_app_desc_t, and
 * before esp_https_ota_abort()/finish() -- keeps performing until enough of
 * the image has actually been written to flash to read our struct back out
 * of it. A hard read/parse failure here is treated as "doesn't match" (fail
 * closed) rather than silently allowing the update through -- this check
 * exists specifically to catch mismatched hardware/command-set/customer
 * images, so an inability to verify shouldn't be waved through as a match. */
static bool image_id_matches(esp_https_ota_handle_t handle)
{
    const size_t offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) +
                          sizeof(esp_app_desc_t);
    const size_t needed = offset + sizeof(m2m_image_id_t);

    while ((size_t)esp_https_ota_get_image_len_read(handle) < needed) {
        esp_err_t perr = esp_https_ota_perform(handle);
        if (perr == ESP_OK) {
            break; /* whole (small) image already written */
        }
        if (perr != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            return false; /* real error partway through -- can't verify, treat as mismatch */
        }
        if (esp_https_ota_is_complete_data_received(handle)) {
            break; /* image smaller than our struct's offset -- shouldn't happen, avoid spinning */
        }
    }

    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    if (!target) {
        return false;
    }
    m2m_image_id_t downloaded_id = {0};
    if (esp_partition_read(target, offset, &downloaded_id, sizeof(downloaded_id)) != ESP_OK) {
        return false;
    }
    downloaded_id.id[sizeof(downloaded_id.id) - 1] = '\0'; /* defend against a corrupt/unterminated read */
    return strcmp(downloaded_id.id, M2M_FW_IMAGE_ID) == 0;
}

/* Parses a fixed <MM>.<NN> version string into MM*100+NN, matching the
 * naming guide's own "자동화용 정수 변환" rule (section 6.1). Returns -1 if
 * the string doesn't have that shape, so callers can fall back rather than
 * silently mis-comparing (e.g. "1.0.2"-style leftovers or a malformed
 * server response). */
static int parse_version_code(const char *ver)
{
    int mm, nn, extra;
    if (sscanf(ver, "%d.%d%n", &mm, &nn, &extra) != 2 || ver[extra] != '\0' ||
        mm < 0 || mm > 99 || nn < 0 || nn > 99) {
        return -1;
    }
    return mm * 100 + nn;
}

/* A failed check: OTH-AT reports the lookup error as server version 0. */
#if CONFIG_AT_MODEM_CMDSET_OTH
#define OTA_CHECK_FAILED()     at_event_post("OTA_VERSION:%d 0", parse_version_code(esp_app_get_description()->version))
#else
#define OTA_CHECK_FAILED() at_event_post("OTA_CHECK:ERROR %d", 1) /* doc: 1-initialization error */
#endif

static void ota_check_worker(void *arg)
{
    char *url = arg;

    esp_http_client_config_t http_config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
    };
    esp_https_ota_config_t ota_config = {.http_config = &http_config};

    esp_https_ota_handle_t handle;
    esp_err_t err = esp_https_ota_begin(&ota_config, &handle);
    if (err != ESP_OK) {
        OTA_CHECK_FAILED();
        goto done;
    }

    esp_app_desc_t server_desc;
    err = esp_https_ota_get_img_desc(handle, &server_desc);
    if (err != ESP_OK) {
        esp_https_ota_abort(handle);
        OTA_CHECK_FAILED();
        goto done;
    }

    bool image_id_ok = image_id_matches(handle);
    esp_https_ota_abort(handle); /* only checking -- nothing gets committed/marked bootable */

    const esp_app_desc_t *local_desc = esp_app_get_description();
    int local_code = parse_version_code(local_desc->version);
    int server_code = parse_version_code(server_desc.version);
    bool is_newer = (local_code >= 0 && server_code >= 0)
                        ? (server_code > local_code)
                        : (strcmp(local_desc->version, server_desc.version) != 0);

    strlcpy(s_checked_url, url, sizeof(s_checked_url));
    s_checked_ok = true;
    s_checked_is_newer = is_newer;
    s_checked_image_id_ok = image_id_ok;

#if CONFIG_AT_MODEM_CMDSET_OTH
    /* OTH-AT: *OTH*OTA_VERSION:<local> <server>, as integers (MM*100+NN) */
    at_event_post("OTA_VERSION:%d %d", local_code, server_code > 0 ? server_code : 0);
#else
    at_event_post("OTA_CHECK:DONE %s %s", local_desc->version, server_desc.version);
#endif

done:
    free(url);
    s_ota_task = NULL;
    vTaskDelete(NULL);
}

/* AT*M2M*OTA_CHECK=<url> */
void cmd_ota_check(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, 2); /* doc: 2-argument error */
        return;
    }
    if (s_ota_task) {
        at_reply_error(cmd->name, 1); /* doc has no "already in progress" code for OTA_CHECK -- generic bucket */
        return;
    }

    char *url = strdup(cmd->argv[0]);
    if (!url) {
        at_reply_error(cmd->name, 1);
        return;
    }
    s_checked_ok = false; /* invalidate any previous check while this one runs */

    if (xTaskCreate(ota_check_worker, "ota_check", 6144, url, 5, &s_ota_task) != pdPASS) {
        free(url);
        s_ota_task = NULL;
        at_reply_error(cmd->name, 1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

static void ota_update_worker(void *arg)
{
    char *url = arg;

    esp_http_client_config_t http_config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 30000,
    };
    esp_https_ota_config_t ota_config = {.http_config = &http_config};

#if CONFIG_AT_MODEM_CMDSET_OTH
    if (esp_https_ota(&ota_config) == ESP_OK) {
        at_event_post("OTA_UPDATE:OK");
    } else {
        at_event_post("OTA_UPDATE:ERROR %d", 9); /* OTH: 9-OTA server error */
    }
#else
    if (esp_https_ota(&ota_config) == ESP_OK) {
        at_event_post("OTA_UPDATE:DONE");
    } else {
        at_event_post("OTA_UPDATE:ERROR %d", 1); /* doc: 1-initialization error (closest generic fit) */
    }
#endif

    free(url);
    s_ota_task = NULL;
    vTaskDelete(NULL);
}

/* AT*M2M*OTA_UPDATE=<url> */
void cmd_ota_update(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, 2); /* doc: 2-argument error */
        return;
    }
    if (s_ota_task) {
        /* doc code 3 already means "server version not newer" for this
         * command (checked a few lines below) -- reusing it here for
         * "already in progress" would make the two conditions
         * indistinguishable to the host, so use the generic bucket instead. */
        at_reply_error(cmd->name, 1);
        return;
    }
    if (!s_checked_ok || strcmp(cmd->argv[0], s_checked_url) != 0) {
        at_reply_error(cmd->name, 4); /* doc: 4-run AT*M2M*OTA_CHECK first */
        return;
    }
    if (!s_checked_is_newer) {
        at_reply_error(cmd->name, 3); /* doc: 3-server version not newer than local version */
        return;
    }
    if (!s_checked_image_id_ok) {
#if CONFIG_AT_MODEM_CMDSET_OTH
        at_reply_error(cmd->name, 1); /* OTH has no image-ID code: 1, the nearest (signature) */
#else
        at_reply_error(cmd->name, 5); /* doc: 5-downloaded image ID doesn't match the installed image */
#endif
        return;
    }

    char *url = strdup(cmd->argv[0]);
    if (!url) {
        at_reply_error(cmd->name, 1);
        return;
    }

    if (xTaskCreate(ota_update_worker, "ota_update", 8192, url, 5, &s_ota_task) != pdPASS) {
        free(url);
        s_ota_task = NULL;
        at_reply_error(cmd->name, 1);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}
