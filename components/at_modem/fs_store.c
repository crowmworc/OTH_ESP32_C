#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_spiffs.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "esp_random.h"

#include "fs_store.h"

static const char *TAG = "fs_store";
#define FS_BASE_PATH "/spiffs"

/* ---- Encrypted-NVS backend (see fs_store.h) ------------------------------
 * One blob per file in namespace "m2m_files", holding "<name>\0<data>". The
 * NVS key is 'f' + 14 hex digits of SHA-256(name): file names (up to 30
 * characters) don't fit NVS's 15-character keys, and the stored name is
 * what fs_store_list() reports. */
#define SECRET_NS "m2m_files"

static void secret_key(const char *filename, char key[16])
{
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char *)filename, strlen(filename), hash, 0);
    key[0] = 'f';
    for (int i = 0; i < 7; i++) {
        snprintf(key + 1 + i * 2, 3, "%02x", hash[i]);
    }
}

static bool contains(const void *data, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    const char *d = data;
    for (size_t i = 0; len >= n && i <= len - n; i++) {
        if (memcmp(d + i, needle, n) == 0) {
            return true;
        }
    }
    return false;
}

bool fs_store_is_secret(const char *filename, const void *data, size_t len)
{
    static const char *exts[] = { ".key", ".p12", ".pfx", ".pac" };
    size_t nlen = strlen(filename);
    for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        size_t elen = strlen(exts[i]);
        if (nlen > elen && strcasecmp(filename + nlen - elen, exts[i]) == 0) {
            return true;
        }
    }
    return data && contains(data, len, "PRIVATE KEY-----");
}

/* Reads the whole "<name>\0<data>" blob; returns it (caller frees) with the
 * data offset in *data_off, or NULL if there is no such file. */
static char *secret_get(const char *filename, size_t *blob_len, size_t *data_off)
{
    nvs_handle_t h;
    if (nvs_open(SECRET_NS, NVS_READONLY, &h) != ESP_OK) {
        return NULL;
    }
    char key[16];
    secret_key(filename, key);
    size_t len = 0;
    char *blob = NULL;
    if (nvs_get_blob(h, key, NULL, &len) == ESP_OK && len > 0 && (blob = malloc(len + 1)) != NULL) {
        if (nvs_get_blob(h, key, blob, &len) != ESP_OK) {
            free(blob);
            blob = NULL;
        }
    }
    nvs_close(h);
    if (!blob) {
        return NULL;
    }
    blob[len] = '\0';
    size_t name_len = strnlen(blob, len);
    if (name_len >= len || strcmp(blob, filename) != 0) {
        free(blob);
        return NULL;
    }
    *blob_len = len;
    *data_off = name_len + 1;
    return blob;
}

static bool secret_put(const char *filename, const void *data, size_t len)
{
    size_t name_len = strlen(filename);
    char *blob = malloc(name_len + 1 + len);
    if (!blob) {
        return false;
    }
    memcpy(blob, filename, name_len + 1);
    memcpy(blob + name_len + 1, data, len);
    nvs_handle_t h;
    bool ok = false;
    if (nvs_open(SECRET_NS, NVS_READWRITE, &h) == ESP_OK) {
        char key[16];
        secret_key(filename, key);
        ok = nvs_set_blob(h, key, blob, name_len + 1 + len) == ESP_OK && nvs_commit(h) == ESP_OK;
        nvs_close(h);
    }
    memset(blob, 0, name_len + 1 + len);
    free(blob);
    return ok;
}

static bool secret_erase(const char *filename)
{
    nvs_handle_t h;
    if (nvs_open(SECRET_NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    char key[16];
    secret_key(filename, key);
    bool ok = nvs_erase_key(h, key) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

/* ---- SPIFFS backend ------------------------------------------------------ */

/* Overwrites a SPIFFS file with zeros before deleting it, so a private key
 * that sat there in the clear isn't trivially left behind (SPIFFS may still
 * keep stale pages until they are garbage-collected). */
static void spiffs_wipe_remove(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > 0) {
        FILE *f = fopen(path, "r+b");
        if (f) {
            static const char zeros[256];
            for (long left = st.st_size; left > 0; left -= (long)sizeof(zeros)) {
                fwrite(zeros, 1, left < (long)sizeof(zeros) ? (size_t)left : sizeof(zeros), f);
            }
            fclose(f);
        }
    }
    remove(path);
}

static char *spiffs_read_alloc(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    char *buf = (size >= 0) ? malloc((size_t)size + 1) : NULL;
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) {
        *out_len = n;
    }
    return buf;
}

#define MIGRATE_KEEP_MAX (48 * 1024) /* public files held in RAM across a reformat */

/* Moves private-key files an older firmware stored in plain SPIFFS into
 * encrypted NVS (one-time, at boot). */
static void migrate_secrets(void)
{
    DIR *dir = opendir(FS_BASE_PATH);
    if (!dir) {
        return;
    }
    char names[16][FS_STORE_NAME_MAX + 1];
    int count = 0;
    bool can_format = true; /* false once any file couldn't be kept in RAM */
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (count == 16 || !fs_store_name_valid(ent->d_name)) {
            can_format = false;
            continue;
        }
        strlcpy(names[count++], ent->d_name, sizeof(names[0]));
    }
    closedir(dir);

    /* Public files stay in RAM so SPIFFS can be reformatted afterwards. */
    char *keep[16] = {0};
    size_t keep_len[16] = {0}, keep_total = 0;
    int moved = 0;
    for (int i = 0; i < count; i++) {
        char path[64];
        fs_store_path(names[i], path, sizeof(path));
        size_t len;
        char *data = spiffs_read_alloc(path, &len);
        if (!data) {
            can_format = false;
            continue;
        }
        if (fs_store_is_secret(names[i], data, len)) {
            if (len <= FS_STORE_SECRET_MAX && secret_put(names[i], data, len)) {
                spiffs_wipe_remove(path);
                moved++;
                ESP_LOGI(TAG, "moved %s into encrypted NVS", names[i]);
            } else {
                can_format = false; /* still needed from SPIFFS */
                ESP_LOGW(TAG, "%s holds a private key but could not be moved into NVS", names[i]);
            }
            memset(data, 0, len);
            free(data);
        } else if (keep_total + len <= MIGRATE_KEEP_MAX) {
            keep[i] = data;
            keep_len[i] = len;
            keep_total += len;
        } else {
            can_format = false;
            free(data);
        }
    }

    /* SPIFFS never overwrites in place: a deleted file's pages, the key
     * included, stay in flash until garbage collection reuses the block.
     * Reformatting erases every block, so no plaintext key survives the
     * move. Skipped (with a warning) if the public files didn't fit in RAM. */
    if (moved > 0) {
        if (can_format && esp_spiffs_format("storage") == ESP_OK) {
            for (int i = 0; i < count; i++) {
                if (keep[i]) {
                    char path[64];
                    fs_store_path(names[i], path, sizeof(path));
                    FILE *f = fopen(path, "wb");
                    if (!f || fwrite(keep[i], 1, keep_len[i], f) != keep_len[i]) {
                        ESP_LOGE(TAG, "lost %s while reformatting storage", names[i]);
                    }
                    if (f) {
                        fclose(f);
                    }
                }
            }
            ESP_LOGI(TAG, "storage reformatted to drop stale key pages");
        } else {
            ESP_LOGW(TAG, "stale key pages may remain in storage -- erase the storage partition");
        }
    }
    for (int i = 0; i < count; i++) {
        free(keep[i]);
    }
}

void fs_store_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = FS_BASE_PATH,
        .partition_label = "storage",
        .max_files = 8,
        .format_if_mount_failed = true,
    };
    esp_err_t err = esp_vfs_spiffs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mount failed: %s", esp_err_to_name(err));
        return;
    }
    size_t total = 0, used = 0;
    esp_spiffs_info("storage", &total, &used);
    ESP_LOGI(TAG, "storage ready: %u/%u bytes used", (unsigned)used, (unsigned)total);
    migrate_secrets();
}

bool fs_store_name_valid(const char *filename)
{
    if (!filename || filename[0] == '\0' || filename[0] == '.') {
        return false;
    }
    size_t len = 0;
    for (const char *c = filename; *c; c++, len++) {
        bool ok = (*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') ||
                  *c == '.' || *c == '_' || *c == '-';
        if (!ok || len >= FS_STORE_NAME_MAX) {
            return false;
        }
    }
    return true;
}

bool fs_store_path(const char *filename, char *out, size_t out_size)
{
    if (!fs_store_name_valid(filename)) {
        if (out_size > 0) {
            out[0] = '\0';
        }
        return false;
    }
    snprintf(out, out_size, "%s/%s", FS_BASE_PATH, filename);
    return true;
}

/* ---- Public API over both backends ---------------------------------------- */

bool fs_store_write(const char *filename, const void *data, size_t len)
{
    char path[64];
    if (!fs_store_path(filename, path, sizeof(path))) {
        return false;
    }
    if (fs_store_is_secret(filename, data, len)) {
        if (len > FS_STORE_SECRET_MAX || !secret_put(filename, data, len)) {
            return false;
        }
        spiffs_wipe_remove(path); /* an older non-secret copy, if any */
        return true;
    }
    FILE *f = fopen(path, "wb");
    if (!f) {
        return false;
    }
    bool ok = fwrite(data, 1, len, f) == len;
    fclose(f);
    if (!ok) {
        remove(path);
        return false;
    }
    secret_erase(filename); /* an older secret copy, if any */
    return true;
}

char *fs_store_read_alloc(const char *filename, size_t *out_len)
{
    char path[64];
    if (!fs_store_path(filename, path, sizeof(path))) {
        return NULL;
    }
    size_t blob_len, off;
    char *blob = secret_get(filename, &blob_len, &off);
    if (blob) {
        memmove(blob, blob + off, blob_len - off + 1); /* includes the NUL */
        if (out_len) {
            *out_len = blob_len - off;
        }
        return blob;
    }
    return spiffs_read_alloc(path, out_len);
}

bool fs_store_read(const char *filename, char *out, size_t out_cap, size_t *out_len)
{
    size_t len;
    char *data = fs_store_read_alloc(filename, &len);
    if (!data || out_cap == 0) {
        free(data);
        return false;
    }
    size_t n = len < out_cap - 1 ? len : out_cap - 1;
    memcpy(out, data, n);
    out[n] = '\0';
    memset(data, 0, len);
    free(data);
    if (out_len) {
        *out_len = n;
    }
    return true;
}

bool fs_store_remove(const char *filename)
{
    char path[64];
    if (!fs_store_path(filename, path, sizeof(path))) {
        return false;
    }
    bool removed = secret_erase(filename);
    struct stat st;
    if (stat(path, &st) == 0) {
        spiffs_wipe_remove(path);
        removed = true;
    }
    return removed;
}

bool fs_store_exists(const char *filename)
{
    char path[64];
    if (!fs_store_path(filename, path, sizeof(path))) {
        return false;
    }
    size_t blob_len, off;
    char *blob = secret_get(filename, &blob_len, &off);
    if (blob) {
        memset(blob, 0, blob_len);
        free(blob);
        return true;
    }
    struct stat st;
    return stat(path, &st) == 0;
}

size_t fs_store_size(const char *filename)
{
    char path[64];
    if (!fs_store_path(filename, path, sizeof(path))) {
        return 0;
    }
    size_t blob_len, off;
    char *blob = secret_get(filename, &blob_len, &off);
    if (blob) {
        memset(blob, 0, blob_len);
        free(blob);
        return blob_len - off;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return (size_t)st.st_size;
}

size_t fs_store_list(fs_store_entry_t *out, size_t max_entries)
{
    size_t count = 0;
    DIR *dir = opendir(FS_BASE_PATH);
    if (dir) {
        struct dirent *ent;
        while (count < max_entries && (ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '\0') {
                continue;
            }
            strlcpy(out[count].name, ent->d_name, sizeof(out[count].name));
            out[count].size = fs_store_size(ent->d_name);
            count++;
        }
        closedir(dir);
    }

    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, SECRET_NS, NVS_TYPE_BLOB, &it);
    while (err == ESP_OK && count < max_entries) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        nvs_handle_t h;
        if (nvs_open(SECRET_NS, NVS_READONLY, &h) == ESP_OK) {
            size_t len = 0;
            char *blob = NULL;
            if (nvs_get_blob(h, info.key, NULL, &len) == ESP_OK && len > 0 && (blob = malloc(len)) != NULL &&
                nvs_get_blob(h, info.key, blob, &len) == ESP_OK) {
                size_t name_len = strnlen(blob, len);
                if (name_len < len) {
                    strlcpy(out[count].name, blob, sizeof(out[count].name));
                    out[count].size = len - name_len - 1;
                    count++;
                }
            }
            if (blob) {
                memset(blob, 0, len);
                free(blob);
            }
            nvs_close(h);
        }
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    return count;
}

bool fs_store_cert_fingerprint(const char *filename, char *hex_out, size_t hex_out_size)
{
    if (hex_out_size < 32 * 3) {
        return false;
    }
    size_t n;
    char *buf = fs_store_read_alloc(filename, &n);
    if (!buf) {
        return false;
    }

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    /* n+1 to include the NUL byte -- mbedtls_x509_crt_parse() only
     * auto-detects PEM when buf[buflen-1]=='\0' (see the WF_EAPCERT fix,
     * doc/M2M-AT_Command Set_status.xlsx). */
    int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char *)buf, n + 1);
    memset(buf, 0, n);
    free(buf);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    unsigned char hash[32];
    mbedtls_sha256(crt.raw.p, crt.raw.len, hash, 0);
    for (int i = 0; i < 32; i++) {
        snprintf(hex_out + i * 3, 4, "%02X:", hash[i]);
    }
    hex_out[32 * 3 - 1] = '\0';
    mbedtls_x509_crt_free(&crt);
    return true;
}

static int strength_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

/* 112-bit security strength (EN 18031-1 CCK-1 / SOG-IS): RSA >= 2048 bits,
 * EC >= 256 bits (P-256 and up). Anything else (DSA, unknown) fails. */
static bool pk_strong_enough(const mbedtls_pk_context *pk, char *why, size_t why_size, const char *what)
{
    size_t bits = mbedtls_pk_get_bitlen(pk);
    mbedtls_pk_type_t type = mbedtls_pk_get_type(pk);
    bool ok = (type == MBEDTLS_PK_RSA && bits >= 2048) ||
              ((type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECDSA) && bits >= 256);
    if (!ok) {
        snprintf(why, why_size, "%s is %s-%u (minimum RSA-2048 / EC P-256)", what,
                 type == MBEDTLS_PK_RSA ? "RSA" : (type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECDSA) ? "EC" : "other",
                 (unsigned)bits);
    }
    return ok;
}

bool fs_store_check_pem_strength(const void *data, size_t len, char *why, size_t why_size)
{
    why[0] = '\0';
    /* mbedtls needs a NUL-terminated copy (PEM autodetect, strstr()). */
    char *buf = malloc(len + 1);
    if (!buf) {
        snprintf(why, why_size, "out of memory");
        return false;
    }
    memcpy(buf, data, len);
    buf[len] = '\0';

    bool ok = true;
    if (strstr(buf, "-----BEGIN CERTIFICATE-----")) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        /* A positive return means some blocks failed to parse. */
        if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)buf, len + 1) != 0) {
            snprintf(why, why_size, "certificate does not parse");
            ok = false;
        }
        for (const mbedtls_x509_crt *c = &crt; ok && c && c->raw.p; c = c->next) {
            ok = pk_strong_enough(&c->pk, why, why_size, "certificate key");
        }
        mbedtls_x509_crt_free(&crt);
    }
    if (ok && strstr(buf, "PRIVATE KEY-----")) {
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        int ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)buf, len + 1, NULL, 0, strength_rng, NULL);
        if (ret == 0) {
            ok = pk_strong_enough(&pk, why, why_size, "private key");
        } else if (ret != MBEDTLS_ERR_PK_PASSWORD_REQUIRED) {
            snprintf(why, why_size, "private key does not parse");
            ok = false;
        }
        mbedtls_pk_free(&pk);
    }
    memset(buf, 0, len); /* may hold a private key */
    free(buf);
    return ok;
}

bool fs_store_check_key_strength(const char *filename, char *why, size_t why_size)
{
    size_t n;
    char *buf = fs_store_read_alloc(filename, &n);
    if (!buf) {
        snprintf(why, why_size, "cannot open file");
        return false;
    }
    bool ok = fs_store_check_pem_strength(buf, n, why, why_size);
    memset(buf, 0, n);
    free(buf);
    return ok;
}
