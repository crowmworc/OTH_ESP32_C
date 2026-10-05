#pragma once
/* Named file storage for AT*M2M*NET_HTTPDOWNLOAD, the web certificate
 * upload and AWS provisioning, referenced by name from NET_CONN=ssl/
 * NET_SERVER=ssl/MQTT_CONF/WF_EAPCERT/AWS_CLAIMCERT/NET_HTTPDSTART.
 *
 * Two backends behind one name space (EN 18031-1 SSM-2/SSM-3, to-do B-03):
 * a file holding a private key -- a PEM "PRIVATE KEY" block, or a name
 * ending in .key/.p12/.pfx/.pac -- is kept in the encrypted NVS partition
 * (CONFIG_NVS_ENCRYPTION, HMAC eFuse key), everything else in the plain
 * SPIFFS "storage" partition. Callers never see the difference; always go
 * through these functions rather than fopen() on a path. */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Mounts (formatting on first boot / corruption) the "storage" SPIFFS
 * partition at /spiffs, then moves any private-key file an older firmware
 * left in SPIFFS into encrypted NVS. Call once at startup, after NVS init. */
void fs_store_init(void);

/** True if `filename` is an acceptable storage file name: 1..FS_STORE_NAME_MAX
 * characters of [A-Za-z0-9._-], not starting with '.' (no path separators,
 * no "..", nothing SPIFFS would silently truncate -- EN 18031-1 GEC-6). */
#define FS_STORE_NAME_MAX 30
bool fs_store_name_valid(const char *filename);

/** Largest file kept in encrypted NVS (a private key, usually with its
 * certificate chain). A larger private-key file is refused. */
#define FS_STORE_SECRET_MAX (8 * 1024)

/** True if (name, data) must live in encrypted NVS -- see the file header.
 * `data` may be NULL to decide on the name alone. */
bool fs_store_is_secret(const char *filename, const void *data, size_t len);

/** Resolves a bare filename to its SPIFFS path ("/spiffs/<name>") into
 * `out`, for streaming a large non-secret file (NET_HTTPDOWNLOAD). A name
 * that fails fs_store_name_valid() yields an empty path and returns false. */
bool fs_store_path(const char *filename, char *out, size_t out_size);

/** Stores a whole file, replacing any earlier one of that name in either
 * backend. A secret over FS_STORE_SECRET_MAX is refused (false). */
bool fs_store_write(const char *filename, const void *data, size_t len);

/** Reads a whole file into a new heap buffer, NUL-terminated (*out_len,
 * optional, excludes the NUL). NULL if missing. Caller frees. */
char *fs_store_read_alloc(const char *filename, size_t *out_len);

/** Reads a file into `out` (at most out_cap - 1 bytes, NUL-terminated);
 * *out_len (optional) gets the byte count. False if missing. */
bool fs_store_read(const char *filename, char *out, size_t out_cap, size_t *out_len);

/** Deletes the named file from whichever backend holds it. */
bool fs_store_remove(const char *filename);

/** True if the named file exists. */
bool fs_store_exists(const char *filename);

/** One entry from fs_store_list(). */
typedef struct {
    char name[64];
    size_t size;
} fs_store_entry_t;

/** Lists stored files (both backends) into `out` (caller-provided array of
 * `max_entries`). Returns the number of entries written (capped at
 * max_entries even if more files exist). For AT*M2M*NET_FILELIST. */
size_t fs_store_list(fs_store_entry_t *out, size_t max_entries);

/** Size in bytes of the named file, or 0 if it doesn't exist. */
size_t fs_store_size(const char *filename);

/** If the named file parses as a PEM X.509 certificate, writes its
 * SHA-256 fingerprint as a colon-separated uppercase hex string (e.g.
 * "14:05:37:...") into hex_out (needs >= 96 bytes) and returns true.
 * Returns false for non-certificate files (keys, PAC blobs, etc.) or
 * parse failures -- not an error, just "no fingerprint to show". */
bool fs_store_cert_fingerprint(const char *filename, char *hex_out, size_t hex_out_size);

/** EN 18031-1 CCK-1 (112-bit minimum): checks every certificate and the
 * private key (if any) in `data`. Returns false -- with a short reason in
 * `why` -- when one is weaker than RSA-2048 / EC P-256, or a PEM block
 * can't be parsed at all. Non-PEM data and password-protected keys (which
 * can't be opened without their password) pass. */
bool fs_store_check_pem_strength(const void *data, size_t len, char *why, size_t why_size);

/** fs_store_check_pem_strength() on a stored file. */
bool fs_store_check_key_strength(const char *filename, char *why, size_t why_size);

#ifdef __cplusplus
}
#endif
