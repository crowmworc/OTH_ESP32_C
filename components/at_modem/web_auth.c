/* Configuration web server credentials, login throttling and session state.
 *
 * Added 2026-09-27 for EN 18031-1 (see doc/EN18031-1_To-Do.xlsx, Phase A):
 *
 * - AUM-5-1 (factory default passwords): the factory default stays the doc's
 *   own NET_HTTPDCONF example, admin/admin, but it only ever unlocks the
 *   password-change route -- cmd_httpd.c refuses every other /api and /ota
 *   request with 403 until web_auth_must_change() goes false. "Default in
 *   effect" is simply "no password hash stored in NVS", so SYS_FACTORY's NVS
 *   erase brings the forced change back with no extra state to keep in sync.
 * - AUM-3 / AUM-5-2 (authenticator validation, password strength): policy in
 *   web_auth_check_policy() -- 8..64 printable ASCII characters, at least one
 *   letter and one digit, not equal to the id or to the factory default.
 *   Applied to both the web route and AT*M2M*NET_HTTPDCONF. Comparisons use
 *   mbedtls_ct_memcmp() so response timing doesn't leak how much matched.
 * - AUM-4 (changing authenticators): web_auth_set(), reachable from the web
 *   UI itself (POST /api/password) as well as from the host over AT.
 * - AUM-6 (brute force): 5 consecutive failures lock logins for 60 s; each
 *   further lockout doubles that, capped at 1 h. A correct password is
 *   refused while locked too. The lockout round counter is kept in NVS so a
 *   reboot doesn't reset it -- on boot a stored round re-applies its lockout
 *   from power-on. A successful login, or new credentials set over AT (the
 *   host, an authorized entity, recovering access), clears it.
 *   Trade-off noted for the evaluation: the lockout is global rather than
 *   per client, so an attacker can keep the legitimate user locked out for
 *   up to the cap; the AT interface stays available to recover.
 * - SSM-3 (confidential security parameters at rest): only a salted
 *   PBKDF2-HMAC-SHA256 hash of the password is stored, never the password.
 *   A plaintext "httpd_pw" left by older firmware is converted on first boot
 *   and erased.
 *
 * Sessions: one at a time (single-owner device, same as before), 16 random
 * bytes from the hardware RNG, expiring after 10 min idle or 12 h total. */

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "esp_random.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/constant_time.h"

#include "at_nvs_kv.h"
#include "web_auth.h"

static const char *TAG = "web_auth";

#define DEFAULT_ID "admin"
#define DEFAULT_PW "admin"

#define SALT_LEN   16
#define HASH_LEN   32
#define PBKDF2_ITERATIONS 10000

#define LOCK_AFTER_FAILS   5
#define LOCK_BASE_S        60
#define LOCK_MAX_S         3600
#define LOCK_MAX_ROUNDS    16

#define SESSION_IDLE_US    (10LL * 60 * 1000000)
#define SESSION_MAX_US     (12LL * 3600 * 1000000)

/* NVS keys (namespace shared with the rest of the AT modem, see at_nvs_kv.h) */
#define KEY_ID          "httpd_id"
#define KEY_PW_LEGACY   "httpd_pw"  /* plaintext, pre-2026-09-27 firmware only */
#define KEY_PW_HASH     "httpd_pwh" /* hex(salt) + hex(hash) */
#define KEY_LOCK_ROUNDS "httpd_lkr"

static SemaphoreHandle_t s_lock;

static char s_id[WEB_AUTH_ID_MAX + 1];
static bool s_has_hash;
static uint8_t s_salt[SALT_LEN];
static uint8_t s_hash[HASH_LEN];

static uint8_t s_fail_count;
static uint16_t s_lock_rounds;
static int64_t s_lock_until_us;

static char s_token[WEB_AUTH_TOKEN_LEN + 1];
static int64_t s_token_created_us;
static int64_t s_token_used_us;

/* ---- helpers ---------------------------------------------------------- */

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        snprintf(out + i * 2, 3, "%02x", in[i]);
    }
}

static bool from_hex(const char *in, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (!isxdigit((unsigned char)in[i * 2]) || !isxdigit((unsigned char)in[i * 2 + 1]) ||
            sscanf(in + i * 2, "%2x", &v) != 1) {
            return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

static bool derive(const char *password, const uint8_t salt[SALT_LEN], uint8_t out[HASH_LEN])
{
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)password, strlen(password),
                                         salt, SALT_LEN, PBKDF2_ITERATIONS, HASH_LEN, out) == 0;
}

/* Constant-time string equality (length is not secret here: both sides'
 * lengths are bounded and the comparison still runs over the longer one). */
static bool ct_streq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    size_t n = la > lb ? la : lb;
    char pa[WEB_AUTH_PW_MAX + 1] = {0}, pb[WEB_AUTH_PW_MAX + 1] = {0};
    if (n > WEB_AUTH_PW_MAX) {
        return false;
    }
    memcpy(pa, a, la);
    memcpy(pb, b, lb);
    return (mbedtls_ct_memcmp(pa, pb, n + 1) == 0);
}

static uint32_t lock_duration_s(uint16_t rounds)
{
    uint32_t s = LOCK_BASE_S;
    for (uint16_t i = 1; i < rounds && s < LOCK_MAX_S; i++) {
        s *= 2;
    }
    return s > LOCK_MAX_S ? LOCK_MAX_S : s;
}

/* Stores id + a fresh salted hash; caller holds s_lock. */
static bool store_locked(const char *id, const char *password)
{
    uint8_t salt[SALT_LEN], hash[HASH_LEN];
    esp_fill_random(salt, sizeof(salt));
    if (!derive(password, salt, hash)) {
        return false;
    }
    char hex[(SALT_LEN + HASH_LEN) * 2 + 1];
    to_hex(salt, SALT_LEN, hex);
    to_hex(hash, HASH_LEN, hex + SALT_LEN * 2);
    m2m_nvs_set_str(KEY_ID, id);
    m2m_nvs_set_str(KEY_PW_HASH, hex);
    m2m_nvs_set_str(KEY_PW_LEGACY, "");
    strlcpy(s_id, id, sizeof(s_id));
    memcpy(s_salt, salt, SALT_LEN);
    memcpy(s_hash, hash, HASH_LEN);
    s_has_hash = true;
    return true;
}

/* ---- public ----------------------------------------------------------- */

void web_auth_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }

    size_t len = sizeof(s_id);
    m2m_nvs_get_str(KEY_ID, s_id, &len);
    if (s_id[0] == '\0') {
        strlcpy(s_id, DEFAULT_ID, sizeof(s_id));
    }

    char hex[(SALT_LEN + HASH_LEN) * 2 + 1] = "";
    len = sizeof(hex);
    m2m_nvs_get_str(KEY_PW_HASH, hex, &len);
    s_has_hash = strlen(hex) == (SALT_LEN + HASH_LEN) * 2 && from_hex(hex, s_salt, SALT_LEN) &&
                 from_hex(hex + SALT_LEN * 2, s_hash, HASH_LEN);

    if (!s_has_hash) {
        char legacy[WEB_AUTH_PW_MAX + 1] = "";
        len = sizeof(legacy);
        m2m_nvs_get_str(KEY_PW_LEGACY, legacy, &len);
        if (legacy[0] != '\0') {
            /* Older firmware kept NET_HTTPDCONF's password in plaintext. Keep
             * it working (it was set by the host, an authorized entity) but
             * store only its hash from now on -- unless it is the factory
             * default, which must still be changed on first use. */
            if (strcmp(legacy, DEFAULT_PW) != 0) {
                store_locked(s_id, legacy);
                ESP_LOGI(TAG, "converted stored web password to a salted hash");
            } else {
                m2m_nvs_set_str(KEY_PW_LEGACY, "");
            }
            memset(legacy, 0, sizeof(legacy));
        }
    }

    m2m_nvs_get_u16(KEY_LOCK_ROUNDS, &s_lock_rounds);
    if (s_lock_rounds > 0) {
        s_lock_until_us = esp_timer_get_time() + (int64_t)lock_duration_s(s_lock_rounds) * 1000000;
    }
}

void web_auth_get_id(char *out, size_t out_size)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    strlcpy(out, s_id, out_size);
    xSemaphoreGive(s_lock);
}

bool web_auth_must_change(void)
{
    return !s_has_hash;
}

web_auth_result_t web_auth_login(const char *id, const char *password, uint32_t *retry_after_s)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int64_t now = esp_timer_get_time();
    if (now < s_lock_until_us) {
        if (retry_after_s) {
            *retry_after_s = (uint32_t)((s_lock_until_us - now + 999999) / 1000000);
        }
        xSemaphoreGive(s_lock);
        return WEB_AUTH_LOCKED;
    }

    bool ok = strlen(password) <= WEB_AUTH_PW_MAX && ct_streq(id, s_id);
    if (s_has_hash) {
        uint8_t hash[HASH_LEN];
        bool derived = strlen(password) <= WEB_AUTH_PW_MAX && derive(password, s_salt, hash);
        ok = ok && derived && mbedtls_ct_memcmp(hash, s_hash, HASH_LEN) == 0;
    } else {
        ok = ok && ct_streq(password, DEFAULT_PW);
    }

    if (ok) {
        s_fail_count = 0;
        s_lock_until_us = 0;
        if (s_lock_rounds) {
            s_lock_rounds = 0;
            m2m_nvs_set_u16(KEY_LOCK_ROUNDS, 0);
        }
        xSemaphoreGive(s_lock);
        return WEB_AUTH_OK;
    }

    if (++s_fail_count >= LOCK_AFTER_FAILS) {
        s_fail_count = 0;
        if (s_lock_rounds < LOCK_MAX_ROUNDS) {
            s_lock_rounds++;
        }
        m2m_nvs_set_u16(KEY_LOCK_ROUNDS, s_lock_rounds);
        uint32_t d = lock_duration_s(s_lock_rounds);
        s_lock_until_us = now + (int64_t)d * 1000000;
        ESP_LOGW(TAG, "%d failed logins, locked for %u s", LOCK_AFTER_FAILS, (unsigned)d);
    }
    xSemaphoreGive(s_lock);
    return WEB_AUTH_BAD_CREDENTIALS;
}

web_auth_policy_t web_auth_check_policy(const char *id, const char *password)
{
    size_t il = id ? strlen(id) : 0;
    if (il == 0 || il > WEB_AUTH_ID_MAX) {
        return WEB_AUTH_POLICY_ID;
    }
    for (size_t i = 0; i < il; i++) {
        if (id[i] <= 0x20 || id[i] >= 0x7f) {
            return WEB_AUTH_POLICY_ID;
        }
    }
    size_t pl = password ? strlen(password) : 0;
    if (pl < WEB_AUTH_PW_MIN || pl > WEB_AUTH_PW_MAX) {
        return WEB_AUTH_POLICY_LENGTH;
    }
    bool letter = false, digit = false;
    for (size_t i = 0; i < pl; i++) {
        char c = password[i];
        if (c <= 0x20 || c >= 0x7f) {
            return WEB_AUTH_POLICY_CHARSET;
        }
        letter |= (bool)isalpha((unsigned char)c);
        digit |= (bool)isdigit((unsigned char)c);
    }
    if (!letter || !digit || strcasecmp(password, id) == 0 || strcasecmp(password, DEFAULT_PW) == 0) {
        return WEB_AUTH_POLICY_WEAK;
    }
    return WEB_AUTH_POLICY_OK;
}

const char *web_auth_policy_text(web_auth_policy_t p)
{
    switch (p) {
    case WEB_AUTH_POLICY_OK:      return "ok";
    case WEB_AUTH_POLICY_ID:      return "username must be 1-31 printable characters without spaces";
    case WEB_AUTH_POLICY_LENGTH:  return "password must be 8-64 characters";
    case WEB_AUTH_POLICY_CHARSET: return "password may only contain printable ASCII characters without spaces";
    case WEB_AUTH_POLICY_WEAK:    return "password must mix letters and digits and differ from the username and the default";
    }
    return "invalid";
}

web_auth_policy_t web_auth_set(const char *id, const char *password)
{
    web_auth_policy_t p = web_auth_check_policy(id, password);
    if (p != WEB_AUTH_POLICY_OK) {
        return p;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool stored = store_locked(id, password);
    /* New credentials from an authorized entity also clear any lockout. */
    s_fail_count = 0;
    s_lock_until_us = 0;
    if (s_lock_rounds) {
        s_lock_rounds = 0;
        m2m_nvs_set_u16(KEY_LOCK_ROUNDS, 0);
    }
    xSemaphoreGive(s_lock);
    return stored ? WEB_AUTH_POLICY_OK : WEB_AUTH_POLICY_LENGTH;
}

void web_auth_session_new(char out[WEB_AUTH_TOKEN_LEN + 1])
{
    uint8_t raw[WEB_AUTH_TOKEN_LEN / 2];
    esp_fill_random(raw, sizeof(raw));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    to_hex(raw, sizeof(raw), s_token);
    s_token_created_us = s_token_used_us = esp_timer_get_time();
    strlcpy(out, s_token, WEB_AUTH_TOKEN_LEN + 1);
    xSemaphoreGive(s_lock);
}

bool web_auth_session_check(const char *cookie_header)
{
    const char *p = cookie_header ? strstr(cookie_header, "session=") : NULL;
    if (!p) {
        return false;
    }
    p += 8;
    size_t n = strcspn(p, "; ");
    bool ok = false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_token[0] != '\0' && n == WEB_AUTH_TOKEN_LEN &&
        mbedtls_ct_memcmp(p, s_token, WEB_AUTH_TOKEN_LEN) == 0) {
        int64_t now = esp_timer_get_time();
        if (now - s_token_used_us > SESSION_IDLE_US || now - s_token_created_us > SESSION_MAX_US) {
            s_token[0] = '\0'; /* expired */
        } else {
            s_token_used_us = now;
            ok = true;
        }
    }
    xSemaphoreGive(s_lock);
    return ok;
}

void web_auth_session_clear(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_token, 0, sizeof(s_token));
    xSemaphoreGive(s_lock);
}
