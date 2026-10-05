#pragma once
/* Configuration web server credentials, login throttling and session state
 * (EN 18031-1 AUM-3/4/5/6, SSM-3) -- shared by cmd_httpd.c's HTTP routes and
 * its AT*M2M*NET_HTTPDCONF handler. See web_auth.c for the design notes. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEB_AUTH_ID_MAX  31 /* characters, excluding NUL */
#define WEB_AUTH_PW_MIN  8
#define WEB_AUTH_PW_MAX  64

typedef enum {
    WEB_AUTH_OK = 0,
    WEB_AUTH_BAD_CREDENTIALS,
    WEB_AUTH_LOCKED,
} web_auth_result_t;

typedef enum {
    WEB_AUTH_POLICY_OK = 0,
    WEB_AUTH_POLICY_ID,        /* id empty, too long or non-printable */
    WEB_AUTH_POLICY_LENGTH,    /* password shorter/longer than allowed */
    WEB_AUTH_POLICY_CHARSET,   /* password has a space/control/non-ASCII char */
    WEB_AUTH_POLICY_WEAK,      /* no letter+digit mix, equals the id, or equals the factory default */
} web_auth_policy_t;

/* Loads the stored credentials; converts a pre-hash plaintext password left
 * in NVS by an older firmware. Call once at startup, before the server can
 * start. */
void web_auth_init(void);

/* Current login id (factory default "admin" until changed). */
void web_auth_get_id(char *out, size_t out_size);

/* True while the factory default password is still in effect -- the web
 * server then only allows the password-change route (AUM-5-1). */
bool web_auth_must_change(void);

/* Checks id+password, applying the brute-force lockout (AUM-6). On
 * WEB_AUTH_LOCKED, *retry_after_s (if non-NULL) is the remaining lockout. */
web_auth_result_t web_auth_login(const char *id, const char *password, uint32_t *retry_after_s);

/* Checks a new id/password pair against the password policy (AUM-3/5-2). */
web_auth_policy_t web_auth_check_policy(const char *id, const char *password);
const char *web_auth_policy_text(web_auth_policy_t p);

/* Stores new credentials (salted PBKDF2 hash, never the plaintext) after a
 * policy check. Clears the must-change state. Returns the policy verdict --
 * nothing is stored unless it is WEB_AUTH_POLICY_OK. */
web_auth_policy_t web_auth_set(const char *id, const char *password);

/* ---- sessions (one logged-in session at a time) ---- */

/* Creates a new session and writes its token (hex, NUL-terminated) to out. */
#define WEB_AUTH_TOKEN_LEN 32
void web_auth_session_new(char out[WEB_AUTH_TOKEN_LEN + 1]);

/* True if the Cookie header value carries the live, non-expired session
 * token; refreshes its idle timer. */
bool web_auth_session_check(const char *cookie_header);

void web_auth_session_clear(void);

#ifdef __cplusplus
}
#endif
