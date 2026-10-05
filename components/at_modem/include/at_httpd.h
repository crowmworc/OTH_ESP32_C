#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AT*M2M*NET_HTTPDSTART's config "is stored in NV memory and survives a
 * reboot" (doc Ch.6.3) -- call once at startup to auto-restart the
 * configuration web server if it was left enabled.
 */
void at_httpd_init(void);

#ifdef __cplusplus
}
#endif
