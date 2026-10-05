#pragma once
/* Tiny shared NVS accessor for AT command persistent state (SYS_CONF
 * attributes, SYS_COUNTRY, SYS_UART baud). All keys live in one namespace so
 * a single AT*M2M*SYS_FACTORY erase wipes everything at once. */

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* out must be pre-sized via *len (in/out, like nvs_get_str); on any failure
 * (including "not found") out[0] is set to '\0' so callers can treat the
 * return value as "the default applies" without a separate branch. */
esp_err_t m2m_nvs_get_str(const char *key, char *out, size_t *len);
void      m2m_nvs_set_str(const char *key, const char *value);

/* On failure *out is set to 0. */
esp_err_t m2m_nvs_get_u16(const char *key, uint16_t *out);
void      m2m_nvs_set_u16(const char *key, uint16_t value);

esp_err_t m2m_nvs_get_u32(const char *key, uint32_t *out);
void      m2m_nvs_set_u32(const char *key, uint32_t value);

#ifdef __cplusplus
}
#endif
