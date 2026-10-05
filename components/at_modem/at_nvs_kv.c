#include "at_nvs_kv.h"
#include "nvs.h"

#define M2M_NVS_NAMESPACE "m2m_sys"

esp_err_t m2m_nvs_get_str(const char *key, char *out, size_t *len)
{
    out[0] = '\0';
    nvs_handle_t h;
    esp_err_t err = nvs_open(M2M_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_str(h, key, out, len);
    nvs_close(h);
    if (err != ESP_OK) {
        out[0] = '\0';
    }
    return err;
}

void m2m_nvs_set_str(const char *key, const char *value)
{
    nvs_handle_t h;
    if (nvs_open(M2M_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_str(h, key, value);
    nvs_commit(h);
    nvs_close(h);
}

esp_err_t m2m_nvs_get_u16(const char *key, uint16_t *out)
{
    *out = 0;
    nvs_handle_t h;
    esp_err_t err = nvs_open(M2M_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_u16(h, key, out);
    nvs_close(h);
    if (err != ESP_OK) {
        *out = 0;
    }
    return err;
}

void m2m_nvs_set_u16(const char *key, uint16_t value)
{
    nvs_handle_t h;
    if (nvs_open(M2M_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_u16(h, key, value);
    nvs_commit(h);
    nvs_close(h);
}

esp_err_t m2m_nvs_get_u32(const char *key, uint32_t *out)
{
    *out = 0;
    nvs_handle_t h;
    esp_err_t err = nvs_open(M2M_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_u32(h, key, out);
    nvs_close(h);
    if (err != ESP_OK) {
        *out = 0;
    }
    return err;
}

void m2m_nvs_set_u32(const char *key, uint32_t value)
{
    nvs_handle_t h;
    if (nvs_open(M2M_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_u32(h, key, value);
    nvs_commit(h);
    nvs_close(h);
}
