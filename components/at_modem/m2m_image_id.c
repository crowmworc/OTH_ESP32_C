/* Embeds this build's M2M_FW_IMAGE_ID into a fixed, well-known section
 * (.rodata_custom_desc) right after esp_app_desc_t in the app image's DROM
 * segment -- an ESP-IDF-reserved section (see
 * $IDF_PATH/components/esp_system/ld/esp32c3/sections.ld.in: "Should be the
 * second. Custom app version info."), read back via a raw esp_partition_read()
 * at a fixed offset (sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)
 * + sizeof(esp_app_desc_t), matching esp_ota_get_partition_description()'s own
 * offset math) rather than any new custom API. See m2m_version.h and
 * cmd_ota.c's OTA_UPDATE reason-5 check.
 *
 * The `-u m2m_image_id` linker flag in components/at_modem/CMakeLists.txt
 * keeps this symbol from being dropped as unreferenced (nothing in this
 * firmware ever reads its own m2m_image_id at runtime -- only a *future*
 * OTA image's copy is read, from flash, by the *currently running* image). */

#include "m2m_version.h"

const __attribute__((section(".rodata_custom_desc")))
m2m_image_id_t m2m_image_id = { .id = M2M_FW_IMAGE_ID };
