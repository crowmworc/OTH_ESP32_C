#pragma once
/* Release-identity constants, per doc/M2M_SW Release Naming Guide v2.0
 * section 6.1 ("공통 코드는 빌드 스크립트가 만드는 버전 헤더(m2m_version.h)를
 * 사용한다"). Values are derived from this project's Kconfig
 * (main/Kconfig.projbuild, "M2M Release Naming" menu, backed by
 * 03_설계문서/M2M_Code Register.xlsx's registered codes) plus PROJECT_VER
 * (top-level CMakeLists.txt remains the single source of truth for the
 * version number -- see that file's own comment), supplied as a compile
 * definition from components/at_modem/CMakeLists.txt.
 *
 * Do not hand-edit the macros below -- change the Kconfig choices
 * (idf.py menuconfig -> "M2M Release Naming") or PROJECT_VER instead. */

#include "sdkconfig.h"

#ifndef M2M_FW_VERSION_STR
#error "M2M_FW_VERSION_STR must come from a compile definition (see components/at_modem/CMakeLists.txt)"
#endif

/* <MM>.<NN>, e.g. "01.00" -- must equal PROJECT_VER (release checklist item
 * 1); AT*M2M*SYS_VER and AT*M2M*OTA_CHECK report this verbatim. */
#define M2M_FW_VERSION M2M_FW_VERSION_STR

/* <CUSTOMER><REL>, e.g. "AC0" -- AT*M2M*SYS_VER's separate customer_code
 * field. Not used for OTA version comparison (doc: MM/NN only). */
#define M2M_FW_CUSTOMER CONFIG_M2M_CUSTOMER_CODE CONFIG_M2M_REL_CODE

/* <HW> = <CHIP>-<BOARD>-<FLASH>-<CLK>, e.g. "EC3-MA0-N04-40M". */
#define M2M_FW_HW \
    CONFIG_M2M_CHIP_CODE "-" CONFIG_M2M_BOARD_CODE "-" CONFIG_M2M_FLASH_CODE "-" CONFIG_M2M_CLK_CODE

/* <HW>_<CMD>_<CUSTOMER><REL>, e.g. "EC3-MA0-N04-40M_MM_AC0"
 * (OTH-AT build: "..._OT_AC0") -- never shown
 * to the host; AT*M2M*OTA_UPDATE compares a downloaded image's own copy of
 * this (embedded the same way, see m2m_image_id.c) against this running
 * image's copy before installing it (doc reason 5). */
#define M2M_FW_IMAGE_ID \
    M2M_FW_HW "_" CONFIG_M2M_CMD_CODE "_" CONFIG_M2M_CUSTOMER_CODE CONFIG_M2M_REL_CODE

/* Sized generously above M2M_FW_IMAGE_ID's actual max length (15 + 1 + 2 +
 * 1 + 3 = 22 chars) so future longer codes (registry growth) don't need a
 * layout change here -- would need a re-release either way since it's part
 * of the fixed .rodata_custom_desc layout every image carries. */
typedef struct {
    char id[64];
} m2m_image_id_t;

/* Defined in m2m_image_id.c; this running image's own copy of M2M_FW_IMAGE_ID. */
extern const m2m_image_id_t m2m_image_id;
