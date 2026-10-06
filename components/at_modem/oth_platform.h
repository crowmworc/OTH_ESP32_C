#pragma once
/* OTH Platform service -- internal interfaces shared by the OTH-AT AWS IoT
 * client (cmd_oth_aws.c), the SoftAP pairing server (oth_pairing.c) and
 * the cloud-driven firmware upgrade of the module and the host MCU
 * (oth_fota.c). Built only with CONFIG_AT_MODEM_CMDSET_OTH.
 *
 * Flow: the module runs a SoftAP; the smartphone app joins it and, over
 * TCP (oth_pairing.c), hands over the server information (root CA URLs,
 * authentication server, MQTT endpoint/port, region) and the home AP.
 * Once the module has an IP address on the home AP, cmd_oth_aws.c obtains
 * a token and the device certificate/key from the authentication server,
 * downloads the root CA and connects to the AWS IoT endpoint. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- cmd_oth_aws.c ------------------------------------------------------ */

/* Stores the server information received during pairing (NULL / 0 leaves a
 * field unchanged) and drops the credentials obtained for the previous
 * server, so the next connection authenticates again. */
void oth_aws_set_server_info(const char *rootca1_url, const char *rootca2_url, const char *auth_url,
                             const char *endpoint, uint16_t port, uint8_t region);

/* Publishes an A510 (module firmware) / A520 (MCU firmware) progress event:
 * fw_cd 102 request accepted, 201 downloading, 202 downloaded, 301
 * installing, 900 failed (err_cd then non-zero). No-op when not connected. */
void oth_aws_publish_fw_progress(const char *api_no, const char *fw_cd, const char *err_cd,
                                 const char *fw_ver);

/* The host MCU firmware version reported by MCU_READY ("" until then). */
const char *oth_aws_mcu_version(void);

/* An MCU firmware update ordered over the cloud finished: the next A100
 * reports versionChangeM "true"; crc is kept as AWS_GET index 11. */
void oth_aws_note_mcu_updated(uint32_t crc);

/* Removes the stored credentials and root CA (factory reset). */
void oth_aws_forget(void);

/* ---- oth_pairing.c ------------------------------------------------------ */

void oth_pairing_init(void);
/* Station got an IP address: completes a home-AP join ordered by the app. */
void oth_pairing_on_ip(void);

/* ---- oth_fota.c --------------------------------------------------------- */

/* Module firmware upgrade ordered with A511/A531: plain (url) or encrypted
 * (enc_url + enc_key) image, SHA-256 checked when hash is given; reboots
 * into the new image on success. */
void oth_fota_wifi_install(const char *ver, const char *url, const char *enc_url, const char *enc_key,
                           const char *hash);
/* MCU firmware upgrade ordered with A521: the image is staged on the module
 * and relayed to the host with the MOTA_* commands. */
void oth_fota_mcu_install(const char *ver, const char *url, const char *enc_url, const char *enc_key,
                          const char *hash);
/* True once after the boot that follows a module firmware upgrade. */
bool oth_fota_take_version_changed(void);
/* This image's version as an integer, MM.NN -> MM*100+NN (A100/A500 V01). */
int oth_fota_wifi_version(void);

#ifdef __cplusplus
}
#endif
