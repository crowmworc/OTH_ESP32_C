/* OTH Platform pairing server -- TCP port CONFIG_AT_MODEM_OTH_PAIRING_PORT
 * (47000) on the SoftAP. The smartphone app joins the module's SoftAP
 * (SMODE / AUCONMODE=0 2) and hands over the cloud server information and
 * the home AP; the module then joins the home AP and, with an IP address,
 * connects to AWS IoT (cmd_oth_aws.c).
 *
 * Packet: 20-byte header, little-endian --
 *   Length(4) = 12 + payload length, Magic(4) "GEN2", DataType(2),
 *   Reserved(10) -- followed by the payload.
 *   0x0100 -> 0x0101  device information. Request: mode(1) [random(4)];
 *                     mode 1 switches on AES-128-ECB for the rest of the
 *                     session, key = random[0..3] interleaved with the
 *                     station MAC in upper-case hex (see pairing_key()).
 *                     Response: device name(16) = MIB 18, model name(32) =
 *                     MIB 19, status(1) 0 idle / 1 SoftAP / 2 joined, MCU
 *                     version(16) (MCU_READY), Wi-Fi version(16).
 *   0x0200 -> 0x0201  server information: count(2), count x {len(2) URI},
 *                     port(2), region(1); URIs in order root CA 1, root
 *                     CA 2, authentication server, MQTT endpoint.
 *                     Response: result(1), 0 = success.
 *   0x0300 -> 0x0301  AP scan: total(2), count(2) (max. 50), count x
 *                     {len(2) SSID, BSSID(6), RSSI(2), channel(2),
 *                     security(1)}, result(1). Never encrypted.
 *   0x0400 -> 0x0401  home AP: len(2) SSID, len(2) passphrase. Response:
 *                     result(1); the join follows the response.
 * With AES on, 0x0200/0x0400 payloads arrive encrypted and every response
 * except 0x0301 is PKCS#7-padded (always, even when block-aligned) and
 * encrypted.
 *
 * Connections are served one at a time and only over the SoftAP: a client
 * that reached the module through the home network is closed at once. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "mbedtls/aes.h"

#include "at_commands_oth.h"
#include "at_nvs_kv.h"
#include "at_wifi.h"
#include "oth_platform.h"
#include "sdkconfig.h"

static const char *TAG = "oth_pair";

#define MAGIC       "GEN2"
#define HDR_LEN     20
#define HDR_FIXED   12 /* DataType + Reserved, counted in Length */
#define MAX_PAYLOAD 1024
#define RX_TIMEOUT_S 30

typedef struct {
    mbedtls_aes_context dec, enc;
    bool aes;
} session_t;

static volatile bool s_join_pending;
static esp_timer_handle_t s_ap_stop_timer;

/* ---- framing ---------------------------------------------------------------- */

static bool read_full(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            return false;
        }
        got += (size_t)n;
    }
    return true;
}

static bool write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

/* sess NULL: never encrypted (0x0301). */
static bool send_packet(int fd, uint16_t type, const uint8_t *payload, size_t len, session_t *sess)
{
    uint8_t enc[128];
    if (sess && sess->aes) {
        size_t pad = 16 - (len % 16);
        if (len + pad > sizeof(enc)) {
            return false;
        }
        memcpy(enc, payload, len);
        memset(enc + len, (int)pad, pad);
        len += pad;
        for (size_t off = 0; off < len; off += 16) {
            mbedtls_aes_crypt_ecb(&sess->enc, MBEDTLS_AES_ENCRYPT, enc + off, enc + off);
        }
        payload = enc;
    }
    uint8_t hdr[HDR_LEN] = {0};
    uint32_t total = HDR_FIXED + (uint32_t)len;
    hdr[0] = (uint8_t)total;
    hdr[1] = (uint8_t)(total >> 8);
    hdr[2] = (uint8_t)(total >> 16);
    hdr[3] = (uint8_t)(total >> 24);
    memcpy(hdr + 4, MAGIC, 4);
    hdr[8] = (uint8_t)type;
    hdr[9] = (uint8_t)(type >> 8);
    return write_full(fd, hdr, sizeof(hdr)) && (len == 0 || write_full(fd, payload, len));
}

typedef struct {
    const uint8_t *p;
    size_t left;
} cursor_t;

static bool cur_u16(cursor_t *c, uint16_t *out)
{
    if (c->left < 2) {
        return false;
    }
    *out = (uint16_t)(c->p[0] | (c->p[1] << 8));
    c->p += 2;
    c->left -= 2;
    return true;
}

/* A length-prefixed string; fails when it does not fit out[cap]. */
static bool cur_str(cursor_t *c, char *out, size_t cap)
{
    uint16_t n;
    if (!cur_u16(c, &n) || c->left < n || n >= cap) {
        return false;
    }
    memcpy(out, c->p, n);
    out[n] = '\0';
    c->p += n;
    c->left -= n;
    return true;
}

static void put_u16(uint8_t *b, size_t *off, uint16_t v)
{
    b[(*off)++] = (uint8_t)v;
    b[(*off)++] = (uint8_t)(v >> 8);
}

/* ---- 0x0100 device information ----------------------------------------------- */

static void mac_hex(char out[13])
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, 13, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* key[0,4,8,12] = the four random bytes; the other twelve are the MAC hex
 * digits in the order 0,2,4 / 6,8,10 / 1,3,5 / 7,9,11. */
static void pairing_key(const uint8_t rnd[4], uint8_t key[16])
{
    static const uint8_t pos[12] = { 0, 2, 4, 6, 8, 10, 1, 3, 5, 7, 9, 11 };
    char hex[13];
    mac_hex(hex);
    for (int g = 0, k = 0; g < 4; g++) {
        key[g * 4] = rnd[g];
        for (int i = 1; i < 4; i++) {
            key[g * 4 + i] = (uint8_t)hex[pos[k++]];
        }
    }
}

static uint8_t link_status(void)
{
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        return 2;
    }
    wifi_mode_t m = WIFI_MODE_NULL;
    esp_wifi_get_mode(&m);
    return (m == WIFI_MODE_AP || m == WIFI_MODE_APSTA) ? 1 : 0;
}

static void handle_device_info(int fd, const uint8_t *pl, size_t len, session_t *sess)
{
    if (len >= 5 && pl[0] == 1 && !sess->aes) {
        uint8_t key[16];
        pairing_key(pl + 1, key);
        mbedtls_aes_init(&sess->dec);
        mbedtls_aes_init(&sess->enc);
        mbedtls_aes_setkey_dec(&sess->dec, key, 128);
        mbedtls_aes_setkey_enc(&sess->enc, key, 128);
        memset(key, 0, sizeof(key));
        sess->aes = true;
    }
    uint8_t r[16 + 32 + 1 + 16 + 16] = {0};
    char v[33];
    size_t n = sizeof(v);
    v[0] = '\0';
    m2m_nvs_get_str("c37", v, &n); /* MIB 18 */
    strncpy((char *)r, v, 16);
    n = sizeof(v);
    v[0] = '\0';
    m2m_nvs_get_str("c38", v, &n); /* MIB 19 */
    strncpy((char *)r + 16, v, 32);
    r[48] = link_status();
    strncpy((char *)r + 49, oth_aws_mcu_version(), 16);
    strncpy((char *)r + 65, esp_app_get_description()->version, 16);
    send_packet(fd, 0x0101, r, sizeof(r), sess);
}

/* ---- 0x0200 server information ------------------------------------------------- */

static void handle_server_info(int fd, const uint8_t *pl, size_t len, session_t *sess)
{
    cursor_t c = { pl, len };
    static char uri[4][192];
    uint16_t count = 0, port = 0;
    uint8_t result = 1;
    bool ok = cur_u16(&c, &count) && count >= 1 && count <= 4;
    for (int i = 0; ok && i < count; i++) {
        ok = cur_str(&c, uri[i], sizeof(uri[i]));
    }
    if (ok && cur_u16(&c, &port) && c.left >= 1) {
        oth_aws_set_server_info(uri[0], count > 1 ? uri[1] : "", count > 2 ? uri[2] : "",
                                count > 3 ? uri[3] : "", port, c.p[0]);
        result = 0;
    }
    send_packet(fd, 0x0201, &result, 1, sess);
}

/* ---- 0x0300 AP scan ---------------------------------------------------------- */

static uint8_t scan_security(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN: return 0;
    case WIFI_AUTH_WEP: return 1;
    case WIFI_AUTH_WPA_PSK: return 2;
    case WIFI_AUTH_WPA2_ENTERPRISE: return 5;
    default: return 4;
    }
}

static void handle_ap_scan(int fd)
{
    uint16_t total = 0, count = 0;
    wifi_ap_record_t *rec = NULL;
    if (at_wifi_ensure_sta_started() && esp_wifi_scan_start(NULL, true) == ESP_OK) {
        esp_wifi_scan_get_ap_num(&total);
        count = total > 50 ? 50 : total;
        rec = count ? calloc(count, sizeof(*rec)) : NULL;
        if (rec) {
            esp_wifi_scan_get_ap_records(&count, rec);
        } else {
            count = 0;
            esp_wifi_clear_ap_list();
        }
    }
    uint8_t *b = malloc(4 + (size_t)count * (2 + 32 + 6 + 2 + 2 + 1) + 1);
    if (!b) {
        uint8_t fail = 1;
        send_packet(fd, 0x0301, &fail, 1, NULL);
        free(rec);
        return;
    }
    size_t off = 0;
    put_u16(b, &off, total);
    put_u16(b, &off, count);
    for (uint16_t i = 0; i < count; i++) {
        uint16_t sl = (uint16_t)strnlen((const char *)rec[i].ssid, sizeof(rec[i].ssid));
        put_u16(b, &off, sl);
        memcpy(b + off, rec[i].ssid, sl);
        off += sl;
        memcpy(b + off, rec[i].bssid, 6);
        off += 6;
        put_u16(b, &off, (uint16_t)(int16_t)rec[i].rssi);
        put_u16(b, &off, rec[i].primary);
        b[off++] = scan_security(rec[i].authmode);
    }
    b[off++] = rec || total == 0 ? 0 : 1;
    send_packet(fd, 0x0301, b, off, NULL);
    free(b);
    free(rec);
}

/* ---- 0x0400 home AP ----------------------------------------------------------- */

static void handle_ap_info(int fd, const uint8_t *pl, size_t len, session_t *sess)
{
    cursor_t c = { pl, len };
    wifi_config_t cfg = {0};
    char ssid[33], pw[65];
    uint8_t result = 1;
    if (cur_str(&c, ssid, sizeof(ssid)) && ssid[0] && cur_str(&c, pw, sizeof(pw)) &&
        (pw[0] == '\0' || strlen(pw) >= 8)) {
        memcpy(cfg.sta.ssid, ssid, strlen(ssid));
        strlcpy((char *)cfg.sta.password, pw, sizeof(cfg.sta.password));
        if (pw[0]) {
            cfg.sta.threshold.authmode = WIFI_AUTH_WPA_PSK; /* rejects open / WEP look-alikes */
        }
        result = 0;
    }
    memset(pw, 0, sizeof(pw));
    send_packet(fd, 0x0401, &result, 1, sess);
    if (result == 0) {
        vTaskDelay(pdMS_TO_TICKS(300)); /* let the response leave before the radio switches channel */
        s_join_pending = true;
        if (!at_wifi_sta_join(&cfg)) {
            s_join_pending = false;
            ESP_LOGW(TAG, "home AP join could not start");
        }
    }
    memset(&cfg, 0, sizeof(cfg));
}

/* ---- server ----------------------------------------------------------------------- */

/* True when the peer reached us through the SoftAP interface. */
static bool via_softap(int fd)
{
    struct sockaddr_in local;
    socklen_t sl = sizeof(local);
    esp_netif_ip_info_t ip = {0};
    esp_netif_t *ap = at_wifi_get_ap_netif();
    return getsockname(fd, (struct sockaddr *)&local, &sl) == 0 && ap &&
           esp_netif_get_ip_info(ap, &ip) == ESP_OK && ip.ip.addr != 0 &&
           local.sin_addr.s_addr == ip.ip.addr;
}

static void serve_client(int fd)
{
    session_t sess = {0};
    struct timeval tv = { .tv_sec = RX_TIMEOUT_S };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        uint8_t hdr[HDR_LEN];
        if (!read_full(fd, hdr, sizeof(hdr)) || memcmp(hdr + 4, MAGIC, 4) != 0) {
            break;
        }
        uint32_t total = hdr[0] | (hdr[1] << 8) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
        uint16_t type = (uint16_t)(hdr[8] | (hdr[9] << 8));
        if (total < HDR_FIXED || total - HDR_FIXED > MAX_PAYLOAD) {
            break;
        }
        size_t len = total - HDR_FIXED;
        uint8_t *pl = len ? malloc(len) : NULL;
        if (len && (!pl || !read_full(fd, pl, len))) {
            free(pl);
            break;
        }
        if (sess.aes && (type == 0x0200 || type == 0x0400) && len) {
            if (len % 16) {
                free(pl);
                break;
            }
            for (size_t off = 0; off < len; off += 16) {
                mbedtls_aes_crypt_ecb(&sess.dec, MBEDTLS_AES_DECRYPT, pl + off, pl + off);
            }
        }
        switch (type) {
        case 0x0100: handle_device_info(fd, pl, len, &sess); break;
        case 0x0200: handle_server_info(fd, pl, len, &sess); break;
        case 0x0300: handle_ap_scan(fd); break;
        case 0x0400: handle_ap_info(fd, pl, len, &sess); break;
        default: ESP_LOGW(TAG, "unknown data type 0x%04x", type); break;
        }
        if (pl) {
            memset(pl, 0, len);
            free(pl);
        }
    }
    if (sess.aes) {
        mbedtls_aes_free(&sess.dec);
        mbedtls_aes_free(&sess.enc);
    }
}

static void server_task(void *arg)
{
    (void)arg;
    int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int yes = 1;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_AT_MODEM_OTH_PAIRING_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (lfd < 0 || setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0 ||
        bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(lfd, 1) != 0) {
        ESP_LOGE(TAG, "cannot listen on port %d", CONFIG_AT_MODEM_OTH_PAIRING_PORT);
        if (lfd >= 0) {
            close(lfd);
        }
        vTaskDelete(NULL);
        return;
    }
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (via_softap(fd)) {
            serve_client(fd);
        }
        close(fd);
    }
}

/* ---- home AP joined ------------------------------------------------------------ */

static void ap_stop_cb(void *arg)
{
    (void)arg;
    wifi_mode_t m = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&m) == ESP_OK && m == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    }
}

/* The home AP from 0x0400 is joined: keep it as the profile rejoined at
 * boot and after a lost link (AUCONMODE 1), and close the SoftAP a few
 * seconds later so the app can still see the result. */
void oth_pairing_on_ip(void)
{
    if (!s_join_pending) {
        return;
    }
    s_join_pending = false;
    at_oth_wifi_keep_station();
    if (s_ap_stop_timer) {
        esp_timer_stop(s_ap_stop_timer);
        esp_timer_start_once(s_ap_stop_timer, 3 * 1000 * 1000);
    }
}

void oth_pairing_init(void)
{
    const esp_timer_create_args_t t = { .callback = ap_stop_cb, .name = "oth_ap_stop" };
    esp_timer_create(&t, &s_ap_stop_timer);
    if (xTaskCreate(server_task, "oth_pair", 6144, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "no memory for the pairing server");
    }
}
