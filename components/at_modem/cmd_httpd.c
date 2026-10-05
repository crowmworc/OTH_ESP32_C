/* AT*M2M*NET_HTTPDSTART/HTTPDSTOP/HTTPDCONF -- embedded "configuration web
 * server" (doc Ch.6.3, on esp_http_server). The doc never specifies what
 * pages/routes this server actually serves beyond "configuration web
 * server" and login credentials -- there's no route spec to implement
 * against, unlike the AT command set itself. This provides the
 * infrastructure the doc does define (start/stop/port/SSL flag/Basic-auth
 * credentials, persisted across reboots) plus a full WebUI (`webui/index.html`,
 * gzip-embedded) and its backing routes: static page, session login,
 * status, network, Wi-Fi scan/connect (plain + Enterprise), MQTT broker
 * config, TLS certificate management, and firmware upload.
 *
 * Auth model: the WebUI is a single-page app served publicly at "/" (no
 * secrets in the static HTML/JS); every /api/... and /ota route requires a
 * session cookie obtained via POST /api/login, checked against the same
 * NET_HTTPDCONF id/password credentials the doc defines. This replaced an
 * earlier HTTP Basic-Auth gate on every route -- Basic-Auth's native
 * browser credential prompt can't be styled to match the WebUI and (more
 * importantly for this project) makes automated screenshot capture of the
 * UI impossible, since the browser's own auth dialog blocks page rendering
 * entirely. Session tokens are RAM-only (esp_fill_random), single-slot (one
 * logged-in session at a time, matching this being a single-owner embedded
 * device), and cleared on reboot.
 *
 * Credentials, the password policy, the brute-force lockout and session
 * expiry live in web_auth.c (EN 18031-1 AUM-3/4/5/6, 2026-09-27): the
 * factory default admin/admin only opens POST /api/password until it has
 * been changed, and POST /ota is refused unless the server runs over HTTPS.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_app_desc.h"
#include "esp_random.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"

#include "at_commands.h"
#include "at_response.h"
#include "at_nvs_kv.h"
#include "at_httpd.h"
#include "at_wifi.h"
#include "fs_store.h"
#include "mqtt_web.h"
#include "at_pem_scratch.h"
#include "web_auth.h"

static const char *TAG = "at_httpd";
static httpd_handle_t s_httpd;

static bool s_httpd_is_ssl; /* transport of the running server (for /ota) */

/* ---- Session auth (see file header, and web_auth.c for credentials,
 * lockout and session expiry) --------------------------------------------- */

static void send_json_status(httpd_req_t *req, const char *status, const char *json)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
}

static bool session_valid(httpd_req_t *req)
{
    char cookie[128];
    return httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie)) == ESP_OK &&
           web_auth_session_check(cookie);
}

/* Gate for every /api and /ota route except login/logout/session and the
 * password change itself: needs a live session, and -- while the factory
 * default password is still in effect -- refuses everything with 403 so the
 * WebUI's forced password-change screen is the only way forward (AUM-5-1). */
static bool check_session(httpd_req_t *req)
{
    if (!session_valid(req)) {
        send_json_status(req, "401 Unauthorized", "{\"ok\":false,\"error\":\"not authenticated\"}");
        return false;
    }
    if (web_auth_must_change()) {
        send_json_status(req, "403 Forbidden",
                         "{\"ok\":false,\"error\":\"password change required\",\"must_change\":true}");
        return false;
    }
    return true;
}

/* Reads a small JSON request body; replies 400 and returns NULL on error. */
static cJSON *read_json_body(httpd_req_t *req, size_t max)
{
    char body[384];
    if (max > sizeof(body)) {
        max = sizeof(body);
    }
    if (req->content_len <= 0 || (size_t)req->content_len >= max) {
        send_json_status(req, "400 Bad Request", "{\"ok\":false,\"error\":\"bad request size\"}");
        return NULL;
    }
    int n = httpd_req_recv(req, body, req->content_len);
    if (n <= 0) {
        send_json_status(req, "400 Bad Request", "{\"ok\":false,\"error\":\"read failed\"}");
        return NULL;
    }
    body[n] = '\0';
    cJSON *root = cJSON_Parse(body);
    memset(body, 0, sizeof(body)); /* may hold a password */
    if (!root) {
        send_json_status(req, "400 Bad Request", "{\"ok\":false,\"error\":\"malformed json\"}");
    }
    return root;
}

static const char *json_str(cJSON *root, const char *key)
{
    cJSON *j = cJSON_GetObjectItemCaseSensitive(root, key);
    return cJSON_IsString(j) ? j->valuestring : "";
}

static void send_locked(httpd_req_t *req, uint32_t retry_after)
{
    char hdr[12], json[96];
    snprintf(hdr, sizeof(hdr), "%u", (unsigned)retry_after);
    snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"too many failed attempts\",\"retry_after\":%u}",
             (unsigned)retry_after);
    httpd_resp_set_hdr(req, "Retry-After", hdr);
    send_json_status(req, "429 Too Many Requests", json);
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    cJSON *root = read_json_body(req, 256);
    if (!root) {
        return ESP_OK;
    }
    uint32_t retry_after = 0;
    web_auth_result_t r = web_auth_login(json_str(root, "id"), json_str(root, "password"), &retry_after);
    cJSON_Delete(root);

    if (r == WEB_AUTH_LOCKED) {
        send_locked(req, retry_after);
        return ESP_OK;
    }
    if (r != WEB_AUTH_OK) {
        send_json_status(req, "401 Unauthorized", "{\"ok\":false,\"error\":\"invalid credentials\"}");
        return ESP_OK;
    }

    char token[WEB_AUTH_TOKEN_LEN + 1];
    web_auth_session_new(token);
    char cookie_hdr[96];
    snprintf(cookie_hdr, sizeof(cookie_hdr), "session=%s; Path=/; HttpOnly; SameSite=Strict%s", token,
             s_httpd_is_ssl ? "; Secure" : "");
    httpd_resp_set_hdr(req, "Set-Cookie", cookie_hdr);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, web_auth_must_change() ? "{\"ok\":true,\"must_change\":true}"
                                                   : "{\"ok\":true,\"must_change\":false}");
    return ESP_OK;
}

static esp_err_t logout_post_handler(httpd_req_t *req)
{
    web_auth_session_clear();
    httpd_resp_set_hdr(req, "Set-Cookie", "session=; Path=/; Max-Age=0");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t session_get_handler(httpd_req_t *req)
{
    /* Deliberately does NOT call check_session()/401 -- the WebUI polls
     * this on load to decide whether to show the login screen, so a 401
     * here would just be a second thing to special-case client-side. */
    bool authed = session_valid(req);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "authenticated", authed);
    cJSON_AddBoolToObject(root, "must_change", authed && web_auth_must_change());
    if (authed) {
        char id[WEB_AUTH_ID_MAX + 1];
        web_auth_get_id(id, sizeof(id));
        cJSON_AddStringToObject(root, "id", id);
    }
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{}");
    cJSON_free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ---- POST /api/password -- change the login id/password (AUM-4); also the
 * only route open while the factory default must still be changed.
 * {"current":..,"password":..[,"id":..]} -- "id" omitted keeps the current
 * one. The current password is checked through web_auth_login(), so wrong
 * guesses here count toward the same brute-force lockout as the login
 * (skipped only for the forced first change, see below). */

static esp_err_t password_post_handler(httpd_req_t *req)
{
    if (!session_valid(req)) {
        send_json_status(req, "401 Unauthorized", "{\"ok\":false,\"error\":\"not authenticated\"}");
        return ESP_OK;
    }
    cJSON *root = read_json_body(req, 384);
    if (!root) {
        return ESP_OK;
    }
    char cur_id[WEB_AUTH_ID_MAX + 1];
    web_auth_get_id(cur_id, sizeof(cur_id));
    const char *new_id = json_str(root, "id");
    if (new_id[0] == '\0') {
        new_id = cur_id;
    }

    /* While the factory default is in effect the session itself was opened
     * with it, so there is nothing further to prove (and the WebUI may have
     * been reloaded since, losing the password it logged in with). */
    uint32_t retry_after = 0;
    web_auth_result_t r = web_auth_must_change()
                              ? WEB_AUTH_OK
                              : web_auth_login(cur_id, json_str(root, "current"), &retry_after);
    if (r != WEB_AUTH_OK) {
        cJSON_Delete(root);
        if (r == WEB_AUTH_LOCKED) {
            send_locked(req, retry_after);
        } else {
            send_json_status(req, "403 Forbidden", "{\"ok\":false,\"error\":\"current password is wrong\"}");
        }
        return ESP_OK;
    }

    web_auth_policy_t p = web_auth_set(new_id, json_str(root, "password"));
    cJSON_Delete(root);
    if (p != WEB_AUTH_POLICY_OK) {
        char json[192];
        snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"%s\"}", web_auth_policy_text(p));
        send_json_status(req, "400 Bad Request", json);
        return ESP_OK;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_login_uri  = { .uri = "/api/login",  .method = HTTP_POST, .handler = login_post_handler };
static const httpd_uri_t s_logout_uri = { .uri = "/api/logout", .method = HTTP_POST, .handler = logout_post_handler };
static const httpd_uri_t s_session_uri = { .uri = "/api/session", .method = HTTP_GET, .handler = session_get_handler };
static const httpd_uri_t s_password_uri = { .uri = "/api/password", .method = HTTP_POST, .handler = password_post_handler };

/* ---- GET / -- the WebUI (webui/index.html, gzip-embedded) -- public,
 * no session required (see file header). ------------------------------- */

extern const uint8_t index_html_gz_start[] asm("_binary_index_html_gz_start");
extern const uint8_t index_html_gz_end[]   asm("_binary_index_html_gz_end");

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (const char *)index_html_gz_start,
                     index_html_gz_end - index_html_gz_start);
    return ESP_OK;
}

static const httpd_uri_t s_root_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
};

/* ---- GET /api/status -- Status tab + Network tab's current values ----- */

static esp_err_t api_status_get_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }

    const esp_app_desc_t *desc = esp_app_get_description();

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    bool is_ap = (mode == WIFI_MODE_AP);

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char macbuf[18];
    snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    char ssid[33] = "";
    int channel = 0, rssi = 0;
    if (is_ap) {
        wifi_config_t cfg;
        if (esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
            strlcpy(ssid, (char *)cfg.ap.ssid, sizeof(ssid));
            channel = cfg.ap.channel;
        }
    } else {
        wifi_ap_record_t info;
        if (esp_wifi_sta_get_ap_info(&info) == ESP_OK) {
            strlcpy(ssid, (char *)info.ssid, sizeof(ssid));
            channel = info.primary;
            rssi = info.rssi;
        }
    }

    esp_netif_t *sta_netif = at_wifi_get_sta_netif();
    esp_netif_t *ap_netif = at_wifi_get_ap_netif();
    esp_netif_t *netif = is_ap ? ap_netif : sta_netif;

    esp_netif_ip_info_t ip_info = {0};
    esp_netif_get_ip_info(netif, &ip_info);
    esp_netif_dns_info_t dns = {0};
    esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    esp_netif_dhcp_status_t dhcp_status = ESP_NETIF_DHCP_INIT;
    esp_netif_dhcpc_get_status(sta_netif, &dhcp_status);

    char ip_s[16], nm_s[16], gw_s[16], dns_s[16];
    esp_ip4addr_ntoa(&ip_info.ip, ip_s, sizeof(ip_s));
    esp_ip4addr_ntoa(&ip_info.netmask, nm_s, sizeof(nm_s));
    esp_ip4addr_ntoa(&ip_info.gw, gw_s, sizeof(gw_s));
    esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, dns_s, sizeof(dns_s));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "fw", desc->version);
    cJSON_AddStringToObject(root, "mac", macbuf);
    cJSON_AddStringToObject(root, "mode", is_ap ? "SoftAP" : "Station");
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddNumberToObject(root, "channel", channel);
    cJSON_AddNumberToObject(root, "rssi", rssi);
    cJSON_AddBoolToObject(root, "dhcp", dhcp_status == ESP_NETIF_DHCP_STARTED);
    cJSON_AddStringToObject(root, "ip", ip_s);
    cJSON_AddStringToObject(root, "netmask", nm_s);
    cJSON_AddStringToObject(root, "gateway", gw_s);
    cJSON_AddStringToObject(root, "dns", dns_s);

    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{}");
    cJSON_free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static const httpd_uri_t s_api_status_uri = {
    .uri = "/api/status",
    .method = HTTP_GET,
    .handler = api_status_get_handler,
};

/* ---- POST /api/network -- Network tab's Save button -------------------
 * {"dhcp":true} or {"dhcp":false,"ip":..,"netmask":..,"gateway":..}, via
 * at_wifi_set_station_ip() (cmd_wifi.c) -- the same helper AT*M2M*WF_IPSTATUS's
 * Set form uses. DNS is report-only. */

static esp_err_t api_network_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }

    char body[384];
    if (req->content_len <= 0 || (size_t)req->content_len >= sizeof(body)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"bad request size\"}");
        return ESP_OK;
    }
    int n = httpd_req_recv(req, body, req->content_len);
    if (n <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"read failed\"}");
        return ESP_OK;
    }
    body[n] = '\0';

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"malformed json\"}");
        return ESP_OK;
    }

    bool ok = false;
    cJSON *dhcp = cJSON_GetObjectItemCaseSensitive(root, "dhcp");
    if (cJSON_IsTrue(dhcp)) {
        ok = at_wifi_set_station_ip(true, NULL, NULL, NULL);
    } else if (cJSON_IsFalse(dhcp)) {
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(root, "ip");
        cJSON *nm = cJSON_GetObjectItemCaseSensitive(root, "netmask");
        cJSON *gw = cJSON_GetObjectItemCaseSensitive(root, "gateway");
        if (cJSON_IsString(ip) && cJSON_IsString(nm) && cJSON_IsString(gw)) {
            ok = at_wifi_set_station_ip(false, ip->valuestring, nm->valuestring, gw->valuestring);
        }
    }
    cJSON_Delete(root);

    if (!ok) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"invalid network settings\"}");
        return ESP_OK;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_api_network_uri = {
    .uri = "/api/network",
    .method = HTTP_POST,
    .handler = api_network_post_handler,
};

/* ---- GET /api/wifi/scan, POST /api/wifi/connect, POST /api/wifi/enterprise
 * -- Wi-Fi tab and Enterprise tab. Reuse at_wifi_web_*() (cmd_wifi.c),
 * the same esp_wifi_.../esp_eap_client_... calls WF_SCAN/WF_CONN/WF_EAPCONF
 * use. ------------------------------------------------------------------ */

static esp_err_t api_wifi_scan_get_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    cJSON *networks = at_wifi_web_scan();
    if (!networks) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"scan failed\"}");
        return ESP_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "networks", networks);
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{\"networks\":[]}");
    cJSON_free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static const httpd_uri_t s_wifi_scan_uri = { .uri = "/api/wifi/scan", .method = HTTP_GET, .handler = api_wifi_scan_get_handler };

static esp_err_t api_wifi_connect_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    char body[256];
    if (req->content_len <= 0 || (size_t)req->content_len >= sizeof(body)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"bad request size\"}");
        return ESP_OK;
    }
    int n = httpd_req_recv(req, body, req->content_len);
    if (n <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"read failed\"}");
        return ESP_OK;
    }
    body[n] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"malformed json\"}");
        return ESP_OK;
    }
    cJSON *ssid_j = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *pw_j = cJSON_GetObjectItemCaseSensitive(root, "password");
    const char *ssid = cJSON_IsString(ssid_j) ? ssid_j->valuestring : "";
    const char *password = cJSON_IsString(pw_j) ? pw_j->valuestring : "";
    bool ok = at_wifi_web_connect_psk(ssid, password);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    if (!ok) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"connect failed\"}");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_wifi_connect_uri = { .uri = "/api/wifi/connect", .method = HTTP_POST, .handler = api_wifi_connect_post_handler };

static esp_err_t api_wifi_enterprise_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    char body[512];
    if (req->content_len <= 0 || (size_t)req->content_len >= sizeof(body)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"bad request size\"}");
        return ESP_OK;
    }
    int n = httpd_req_recv(req, body, req->content_len);
    if (n <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"read failed\"}");
        return ESP_OK;
    }
    body[n] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"malformed json\"}");
        return ESP_OK;
    }
    #define J(field) cJSON_GetObjectItemCaseSensitive(root, field)
    #define JS(field) (cJSON_IsString(J(field)) ? J(field)->valuestring : "")
    bool ok = at_wifi_web_connect_enterprise(JS("ssid"), JS("method"), JS("identity"),
                                              JS("anonymous_identity"), JS("username"), JS("password"));
    #undef JS
    #undef J
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    if (!ok) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"connect failed -- check method/identity/username\"}");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_wifi_enterprise_uri = { .uri = "/api/wifi/enterprise", .method = HTTP_POST, .handler = api_wifi_enterprise_post_handler };

/* ---- GET/POST /api/mqtt -- MQTT Broker tab. Reuse mqtt_web_*()
 * (cmd_mqtt.c, link 0). ---------------------------------------------- */

static esp_err_t api_mqtt_get_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    mqtt_web_status_t st;
    mqtt_web_get_status(&st);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "configured", st.configured);
    cJSON_AddBoolToObject(root, "connected", st.connected);
    cJSON_AddNumberToObject(root, "scheme", st.scheme);
    cJSON_AddStringToObject(root, "host", st.host);
    cJSON_AddNumberToObject(root, "port", st.port);
    cJSON_AddStringToObject(root, "client_id", st.client_id);
    cJSON_AddStringToObject(root, "user", st.user);
    cJSON_AddBoolToObject(root, "has_password", st.has_password);
    cJSON_AddBoolToObject(root, "has_cert", st.has_cert);
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{}");
    cJSON_free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static const httpd_uri_t s_mqtt_get_uri = { .uri = "/api/mqtt", .method = HTTP_GET, .handler = api_mqtt_get_handler };

static esp_err_t api_mqtt_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    char body[512];
    if (req->content_len <= 0 || (size_t)req->content_len >= sizeof(body)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"bad request size\"}");
        return ESP_OK;
    }
    int n = httpd_req_recv(req, body, req->content_len);
    if (n <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"read failed\"}");
        return ESP_OK;
    }
    body[n] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"malformed json\"}");
        return ESP_OK;
    }
    cJSON *scheme_j = cJSON_GetObjectItemCaseSensitive(root, "scheme");
    cJSON *port_j = cJSON_GetObjectItemCaseSensitive(root, "port");
    #define J(field) cJSON_GetObjectItemCaseSensitive(root, field)
    #define JS(field) (cJSON_IsString(J(field)) ? J(field)->valuestring : "")
    int scheme = cJSON_IsNumber(scheme_j) ? scheme_j->valueint : 0;
    int port = cJSON_IsNumber(port_j) ? port_j->valueint : 0;
    bool ok = mqtt_web_configure_and_connect(scheme, JS("host"), port, JS("client_id"),
                                              JS("user"), JS("password"), JS("cert_name"));
    #undef JS
    #undef J
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    if (!ok) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"invalid config or broker init failed\"}");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_mqtt_post_uri = { .uri = "/api/mqtt", .method = HTTP_POST, .handler = api_mqtt_post_handler };

/* ---- GET /api/certs, POST /api/certs/upload?name=<file> -- TLS
 * Certificates tab. Files live in the same fs_store (SPIFFS) location
 * WF_EAPCERT/MQTT_CONF's cert_name and NET_HTTPDOWNLOAD already use, so a
 * cert uploaded here is immediately usable as a cert_name/WF_EAPCERT
 * value and vice versa. Only 3 well-known names are exposed (matching the
 * TLS Certificates screen) -- WF_EAPCERT/MQTT_CONF's cert_name can still
 * reference any filename via NET_HTTPDOWNLOAD, this is just what the web
 * UI itself manages. ------------------------------------------------- */

#define CERT_UPLOAD_MAX (16 * 1024)

static esp_err_t api_certs_get_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    static const char *names[] = { "ca.pem", "client.crt", "client.key" };
    cJSON *root = cJSON_CreateObject();
    cJSON *files = cJSON_CreateArray();
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", names[i]);
        bool exists = fs_store_exists(names[i]);
        cJSON_AddBoolToObject(item, "exists", exists);
        if (exists) {
            char fp[100];
            if (fs_store_cert_fingerprint(names[i], fp, sizeof(fp))) {
                cJSON_AddStringToObject(item, "fingerprint", fp);
            }
        }
        cJSON_AddItemToArray(files, item);
    }
    cJSON_AddItemToObject(root, "files", files);
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{}");
    cJSON_free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static const httpd_uri_t s_certs_get_uri = { .uri = "/api/certs", .method = HTTP_GET, .handler = api_certs_get_handler };

static bool cert_name_allowed(const char *name)
{
    return name && (strcmp(name, "ca.pem") == 0 || strcmp(name, "client.crt") == 0 ||
                     strcmp(name, "client.key") == 0);
}

static esp_err_t api_certs_upload_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    char query[64], name[32] = "";
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "name", name, sizeof(name));
    }
    if (!cert_name_allowed(name)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"name must be ca.pem, client.crt or client.key\"}");
        return ESP_OK;
    }
    if (req->content_len <= 0 || (size_t)req->content_len > CERT_UPLOAD_MAX) {
        httpd_resp_set_status(req, "413 Payload Too Large");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"file too large\"}");
        return ESP_OK;
    }

    /* Received whole into RAM and checked before anything is stored: a
     * private key must never touch the plain SPIFFS partition, only
     * encrypted NVS (fs_store_write() routes it, EN 18031-1 SSM-3). */
    size_t total = (size_t)req->content_len;
    char *buf = malloc(total);
    if (!buf) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"out of memory\"}");
        return ESP_OK;
    }
    size_t got = 0;
    while (got < total) {
        int n = httpd_req_recv(req, buf + got, total - got);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
    }

    httpd_resp_set_type(req, "application/json");
    char why[80];
    const char *status = NULL, *error = NULL;
    if (got != total) {
        status = "500 Internal Server Error", error = "upload failed";
    } else if (!fs_store_check_pem_strength(buf, total, why, sizeof(why))) {
        status = "400 Bad Request", error = why; /* EN 18031-1 CCK-1 */
    } else if (fs_store_is_secret(name, buf, total) && total > FS_STORE_SECRET_MAX) {
        status = "413 Payload Too Large", error = "a private key file may be at most 8 KB";
    } else if (!fs_store_write(name, buf, total)) {
        status = "500 Internal Server Error", error = "storage write failed";
    }
    memset(buf, 0, total);
    free(buf);
    if (status) {
        char json[160];
        snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"rejected: %s\"}", error);
        httpd_resp_set_status(req, status);
        httpd_resp_sendstr(req, json);
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static const httpd_uri_t s_certs_upload_uri = { .uri = "/api/certs/upload", .method = HTTP_POST, .handler = api_certs_upload_post_handler };

/* ---- Web-based firmware upgrade (not a doc AT*M2M* command -- reachable
 * only through the same HTTPD_START'd server, session-gated, driven from
 * the WebUI's Firmware tab).
 *
 * GET  /ota          -- redirects to "/" (the Firmware tab), kept as a URI
 *      so old bookmarks/links still land somewhere useful.
 * POST /ota?version=<string>, raw .bin as the request body (no multipart --
 *      this project has no multipart parser and a raw octet-stream POST
 *      from a <input type=file> via fetch() needs none)
 *
 * Always targets esp_ota_get_next_update_partition() (never a hardcoded
 * ota_0/ota_1 -- which one is inactive flips after every successful
 * update). Version comparison is the same plain string-inequality
 * simplification cmd_ota.c's OTA_CHECK/OTA_UPDATE already use (this
 * project's esp_app_desc_t versions are arbitrary strings, not numeric). */

#define OTA_UPLOAD_CHUNK 4096

static esp_err_t ota_get_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t ota_post_handler(httpd_req_t *req)
{
    if (!check_session(req)) {
        return ESP_OK;
    }
    /* EN 18031-1 SUM-2: a firmware image may only arrive over the
     * authenticated, integrity-protected HTTPS channel, never plain HTTP. */
    if (!s_httpd_is_ssl) {
        httpd_resp_set_status(req, "403 Forbidden");
        httpd_resp_sendstr(req, "firmware upload requires HTTPS (NET_HTTPDSTART ssl=1)\n");
        return ESP_OK;
    }

    char query[32], new_version[16] = "";
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "version", new_version, sizeof(new_version));
    }
    const esp_app_desc_t *local_desc = esp_app_get_description();
    if (new_version[0] == '\0' || strcmp(new_version, local_desc->version) == 0) {
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_sendstr(req, "not newer than the running version\n");
        return ESP_OK;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition ||
        (req->content_len > 0 && (size_t)req->content_len > update_partition->size)) {
        httpd_resp_set_status(req, "413 Payload Too Large");
        httpd_resp_sendstr(req, "no OTA slot available or firmware too large\n");
        return ESP_OK;
    }

    esp_ota_handle_t handle;
    if (esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &handle) != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "esp_ota_begin failed\n");
        return ESP_OK;
    }

    uint8_t *buf = malloc(OTA_UPLOAD_CHUNK);
    if (!buf) {
        esp_ota_abort(handle);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "out of memory\n");
        return ESP_OK;
    }

    int remaining = req->content_len;
    bool write_error = false;
    while (remaining > 0) {
        int to_read = remaining < OTA_UPLOAD_CHUNK ? remaining : OTA_UPLOAD_CHUNK;
        int n = httpd_req_recv(req, (char *)buf, to_read);
        if (n <= 0 || esp_ota_write(handle, buf, n) != ESP_OK) {
            write_error = true;
            break;
        }
        remaining -= n;
    }
    free(buf);

    if (!write_error && esp_ota_end(handle) == ESP_OK &&
        esp_ota_set_boot_partition(update_partition) == ESP_OK) {
        httpd_resp_sendstr(req, "OK, rebooting\n");
        vTaskDelay(pdMS_TO_TICKS(300)); /* let the response flush */
        esp_restart();
    }
    esp_ota_abort(handle); /* no-op if esp_ota_end() already consumed the handle above */
    httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_sendstr(req, "OTA write/verify failed\n");
    return ESP_OK;
}

static const httpd_uri_t s_ota_get_uri = {
    .uri = "/ota",
    .method = HTTP_GET,
    .handler = ota_get_handler,
};

static const httpd_uri_t s_ota_post_uri = {
    .uri = "/ota",
    .method = HTTP_POST,
    .handler = ota_post_handler,
};

static void register_routes(httpd_handle_t h)
{
    httpd_register_uri_handler(h, &s_root_uri);
    httpd_register_uri_handler(h, &s_login_uri);
    httpd_register_uri_handler(h, &s_logout_uri);
    httpd_register_uri_handler(h, &s_session_uri);
    httpd_register_uri_handler(h, &s_password_uri);
    httpd_register_uri_handler(h, &s_api_status_uri);
    httpd_register_uri_handler(h, &s_api_network_uri);
    httpd_register_uri_handler(h, &s_wifi_scan_uri);
    httpd_register_uri_handler(h, &s_wifi_connect_uri);
    httpd_register_uri_handler(h, &s_wifi_enterprise_uri);
    httpd_register_uri_handler(h, &s_mqtt_get_uri);
    httpd_register_uri_handler(h, &s_mqtt_post_uri);
    httpd_register_uri_handler(h, &s_certs_get_uri);
    httpd_register_uri_handler(h, &s_certs_upload_uri);
    httpd_register_uri_handler(h, &s_ota_get_uri);
    httpd_register_uri_handler(h, &s_ota_post_uri);
}

static esp_err_t start_server(uint16_t port)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.lru_purge_enable = true;
    config.max_open_sockets = CONFIG_AT_MODEM_HTTPD_MAX_SOCKETS; /* RLM-1, see Kconfig */
    config.stack_size = 8192; /* /ota's upload handler streams into esp_ota_write() */
    config.max_uri_handlers = 20;
    esp_err_t err = httpd_start(&s_httpd, &config);
    if (err == ESP_OK) {
        s_httpd_is_ssl = false;
        register_routes(s_httpd);
    }
    return err;
}

/* cert_pem: server certificate+key, PEM, concatenated in one buffer (same
 * "server certificate+key file" convention NET_HTTPDSTART's doc entry and
 * NET_SERVER=ssl already use) -- httpd_ssl_start() copies servercert/
 * prvtkey into its own heap buffers before returning (see
 * esp_https_server/src/https_server.c), so cert_pem only needs to stay
 * valid for the duration of this call, unlike net_link.c's per-connection
 * SSL server slots. cert_pem_len must include the trailing NUL (mbedtls's
 * PEM-vs-DER autodetect requires buf[buflen-1]=='\0', same WF_EAPCERT/
 * NET_SERVER=ssl gotcha). */
static esp_err_t start_server_ssl(uint16_t port, const char *cert_pem, size_t cert_pem_len)
{
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.lru_purge_enable = true;
    config.httpd.max_open_sockets = CONFIG_AT_MODEM_HTTPD_MAX_SOCKETS; /* RLM-1, see Kconfig */
    /* EN 18031-1 RLM-1: esp_https_server runs each TLS handshake to completion
     * inside the single server task, so a client that connects and sends
     * nothing stalls every other client until it times out. The IDF
     * defaults (10 s handshake, only checked after each 5 s socket read
     * timeout) made that ~15 s per idle connection; this keeps it ~3 s
     * (hardware-measured 2026-10-04). A LAN handshake takes < 1 s. */
    config.tls_handshake_timeout_ms = 2500;
    config.httpd.recv_wait_timeout = 3;
    config.httpd.stack_size = 10240; /* generous enough for both TLS handshake and /ota's upload handler */
    config.httpd.max_uri_handlers = 20;
    config.servercert = (const uint8_t *)cert_pem;
    config.servercert_len = cert_pem_len;
    config.prvtkey_pem = (const uint8_t *)cert_pem;
    config.prvtkey_len = cert_pem_len;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = port;
    esp_err_t err = httpd_ssl_start(&s_httpd, &config);
    if (err == ESP_OK) {
        s_httpd_is_ssl = true;
        register_routes(s_httpd);
    }
    return err;
}

/* Mirrors cmd_wifi.c's/net_link.c's own load_cert_file() -- reads a
 * fs_store-staged file into a caller buffer, NUL-terminated, with the raw
 * byte count (excluding that NUL) in *out_len. */
static bool load_cert_file(const char *filename, char *out, size_t out_cap, size_t *out_len)
{
    return fs_store_read(filename, out, out_cap, out_len);
}

/* Build-time transport policy (Kconfig AT_MODEM_HTTPD_MODE, EN 18031-1
 * SCM-1): which of plain HTTP / HTTPS this firmware may serve at all. */
#if CONFIG_AT_MODEM_HTTPD_MODE_HTTP_ONLY
#define HTTPD_ALLOW_HTTP  1
#define HTTPD_ALLOW_HTTPS 0
#elif CONFIG_AT_MODEM_HTTPD_MODE_HTTPS_ONLY
#define HTTPD_ALLOW_HTTP  0
#define HTTPD_ALLOW_HTTPS 1
#else
#define HTTPD_ALLOW_HTTP  1
#define HTTPD_ALLOW_HTTPS 1
#endif

void at_httpd_init(void)
{
    web_auth_init();

    uint16_t enabled = 0;
    m2m_nvs_get_u16("httpd_enabled", &enabled);
    if (!enabled) {
        return;
    }
    uint16_t port = 0;
    m2m_nvs_get_u16("httpd_port", &port);
    if (port == 0) {
        port = 80;
    }
    uint16_t ssl = 0;
    m2m_nvs_get_u16("httpd_ssl", &ssl);
    if (ssl && !HTTPD_ALLOW_HTTPS) {
        ESP_LOGW(TAG, "HTTPS auto-start: this build is HTTP only, starting as plain HTTP");
        ssl = 0;
    }
    if (ssl) {
        char cert_name[17] = "";
        size_t name_len = sizeof(cert_name);
        m2m_nvs_get_str("httpd_cert", cert_name, &name_len);
        char *cert_pem = g_at_pem_scratch; /* shared scratch, see at_pem_scratch.h */
        size_t cert_len;
        if (cert_name[0] != '\0' && load_cert_file(cert_name, cert_pem, AT_PEM_SCRATCH_LEN, &cert_len) &&
            start_server_ssl(port, cert_pem, cert_len + 1) == ESP_OK) {
            return;
        }
        if (!HTTPD_ALLOW_HTTP) {
            ESP_LOGW(TAG, "HTTPS auto-start: cert '%s' missing/unreadable, not starting (HTTPS only build)", cert_name);
            return;
        }
        ESP_LOGW(TAG, "HTTPS auto-start: cert '%s' missing/unreadable, falling back to plain HTTP", cert_name);
    } else if (!HTTPD_ALLOW_HTTP) {
        ESP_LOGW(TAG, "HTTP auto-start: saved config is plain HTTP, not starting (HTTPS only build)");
        return;
    }
    start_server(port);
}

/* AT*M2M*NET_HTTPDSTART=<port> [,<ssl>] [,<cert_name>]
 * ssl=1 needs cert_name: a "server certificate+key file" (one PEM, both
 * blocks concatenated) previously staged with NET_HTTPDOWNLOAD -- same
 * convention as NET_SERVER=ssl's cert_name and WF_EAPCERT's cert/key
 * files. Uses esp_https_server (esp_tls under the hood, same TLS stack
 * net_link.c's own SSL server already uses) rather than raw sockets,
 * since esp_http_server has no lower-level hook to wrap in TLS itself. */
void cmd_net_httpdstart(const at_command_t *cmd)
{
    if (cmd->argc < 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    long port = atol(cmd->argv[0]);
    int ssl = (cmd->argc >= 2) ? atoi(cmd->argv[1]) : 0;
    const char *cert_name = (cmd->argc >= 3) ? cmd->argv[2] : NULL;
    if (port <= 0 || port > 65535) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (s_httpd) {
        at_reply_error(cmd->name, 3); /* doc: 3-already running */
        return;
    }
    if ((ssl && !HTTPD_ALLOW_HTTPS) || (!ssl && !HTTPD_ALLOW_HTTP)) {
        at_reply_error(cmd->name, 4); /* 4-transport disabled in this build (Kconfig AT_MODEM_HTTPD_MODE) */
        return;
    }

    if (ssl) {
        if (!cert_name || cert_name[0] == '\0' || strlen(cert_name) > 16 || !fs_store_exists(cert_name)) {
            at_reply_error(cmd->name, 2); /* doc: 2-SSL enabled but certificate/key not configured */
            return;
        }
        char *cert_pem = g_at_pem_scratch; /* shared scratch, see at_pem_scratch.h */
        size_t cert_len;
        if (!load_cert_file(cert_name, cert_pem, AT_PEM_SCRATCH_LEN, &cert_len)) {
            at_reply_error(cmd->name, 2);
            return;
        }
        if (start_server_ssl((uint16_t)port, cert_pem, cert_len + 1) != ESP_OK) {
            at_reply_error(cmd->name, 1); /* doc: 1-port already in use */
            return;
        }
    } else {
        if (start_server((uint16_t)port) != ESP_OK) {
            at_reply_error(cmd->name, 1); /* doc: 1-port already in use */
            return;
        }
    }

    m2m_nvs_set_u16("httpd_enabled", 1);
    m2m_nvs_set_u16("httpd_port", (uint16_t)port);
    m2m_nvs_set_u16("httpd_ssl", ssl ? 1 : 0);
    m2m_nvs_set_str("httpd_cert", ssl ? cert_name : "");
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_HTTPDSTOP */
void cmd_net_httpdstop(const at_command_t *cmd)
{
    if (!s_httpd) {
        at_reply_error(cmd->name, 1); /* doc: 1-no service */
        return;
    }
    httpd_stop(s_httpd);
    s_httpd = NULL;
    s_httpd_is_ssl = false;
    web_auth_session_clear();
    m2m_nvs_set_u16("httpd_enabled", 0);
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_HTTPDCONF -- Query/Set login credentials, persisted in NVS.
 * Since 2026-09-27 (EN 18031-1, see web_auth.c) only a salted hash of the
 * password is stored, so the Query form can no longer return it -- it
 * reports a fixed "********" placeholder in its place (kept as a second
 * field so the doc's response shape doesn't change). A Set is checked
 * against the password policy: reason 1 when it fails. */
void cmd_net_httpdconf(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        char id[WEB_AUTH_ID_MAX + 1];
        web_auth_get_id(id, sizeof(id));
        at_reply_ok(cmd->name, "%s ********", id);
        return;
    }
    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    web_auth_policy_t p = web_auth_set(cmd->argv[0], cmd->argv[1]);
    if (p != WEB_AUTH_POLICY_OK) {
        ESP_LOGW(TAG, "NET_HTTPDCONF rejected: %s", web_auth_policy_text(p));
        at_reply_error(cmd->name, 1); /* 1-id/password does not meet the policy */
        return;
    }
    web_auth_session_clear(); /* credentials changed: log out any web session */
    at_reply_ok(cmd->name, NULL);
}
