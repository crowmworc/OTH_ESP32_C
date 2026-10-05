set(srcs
        "at_modem.c"
        "at_uart.c"
        "at_parser.c"
        "at_dispatch.c"
        "at_event.c"
        "at_byte_stuffing.c"
        "at_nvs_kv.c"
        "cmd_special.c"
        "cmd_sys.c"
        "cmd_wifi.c"
        "net_link.c"
        "cmd_net.c"
        "cmd_net_svc.c"
        "cmd_net_dtmode.c"
        "fs_store.c"
        "cmd_http.c"
        "cmd_httpd.c"
        "cmd_mqtt.c"
        "cmd_ota.c"
        "cmd_aws.c"
        "m2m_image_id.c"
        "cmd_ble_prov.c"
        "at_pem_scratch.c"
        "web_auth.c")
# OTH-AT front end (Kconfig AT_MODEM_CMDSET), over the shared code above.
if(CONFIG_AT_MODEM_CMDSET_OTH)
    list(APPEND srcs
        "cmd_oth_basic.c"
        "cmd_oth_wifi.c"
        "oth_sock.c"
        "cmd_oth_net.c"
        "cmd_oth_svc.c"
        "cmd_oth_fwup.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES driver nvs_flash esp_hw_support lwip esp_driver_usb_serial_jtag
                  esp_wifi wpa_supplicant esp_netif esp_event esp_app_format
                  esp_http_client esp_http_server esp_https_server spiffs mbedtls esp-tls mqtt
                  esp_https_ota app_update esp_partition json
                  esp_timer bt wifi_provisioning
    # Pre-gzipped web UI (see webui/index.html -- regenerate with
    # `gzip -9 -c webui/index.html > webui/index.html.gz` after editing it)
    EMBED_FILES "webui/index.html.gz"
)

# M2M_FW_VERSION (m2m_version.h) must equal PROJECT_VER (top-level
# CMakeLists.txt) -- read it via the build-property API rather than the
# CMake variable directly, since idf_component_register() runs in a
# function scope that plain `set()` variables from the top-level file don't
# propagate into.
idf_build_get_property(m2m_proj_ver PROJECT_VER)
target_compile_definitions(${COMPONENT_LIB} PRIVATE M2M_FW_VERSION_STR="${m2m_proj_ver}")

# m2m_image_id (m2m_image_id.c) is never referenced at runtime by this
# firmware itself -- only a *future* OTA image's own copy gets read, from
# flash, by *this* running image (see cmd_ota.c) -- so keep the linker from
# dropping it as unused.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-u m2m_image_id")
