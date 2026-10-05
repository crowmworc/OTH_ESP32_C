#pragma once
/* Shared scratch buffer for the several call sites (net_link.c's SSL
 * connect/listen, cmd_httpd.c's HTTPS auto-start/NET_HTTPDSTART, cmd_wifi.c's
 * WF_EAPCERT PAC file) that load one PEM/PAC file from fs_store just long
 * enough to hand it to a library call that copies it into its own storage
 * (esp_tls, httpd_ssl_start/mbedtls, esp_eap_client_set_pac_file) --
 * confirmed by reading each callee, since a library that instead keeps the
 * raw pointer (as wpa_supplicant's esp_eap_client_set_ca_cert/
 * set_certificate_and_key and esp-mqtt's client config both do) would turn a
 * shared buffer into a use-after-reuse bug. Those call sites keep their own
 * persistent static buffers (cmd_wifi.c's s_ca_pem/s_cert_pem/s_key_pem,
 * cmd_aws.c's/cmd_mqtt.c's cert buffers) and must not be switched to this one.
 *
 * The AT command dispatcher is single-threaded (at_dispatch_line() runs to
 * completion before the next line is parsed -- see at_uart.c), so one shared
 * buffer is safe across these call sites the same way each file's own
 * "scratch, reused" static already was. Collapsing 5 separate 2200-byte
 * statics into 1 saves ~8.8KB of .bss (added 2026-09-26 when AT*M2M*BLE_PROV
 * pushed free heap too low for wifi_provisioning+NimBLE to init -- see
 * doc/M2M BT Provisioning Architecture Review.docx). */
#define AT_PEM_SCRATCH_LEN 2200
extern char g_at_pem_scratch[AT_PEM_SCRATCH_LEN];
