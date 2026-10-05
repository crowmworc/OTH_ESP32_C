#include "sdkconfig.h"

#include "at_modem.h"
#include "at_uart.h"
#include "at_event.h"
#include "at_wifi.h"
#include "net_link.h"
#include "at_httpd.h"
#include "fs_store.h"
#include "at_ble_prov.h"

void at_modem_init(void)
{
    at_event_init();
    at_uart_init();
    at_wifi_init();
    net_link_init();
    fs_store_init();
    at_httpd_init();
    at_ble_prov_init();

#if CONFIG_M2M_PWRON_NOTIFY
    /* Doc Ch.7.1: "*M2M*DEVICEREADY -- Module has booted and is ready for
     * commands." Sent last, once every subsystem above is actually usable.
     * Gated by the release-naming CONFIG segment's PWRON digit (M2M_SW
     * Release Naming Guide v2.0 section 4.6) -- this project's actual
     * default is PWRON=0 (host polls instead), matching the doc's own
     * documented default; only send this when a build explicitly opts in
     * via idf.py menuconfig -> M2M Release Naming. */
    at_event_post("DEVICEREADY");
#endif
}
