#include "sdkconfig.h"

#include "at_modem.h"
#include "at_uart.h"
#include "at_dispatch.h"
#include "at_event.h"
#include "at_wifi.h"
#include "net_link.h"
#include "at_httpd.h"
#include "fs_store.h"
#include "at_ble_prov.h"
#include "at_cmdset.h"
#if CONFIG_AT_MODEM_CMDSET_OTH
#include "at_commands_oth.h"
#endif

void at_modem_init(void)
{
    at_event_init();
    at_uart_init();
    at_wifi_init();
#if CONFIG_AT_MODEM_CMDSET_OTH
    at_oth_net_init(); /* OTH-AT sockets (oth_sock.c) instead of net_link.c */
    at_uart_set_escape_guard_ms(500);
#else
    net_link_init();
#endif
    fs_store_init();
    at_httpd_init();
    at_ble_prov_init();

#if CONFIG_AT_MODEM_CMDSET_OTH
    at_oth_init();
    at_dispatch_set_ready(); /* lines received during the init above may run now */
    /* OTH-AT Ch.7: DEVICEREADY once ready (suppressed by EVTDEL=1), then
     * INITSCAN when a saved station profile is being rejoined. */
    at_event_post("DEVICEREADY");
    if (at_wifi_take_boot_autoconnect()) {
        at_event_post("INITSCAN");
    }
#else
    at_dispatch_set_ready();
#endif
#if !CONFIG_AT_MODEM_CMDSET_OTH && CONFIG_M2M_PWRON_NOTIFY
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
