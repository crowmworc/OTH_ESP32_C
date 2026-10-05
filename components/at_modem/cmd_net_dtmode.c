/* AT*M2M*NET_DTMODE (doc Ch.4.1/8.5) -- transparent passthrough: UART bytes
 * relay directly to one open link, bypassing the AT command parser, until
 * "+++" (framed by >=20ms silence on both sides) or NET_DTMODE=0 leaves it.
 *
 * NOTE: the "+++" guard-time detection (at_uart.c's
 * at_uart_passthrough_loop()) hasn't been exercised against a real serial
 * host yet -- it's implemented from the doc's description of the classic
 * Hayes escape sequence, but the exact timing needs live verification once
 * hardware is available for this phase.
 */

#include <stdlib.h>

#include "at_commands.h"
#include "at_response.h"
#include "at_uart.h"
#include "net_link.h"

static volatile int s_dtmode_link = -1;
static volatile int s_dtmode_interval_ms = 200;

static void dtmode_sink(const uint8_t *data, size_t len)
{
    if (s_dtmode_link >= 0) {
        net_link_send(s_dtmode_link, data, len);
    }
}

/* Doc Ch.8.5's example: after "+++" and its trailing silence, the host's
 * very next line is a plain "AT" which just gets the usual "OK" -- leaving
 * passthrough is silent on the module's side, no notification of its own. */
static void dtmode_on_escape(void)
{
    s_dtmode_link = -1;
    net_link_set_passthrough(-1);
}

void cmd_net_dtmode(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        int active = s_dtmode_link >= 0;
        at_reply_ok(cmd->name, "%d %d %d", active, active ? s_dtmode_link : 0, s_dtmode_interval_ms);
        return;
    }

    if (cmd->argc < 2) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    int link_id = atoi(cmd->argv[1]);

    if (mode == 0) {
        /* Not in the doc's parameter list (only "+++" is documented as the
         * way out) but a sane escape hatch to have alongside it. */
        s_dtmode_link = -1;
        net_link_set_passthrough(-1);
        at_uart_set_passthrough(NULL, NULL);
        at_reply_ok(cmd->name, "%d %d", mode, link_id);
        return;
    }
    if (mode != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (link_id < 0 || link_id >= NET_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    int interval_ms = (cmd->argc >= 3) ? atoi(cmd->argv[2]) : 200;
    if (interval_ms < 10 || interval_ms > 1000) {
        interval_ms = 200; /* doc: out-of-range falls back to the default */
    }

    s_dtmode_interval_ms = interval_ms;
    s_dtmode_link = link_id;
    net_link_set_passthrough(link_id);
    at_uart_set_passthrough(dtmode_sink, dtmode_on_escape);
    at_reply_ok(cmd->name, "%d %d", mode, link_id);
}
