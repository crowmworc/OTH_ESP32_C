/* AT, ATE, ATV. Bare "OK"/"ERROR" replies, no "*M2M*" wrapper. */

#include "at_commands.h"
#include "at_response.h"
#include "at_uart.h"

/* AT -- check whether Host and Modem are connected. */
void cmd_at(const at_command_t *cmd)
{
    (void)cmd;
    at_reply_special_ok();
}

/* ATE<0/1> -- turn received-character echo off/on. */
void cmd_ate(const at_command_t *cmd)
{
    if (cmd->argc < 1 || (cmd->argv[0][0] != '0' && cmd->argv[0][0] != '1')) {
        at_reply_special_error();
        return;
    }
    at_uart_set_echo(cmd->argv[0][0] == '1');
    at_reply_special_ok();
}

/* ATV (TBD in the doc) -- accepted as a no-op. */
void cmd_atv(const at_command_t *cmd)
{
    (void)cmd;
    at_reply_special_ok();
}
