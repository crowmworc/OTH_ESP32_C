#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "at_uart.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Generic error codes used when the M2M doc doesn't enumerate specific
 * per-command codes for a given failure (see Appendix C for the documented
 * ones). Individual command handlers may use those documented codes
 * instead where the doc specifies them. */
#define AT_ERR_GENERIC       1
#define AT_ERR_ARG           2
#define AT_ERR_STATE         3
#define AT_ERR_TIMEOUT       4
#define AT_ERR_NOT_SUPPORTED 99

/** "*M2M*<cmd>:OK[ <fmt...>]\r\n" -- pass fmt=NULL for a bare OK. */
static inline void at_reply_ok(const char *cmd, const char *fmt, ...)
{
    char line[256];
    int n = snprintf(line, sizeof(line), "*M2M*%s:OK", cmd);
    if (fmt && n > 0 && n < (int)sizeof(line)) {
        va_list ap;
        va_start(ap, fmt);
        line[n++] = ' ';
        vsnprintf(line + n, sizeof(line) - n, fmt, ap);
        va_end(ap);
    }
    size_t len = strnlen(line, sizeof(line) - 3);
    line[len++] = '\r';
    line[len++] = '\n';
    at_uart_write(line, len);
}

/** "*M2M*<cmd>:ERROR[ <code>]\r\n" -- pass code<0 to omit the code. */
static inline void at_reply_error(const char *cmd, int code)
{
    char line[64];
    int len;
    if (code >= 0) {
        len = snprintf(line, sizeof(line), "*M2M*%s:ERROR %d\r\n", cmd, code);
    } else {
        len = snprintf(line, sizeof(line), "*M2M*%s:ERROR\r\n", cmd);
    }
    at_uart_write(line, (size_t)len);
}

/** Bare "OK\r\n" for special commands (AT, ATE, ATV). */
static inline void at_reply_special_ok(void)
{
    at_uart_write_str("OK\r\n");
}

/** Bare "ERROR\r\n" for special commands (AT, ATE, ATV). */
static inline void at_reply_special_error(void)
{
    at_uart_write_str("ERROR\r\n");
}

/**
 * "*M2M*<fmt>...\r\n" -- for IND/DONE-shaped lines a command handler emits
 * itself as a *synchronous* continuation of its own reply (e.g. WF_SCAN's
 * IND lines before its trailing DONE, NET_STATUS's IND lines before its
 * OK). Never use at_event_post() for these: that queues onto the lower-
 * priority event-writer task, so a same-handler at_reply_ok()/error() call
 * right after routinely wins the race and lands on the wire first, putting
 * OK/ERROR before the IND lines it was supposed to follow. at_event_post()
 * remains correct for genuinely asynchronous notifications fired later
 * from a different context (a Wi-Fi/socket event callback).
 */
static inline void at_reply_line(const char *fmt, ...)
{
    char line[300];
    int n = snprintf(line, sizeof(line), "*M2M*");
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof(line) - n, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if ((size_t)n > sizeof(line) - 3) {
        n = (int)sizeof(line) - 3;
    }
    line[n++] = '\r';
    line[n++] = '\n';
    at_uart_write(line, (size_t)n);
}

#ifdef __cplusplus
}
#endif
