#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse and execute one complete, CR-stripped AT command line (mutable
 * buffer, may be tokenized in place). Looks up the command in the static
 * dispatch table and invokes its handler, which is responsible for sending
 * the appropriate OK/ERROR response itself. Unknown/malformed lines get a
 * generic ERROR reply.
 */
void at_dispatch_line(char *line);

/**
 * Runs the command lines at_dispatch_line() held back while the boot-time
 * Wi-Fi join was pending, in order, once it has an outcome. Called by the
 * line reader between bytes; returns true while lines are still held (the
 * caller then polls again soon instead of blocking).
 */
bool at_dispatch_poll(void);

/** Called once at the end of at_modem_init(): lines held since boot may run. */
void at_dispatch_set_ready(void);

#ifdef __cplusplus
}
#endif
