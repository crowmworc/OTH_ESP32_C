#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** Create the event queue and the writer task that drains it to the AT UART. */
void at_event_init(void);

/** AT*M2M*SYS_FACTORY-adjacent housekeeping toggles whether async events are
 * emitted at all (reserved for a future EVTDEL-equivalent command). */
void at_event_set_enabled(bool enabled);
bool at_event_enabled(void);

/**
 * Format and enqueue an async "*M2M*..." event line (CRLF appended
 * automatically). Safe to call from any task or from an esp_event handler
 * context -- never blocks on UART I/O directly.
 *
 * Example: at_event_post("WF_CONN:DONE");
 */
void at_event_post(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
