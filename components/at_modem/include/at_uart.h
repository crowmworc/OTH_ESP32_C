#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the AT command UART (port/pins/baud from Kconfig) and start
 * the RX task that reads CR-terminated lines and hands each complete line
 * to the dispatcher.
 */
void at_uart_init(void);

/**
 * Write a raw, already-formatted line (e.g. "*M2M*SYS_VER:OK 1.0 ...\r\n")
 * to the AT UART. Thread-safe: serializes against other writers (responses,
 * events) with an internal mutex. Does not add or strip any terminators.
 */
void at_uart_write(const char *data, size_t len);

/** Convenience wrapper around at_uart_write() for NUL-terminated strings. */
void at_uart_write_str(const char *str);

/**
 * Write two buffers as one atomic unit -- no other writer's output (a
 * command reply, an event) can land between them. Needed when a payload
 * that may itself contain structurally-significant bytes (a literal CR,
 * say) must go out immediately after a formatted header on the same
 * logical line, e.g. AT*M2M*NET_RECV:IND's raw data field (doc Ch.1.4:
 * module->host payloads are never byte-stuffed, so the header's <size>
 * field is the only way the host knows where the payload ends).
 */
void at_uart_write_atomic2(const char *a, size_t a_len, const char *b, size_t b_len);

/**
 * AT*M2M*NET_DTMODE=1 (doc Ch.4.1/8.5): while active, received bytes are
 * handed to `sink` raw instead of being assembled into AT command lines.
 * The "+++" escape (three plus characters framed by >=20ms of silence on
 * both sides, no other characters) is still detected internally; once
 * confirmed, the RX task clears the sink itself and calls `on_escape`
 * (may be NULL) before resuming normal AT line parsing.
 *
 * Pass sink=NULL to cancel passthrough immediately without waiting for the
 * escape sequence (used when the underlying link closes, or by
 * AT*M2M*NET_DTMODE=0 -- not in the doc's parameter list, but a sane
 * escape hatch alongside "+++").
 */
typedef void (*at_uart_passthrough_sink_t)(const uint8_t *data, size_t len);
void at_uart_set_passthrough(at_uart_passthrough_sink_t sink, void (*on_escape)(void));
/* Silence (ms) that must follow "+++" to leave passthrough: 20 by default
 * (M2M-AT), 500 for OTH-AT. */
void at_uart_set_escape_guard_ms(int ms);
/* Every received byte goes to `sink` (no "+++" escape) until called with
 * NULL -- for binary transfers such as OTH-AT FWUPGRADE (XMODEM). */
void at_uart_set_raw_sink(at_uart_passthrough_sink_t sink);

/**
 * Blocking read of exactly `len` raw bytes from the host, bypassing the
 * normal AT line parser entirely -- for AT*M2M*AWS_PUB's "> <raw_payload>"
 * step (doc Ch.6.5): the host's command line gets "OK" + a literal "> "
 * prompt, then sends the payload as a separate write, which the module
 * must read as exactly <data_len> raw bytes rather than a CR-terminated
 * AT line. Must be called synchronously from within a command handler
 * (i.e. still on the AT dispatcher's own call stack) -- it works by
 * borrowing that same call stack to read bytes directly, not by touching
 * any shared passthrough state, so it composes fine with NET_DTMODE.
 * Returns false on timeout (any bytes already read are discarded).
 */
bool at_uart_read_raw(uint8_t *out, size_t len, uint32_t timeout_ms);

/** ATE<0/1>: echo every received byte back to the Host. */
void at_uart_set_echo(bool enabled);

/**
 * AT*M2M*SYS_UART: apply a new baud rate to the physical UART immediately.
 * No-op when CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG is enabled -- USB CDC
 * has no real baud rate, so the value is only persisted (by the caller) for
 * reporting back on the next SYS_UART query.
 */
void at_uart_apply_baud_rate(uint32_t baud_rate);

/**
 * Redirect at_uart_write() output to a connected TCP client's socket fd
 * instead of the physical UART (used by at_net_console.c as an alternate AT
 * command transport for when no UART hardware is wired up). Pass -1 to fall
 * back to the physical UART.
 */
void at_uart_bind_tcp_client(int fd);

#ifdef __cplusplus
}
#endif
