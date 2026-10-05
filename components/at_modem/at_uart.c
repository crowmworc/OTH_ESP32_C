#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#if CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG
#include "driver/usb_serial_jtag.h"
#endif
#include "lwip/sockets.h"
#include "esp_log.h"

#include "at_uart.h"
#include "at_dispatch.h"

static const char *TAG = "at_uart";

#define AT_UART_PORT      ((uart_port_t)CONFIG_AT_MODEM_UART_PORT)
/* AT*M2M*NET_SEND's payload can be up to 8192 bytes (doc Ch.4.2), and every
 * byte the host stuffs (Ch.1.4: literal 0x0D/0x08/0x1B) doubles in size on
 * the wire -- worst case 16384 bytes of stuffed payload, plus room for the
 * "AT*M2M*NET_SEND=<link_id> <size> " prefix. This is a `static` buffer
 * (not on the task's stack), so the extra ~16KB is cheap on this chip's
 * ~400KB SRAM. */
#define AT_LINE_MAX        16448

/* CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG: carry the AT command stream over
 * the chip's built-in USB Serial/JTAG controller (same USB cable used for
 * flashing/monitor, e.g. COM7) instead of a physical UART peripheral -- no
 * second USB-serial adapter needed. See the Kconfig help for the required
 * console-secondary-output trade-off (must be disabled or ESP_LOG lines
 * corrupt the AT stream). */
#if CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG
static inline int at_transport_read_byte(uint8_t *byte, TickType_t timeout)
{
    return usb_serial_jtag_read_bytes(byte, 1, timeout);
}
static inline void at_transport_write(const char *data, size_t len)
{
    usb_serial_jtag_write_bytes(data, len, portMAX_DELAY);
}
#else
static inline int at_transport_read_byte(uint8_t *byte, TickType_t timeout)
{
    return uart_read_bytes(AT_UART_PORT, byte, 1, timeout);
}
static inline void at_transport_write(const char *data, size_t len)
{
    uart_write_bytes(AT_UART_PORT, data, len);
}
#endif

static SemaphoreHandle_t s_write_mutex;
static atomic_bool s_echo = false;
/* -1 = write to the physical UART (default); >=0 = an at_net_console.c TCP
 * client fd currently stands in for it. Guarded by s_write_mutex, same as
 * the writes themselves. */
static int s_tcp_fd = -1;

/* AT*M2M*NET_DTMODE passthrough state -- see at_uart_set_passthrough(). Only
 * ever touched by at_uart_rx_task() except for the initial set/clear calls
 * (a command handler calling at_uart_set_passthrough(NULL,...) to force an
 * early exit), so a plain atomic_bool "active" flag is enough; the sink/
 * callback pointers are only read by the task after observing active==true,
 * and only written right before flipping active, so there's no torn read. */
static atomic_bool s_passthrough_active = false;
static at_uart_passthrough_sink_t s_passthrough_sink;
static void (*s_passthrough_on_escape)(void);

void at_uart_set_passthrough(at_uart_passthrough_sink_t sink, void (*on_escape)(void))
{
    if (sink) {
        s_passthrough_sink = sink;
        s_passthrough_on_escape = on_escape;
        atomic_store(&s_passthrough_active, true);
    } else {
        atomic_store(&s_passthrough_active, false);
    }
}

/* doc Ch.8.5: "+++" (three plus characters, no other characters, framed by
 * >=20ms of silence on both sides) exits passthrough. Implemented as the
 * classic Hayes guard-time state machine: buffer up to 3 leading '+'
 * bytes without forwarding them; a 20ms read timeout with exactly 3
 * buffered confirms the escape, while any other byte (or a 4th '+')
 * flushes the buffered '+'s as ordinary data and resets. */
static int s_escape_guard_ms = 20;

void at_uart_set_escape_guard_ms(int ms)
{
    s_escape_guard_ms = ms;
}

static void at_uart_passthrough_loop(void)
{
    int plus_run = 0;
    bool seen_silence = false;
    uint8_t byte;

    while (atomic_load(&s_passthrough_active)) {
        int n = at_transport_read_byte(&byte, pdMS_TO_TICKS(20));
        if (n <= 0 && plus_run == 3 && s_escape_guard_ms > 20) {
            /* OTH-AT: "+++" must be followed by a longer silence */
            n = at_transport_read_byte(&byte, pdMS_TO_TICKS(s_escape_guard_ms - 20));
        }
        if (n <= 0) {
            if (plus_run == 3) {
                void (*on_escape)(void) = s_passthrough_on_escape;
                atomic_store(&s_passthrough_active, false);
                if (on_escape) {
                    on_escape();
                }
                return;
            }
            seen_silence = true;
            continue;
        }

        if (byte == '+' && plus_run < 3 && (plus_run > 0 || seen_silence)) {
            plus_run++;
            seen_silence = false;
            continue; /* tentatively buffered, not forwarded yet */
        }

        for (int i = 0; i < plus_run; i++) {
            uint8_t plus = '+';
            s_passthrough_sink(&plus, 1);
        }
        plus_run = 0;
        seen_silence = false;
        s_passthrough_sink(&byte, 1);
    }
}

/* Doc Ch.1.1: a command line sent Host->Modem always terminates with a
 * bare CR (0x0D). Byte-stuffing/escaping of literal 0x0D/0x08/0x1B bytes
 * only applies to the *data payload* of AT*M2M*NET_SEND/AWS_PUB (handled by
 * the relevant command layer, not here) -- so the line reader below only
 * needs to treat an unescaped CR as end-of-line. */
static void at_uart_rx_task(void *arg)
{
    static char line[AT_LINE_MAX];
    size_t idx = 0;
    uint8_t byte;

    for (;;) {
        if (atomic_load(&s_passthrough_active)) {
            at_uart_passthrough_loop();
            idx = 0; /* discard any partial line buffered before passthrough started */
            continue;
        }

        int n = at_transport_read_byte(&byte, portMAX_DELAY);
        if (n <= 0) {
            continue;
        }

        if (atomic_load(&s_echo)) {
            at_uart_write((const char *)&byte, 1);
        }

        if (byte == '\r') {
            line[idx] = '\0';
            if (idx > 0) {
                at_dispatch_line(line);
            }
            idx = 0;
        } else if (byte == '\n' && idx == 0) {
            /* The LF of a host's CRLF line ending. Not a terminator, and
             * ignored only here: inside a line it is payload data (byte
             * stuffing, doc Ch.1.4, escapes CR/BS/ESC but not LF), which
             * dropping it used to corrupt. */
            continue;
        } else if (idx < AT_LINE_MAX - 1) {
            line[idx++] = (char)byte;
        } else {
            ESP_LOGW(TAG, "line overflow, dropping");
            idx = 0;
        }
    }
}

void at_uart_init(void)
{
    s_write_mutex = xSemaphoreCreateMutex();

#if CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG
    usb_serial_jtag_driver_config_t cfg = {
        .rx_buffer_size = CONFIG_AT_MODEM_UART_RX_BUF_SIZE,
        .tx_buffer_size = CONFIG_AT_MODEM_UART_TX_BUF_SIZE,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));
#else
    uart_config_t cfg = {
        .baud_rate = CONFIG_AT_MODEM_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(AT_UART_PORT,
                                         CONFIG_AT_MODEM_UART_RX_BUF_SIZE,
                                         CONFIG_AT_MODEM_UART_TX_BUF_SIZE,
                                         0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(AT_UART_PORT, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(AT_UART_PORT,
                                  CONFIG_AT_MODEM_UART_TX_GPIO,
                                  CONFIG_AT_MODEM_UART_RX_GPIO,
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
#endif

    xTaskCreate(at_uart_rx_task, "at_uart_rx", 4096, NULL, 10, NULL);

#if CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG
    ESP_LOGI(TAG, "AT UART ready: native USB Serial/JTAG, baud=n/a (USB CDC)");
#else
    ESP_LOGI(TAG, "UART%d ready: TX=%d RX=%d baud=%d",
              CONFIG_AT_MODEM_UART_PORT, CONFIG_AT_MODEM_UART_TX_GPIO,
              CONFIG_AT_MODEM_UART_RX_GPIO, CONFIG_AT_MODEM_UART_BAUD_RATE);
#endif
}

void at_uart_write(const char *data, size_t len)
{
    xSemaphoreTake(s_write_mutex, portMAX_DELAY);
    if (s_tcp_fd >= 0) {
        if (lwip_send(s_tcp_fd, data, len, 0) < 0) {
            /* Client vanished without at_net_console.c noticing yet -- fall
             * back to the physical UART until the next connect. */
            s_tcp_fd = -1;
        }
    } else {
        at_transport_write(data, len);
    }
    xSemaphoreGive(s_write_mutex);
}

void at_uart_write_str(const char *str)
{
    at_uart_write(str, strlen(str));
}

void at_uart_write_atomic2(const char *a, size_t a_len, const char *b, size_t b_len)
{
    xSemaphoreTake(s_write_mutex, portMAX_DELAY);
    if (s_tcp_fd >= 0) {
        if (lwip_send(s_tcp_fd, a, a_len, 0) < 0 || lwip_send(s_tcp_fd, b, b_len, 0) < 0) {
            s_tcp_fd = -1;
        }
    } else {
        at_transport_write(a, a_len);
        at_transport_write(b, b_len);
    }
    xSemaphoreGive(s_write_mutex);
}

void at_uart_set_echo(bool enabled)
{
    atomic_store(&s_echo, enabled);
}

bool at_uart_read_raw(uint8_t *out, size_t len, uint32_t timeout_ms)
{
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    size_t got = 0;
    while (got < len) {
        TickType_t now = xTaskGetTickCount();
        if (now >= deadline) {
            return false;
        }
        int n = at_transport_read_byte(&out[got], deadline - now);
        if (n <= 0) {
            return false;
        }
        got++;
    }
    return true;
}

void at_uart_apply_baud_rate(uint32_t baud_rate)
{
#if !CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG
    uart_set_baudrate(AT_UART_PORT, baud_rate);
#else
    (void)baud_rate;
#endif
}

void at_uart_bind_tcp_client(int fd)
{
    xSemaphoreTake(s_write_mutex, portMAX_DELAY);
    s_tcp_fd = fd;
    xSemaphoreGive(s_write_mutex);
}
