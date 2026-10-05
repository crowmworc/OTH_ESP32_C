#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"

#include "at_event.h"
#include "at_uart.h"

static const char *TAG = "at_event";

#define AT_EVENT_LINE_MAX 256

typedef struct {
    char line[AT_EVENT_LINE_MAX];
    size_t len;
} at_event_msg_t;

static QueueHandle_t s_queue;
static atomic_bool s_enabled = true;

static void at_event_task(void *arg)
{
    at_event_msg_t msg;
    for (;;) {
        if (xQueueReceive(s_queue, &msg, portMAX_DELAY) == pdTRUE) {
            at_uart_write(msg.line, msg.len);
        }
    }
}

void at_event_init(void)
{
    s_queue = xQueueCreate(CONFIG_AT_MODEM_EVENT_QUEUE_LEN, sizeof(at_event_msg_t));
    xTaskCreate(at_event_task, "at_event", 3072, NULL, 9, NULL);
}

void at_event_set_enabled(bool enabled)
{
    atomic_store(&s_enabled, enabled);
}

void at_event_post(const char *fmt, ...)
{
    if (!atomic_load(&s_enabled)) {
        return;
    }

    at_event_msg_t msg;
    int n = snprintf(msg.line, sizeof(msg.line), "*M2M*");
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(msg.line + n, sizeof(msg.line) - n, fmt, ap);
    va_end(ap);

    if (n < 0) {
        return;
    }
    if ((size_t)n > sizeof(msg.line) - 3) {
        n = sizeof(msg.line) - 3;
    }
    msg.line[n++] = '\r';
    msg.line[n++] = '\n';
    msg.len = (size_t)n;

    if (xQueueSend(s_queue, &msg, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "event queue full, dropping: %s", msg.line);
    }
}
