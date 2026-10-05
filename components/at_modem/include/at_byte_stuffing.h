#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Byte-stuffing per doc section 1.4 ("Byte Stuffing for Binary Payloads"):
 * a literal 0x0D/0x08/0x1B byte in a NET_SEND/AWS_PUB/... data payload is
 * encoded as 0x1B followed by (byte ^ 0x20), so it can never be confused
 * with the AT protocol's own CR line terminator.
 */

/** Encode `in` (raw bytes, may contain any value) into `out` as ASCII text
 * suitable for embedding in a "*M2M*NET_RECV:..." event line. Returns bytes
 * written, truncating (never partial-escaping) if `out_cap` is too small. */
size_t at_byte_stuff_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/** Decode an escaped text field (from a NET_SEND command's data param)
 * back into raw bytes. Returns bytes written. */
size_t at_byte_stuff_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
