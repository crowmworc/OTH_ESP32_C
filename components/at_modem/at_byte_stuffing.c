#include "at_byte_stuffing.h"

size_t at_byte_stuff_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t b = in[i];
        if (b == 0x0D || b == 0x08 || b == 0x1B) {
            if (o + 2 > out_cap) {
                break;
            }
            out[o++] = (char)0x1B;
            out[o++] = (char)(b ^ 0x20);
        } else {
            if (o + 1 > out_cap) {
                break;
            }
            out[o++] = (char)b;
        }
    }
    return o;
}

size_t at_byte_stuff_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; i < in_len && o < out_cap; i++) {
        uint8_t b = (uint8_t)in[i];
        if (b == 0x1B && i + 1 < in_len) {
            out[o++] = (uint8_t)((uint8_t)in[++i] ^ 0x20);
        } else {
            out[o++] = b;
        }
    }
    return o;
}
