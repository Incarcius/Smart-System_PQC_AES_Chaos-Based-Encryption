/*
 * cobs.c — Consistent Overhead Byte Stuffing. See cobs.h for why.
 *
 * The encoding replaces each zero byte with the distance to the next zero.
 * A leading "code" byte gives the distance to the first zero; runs longer than
 * 254 non-zero bytes are split with a 0xFF code that consumes no input byte.
 */
#include "cobs.h"

size_t cobs_encode(const uint8_t *src, size_t len, uint8_t *dst)
{
    size_t read_i = 0;
    size_t code_i = 0;   /* where the current code byte will be written */
    size_t write_i = 1;  /* first payload byte goes after that code byte */
    uint8_t code = 1;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    while (read_i < len) {
        if (src[read_i] == 0) {
            /* Close the current run: the code byte is the distance to here. */
            dst[code_i] = code;
            code_i  = write_i++;
            code    = 1;
            read_i++;
            continue;
        }

        dst[write_i++] = src[read_i++];
        code++;

        if (code == 0xFF) {
            /*
             * A full 254-byte run with no zero. Emit the code and start a new
             * group. Note this consumes no input byte, which is why the
             * worst-case size adds one byte per 254 rather than per 255.
             */
            dst[code_i] = code;
            code_i  = write_i++;
            code    = 1;
        }
    }

    dst[code_i] = code;
    return write_i;
}

long cobs_decode(const uint8_t *src, size_t len, uint8_t *dst)
{
    size_t read_i = 0;
    size_t write_i = 0;

    if (src == NULL || dst == NULL) {
        return -1;
    }

    while (read_i < len) {
        uint8_t code = src[read_i];
        uint8_t i;

        /*
         * A zero code byte is impossible in a well-formed frame — the encoder
         * never emits one, and 0x00 is the delimiter, so finding one inside a
         * frame means the frame was truncated or corrupted.
         */
        if (code == 0) {
            return -1;
        }

        /* The run must fit inside what is left of the input. */
        if (read_i + code > len) {
            return -1;
        }

        read_i++;

        for (i = 1; i < code; i++) {
            dst[write_i++] = src[read_i++];
        }

        /*
         * A group shorter than 0xFF represents a zero byte in the original,
         * except when it ends exactly at the end of the frame — that trailing
         * zero was never part of the payload.
         */
        if (code != 0xFF && read_i < len) {
            dst[write_i++] = 0;
        }
    }

    return (long)write_i;
}
