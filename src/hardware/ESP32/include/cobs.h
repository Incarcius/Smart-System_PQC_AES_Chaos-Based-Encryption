/*
 * cobs.h — Consistent Overhead Byte Stuffing for the ESP32 -> gateway UART.
 *
 * Why framing is needed at all
 * ---------------------------
 * UART is a byte stream with no message boundaries, and an encrypted frame is
 * arbitrary binary — ciphertext and GCM tag contain 0x00 as often as any other
 * value. The deck (slide 13) describes sending JSON over UART, which works for
 * plaintext readings but not once AES-GCM is in the path.
 *
 * Why COBS rather than the alternatives
 * -------------------------------------
 *   base64 inside JSON   works, +33% bytes, and easy to eyeball while debugging
 *   length-prefix        smallest, but a single corrupted length byte
 *                        desynchronises the stream until someone restarts the
 *                        link — on a substation UART run that is a dead link,
 *                        not a dropped packet
 *   COBS                 1 byte overhead per frame (+1 per 254), and 0x00
 *                        appears ONLY as the delimiter, so a receiver that
 *                        loses sync resynchronises at the very next frame
 *                        boundary with no ambiguity
 *
 * The resync property is the one that matters here. Electrical noise on a
 * substation line is expected, not exceptional, and recovery should be
 * automatic.
 *
 * Encoding removes every zero byte from the payload; the caller appends a
 * single 0x00 as the frame delimiter.
 */
#ifndef NODE_COBS_H
#define NODE_COBS_H

#include <stdint.h>
#include <stddef.h>

/*
 * Worst-case encoded size for `n` payload bytes, EXCLUDING the trailing
 * delimiter: one overhead byte, plus one more per 254 bytes of payload.
 * Allocate with this; never assume the encoding shrinks anything.
 */
#define COBS_ENCODED_MAX(n)  ((n) + ((n) / 254u) + 1u)

/*
 * Encode `len` bytes into `dst`, which must hold at least
 * COBS_ENCODED_MAX(len). Returns the number of bytes written. Does NOT write
 * the trailing 0x00 delimiter — the caller does that, so a transport that
 * already frames can skip it.
 *
 * The output is guaranteed to contain no 0x00 byte.
 */
size_t cobs_encode(const uint8_t *src, size_t len, uint8_t *dst);

/*
 * Decode `len` bytes (a single frame, delimiter already stripped) into `dst`,
 * which must hold at least `len` bytes.
 *
 * Returns the decoded length, or -1 if the frame is malformed: a zero code
 * byte, or a code that runs past the end of the input. Both mean a corrupted
 * or truncated frame — drop it and wait for the next delimiter.
 */
long cobs_decode(const uint8_t *src, size_t len, uint8_t *dst);

#endif /* NODE_COBS_H */
