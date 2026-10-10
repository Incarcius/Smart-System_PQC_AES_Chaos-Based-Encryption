/*
 * node_frame.h — the leaf -> gateway telemetry frame.
 *
 * Mirrors the gateway -> server design in include/protocol.h deliberately:
 * cleartext header used as AES-GCM AAD, deterministic nonce from
 * (key_epoch, seq), payload encrypted. Same discipline at both tiers means one
 * set of invariants to reason about rather than two.
 *
 * Wire layout, before COBS:
 *
 *     off  len  field
 *      0    1   version          LEAF_PROTO_VERSION
 *      1    1   channel_count
 *      2    2   endpoint_id      u16 BE  — the ESP32, not a channel
 *      4    4   key_epoch        u32 BE
 *      8    8   seq              u64 BE
 *     16    n   ciphertext       encrypted payload
 *   16+n   16   tag              GCM tag
 *
 *     AAD   = bytes [0 .. 15]
 *     nonce = key_epoch(4 BE) || seq(8 BE)
 *
 * Payload (encrypted):
 *
 *      0    8   timestamp_ms     u64 BE
 *      8    8   channel 0        id, quality, reserved, value
 *     16    8   channel 1
 *     ...
 *
 * For the 5-channel prototype: 16 + 48 + 16 = 80 bytes, 81 after COBS plus a
 * delimiter. At 10 Hz that is ~820 B/s against 11.5 kB/s at 115200 baud, so
 * the link runs at about 7% utilisation — ample headroom for more channels.
 *
 * Why endpoint_id and key_epoch are in the clear
 * ----------------------------------------------
 * The gateway must pick the right session key and reconstruct the nonce before
 * it can decrypt anything, so those fields have to be readable first. They are
 * not unprotected: the whole 16-byte header is the GCM AAD, so flipping any
 * bit of it fails the tag. Same reasoning as the posture field on the uplink.
 *
 * The timestamp is inside the ciphertext because nothing needs it before
 * decryption, and sampling times leak activity patterns.
 */
#ifndef NODE_FRAME_H
#define NODE_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include "channel.h"

#define LEAF_PROTO_VERSION   0x01
#define LEAF_HEADER_LEN      16
#define LEAF_NONCE_LEN       12
#define LEAF_TAG_LEN         16
#define LEAF_KEY_LEN         32

/* 8 bytes of payload per channel, plus the 8-byte timestamp. */
#define LEAF_PAYLOAD_LEN(n)  (8u + 8u * (n))
#define LEAF_FRAME_LEN(n)    (LEAF_HEADER_LEN + LEAF_PAYLOAD_LEN(n) + LEAF_TAG_LEN)

/* Largest frame this build can emit, for static buffer sizing. */
#define LEAF_FRAME_MAX       LEAF_FRAME_LEN(NODE_MAX_CHANNELS)

typedef struct {
    uint8_t  version;
    uint8_t  channel_count;
    uint16_t endpoint_id;
    uint32_t key_epoch;
    uint64_t seq;
} leaf_header_t;

typedef enum {
    LEAF_OK            =  0,
    LEAF_ERR_PARAM     = -1,
    LEAF_ERR_FORMAT    = -2,   /* bad version, or length/count disagree */
    LEAF_ERR_AUTH      = -3,   /* GCM tag failed — forged or corrupt    */
    LEAF_ERR_BACKEND   = -4,   /* AEAD backend failure                  */
    LEAF_ERR_TOO_SMALL = -5    /* output buffer too small               */
} leaf_status_t;

void tg_leaf_header_serialize(const leaf_header_t *h, uint8_t out[LEAF_HEADER_LEN]);
int  tg_leaf_header_parse(const uint8_t in[LEAF_HEADER_LEN], leaf_header_t *h);

/* nonce = key_epoch(4 BE) || seq(8 BE) — identical construction to the uplink. */
void tg_leaf_nonce_derive(const leaf_header_t *h, uint8_t nonce[LEAF_NONCE_LEN]);

/*
 * Build a complete sealed frame.
 *
 * `h->channel_count` must equal `count`. The caller is responsible for `seq`
 * being fresh — on the leaf that means a nonce guard exactly like the
 * gateway's, with key_epoch persisted across reboots.
 *
 * Returns the frame length, or a negative leaf_status_t.
 */
long tg_leaf_frame_seal(const uint8_t key[LEAF_KEY_LEN],
                        const leaf_header_t *h,
                        uint64_t timestamp_ms,
                        const channel_reading_t *readings, size_t count,
                        uint8_t *out, size_t out_cap);

/*
 * Verify and unpack a sealed frame.
 *
 * On success writes the header, timestamp and up to `max_readings` channel
 * readings, and returns the channel count. Any failure returns a negative
 * leaf_status_t and leaves the outputs unspecified — check the return value.
 */
long tg_leaf_frame_open(const uint8_t key[LEAF_KEY_LEN],
                        const uint8_t *in, size_t len,
                        leaf_header_t *h,
                        uint64_t *timestamp_ms,
                        channel_reading_t *readings, size_t max_readings);

#endif /* NODE_FRAME_H */
