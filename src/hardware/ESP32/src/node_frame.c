/*
 * node_frame.c — leaf -> gateway frame construction. See node_frame.h.
 */
#include "node_frame.h"
#include "aead_iface.h"

#include <string.h>

/* ── big-endian helpers ──────────────────────────────────────────────────── */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/*
 * Floats travel as their IEEE-754 single-precision bit pattern, big-endian.
 *
 * memcpy rather than a pointer cast or a union: casting a float* to uint32*
 * violates strict aliasing and modern compilers do miscompile it. memcpy of
 * four bytes is recognised and emitted as a register move, so this costs
 * nothing.
 *
 * Every target here (xtensa, ARM, x86-64) is IEEE-754 with the same byte
 * order within the word, so the bit pattern is portable. The KAT pins it.
 */
static void put_f32(uint8_t *p, float v)
{
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));
    put_u32(p, bits);
}

static float get_f32(const uint8_t *p)
{
    uint32_t bits = get_u32(p);
    float v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

/* ── header ──────────────────────────────────────────────────────────────── */

void tg_leaf_header_serialize(const leaf_header_t *h, uint8_t out[LEAF_HEADER_LEN])
{
    out[0] = h->version;
    out[1] = h->channel_count;
    put_u16(out + 2, h->endpoint_id);
    put_u32(out + 4, h->key_epoch);
    put_u64(out + 8, h->seq);
}

int tg_leaf_header_parse(const uint8_t in[LEAF_HEADER_LEN], leaf_header_t *h)
{
    h->version       = in[0];
    h->channel_count = in[1];
    h->endpoint_id   = get_u16(in + 2);
    h->key_epoch     = get_u32(in + 4);
    h->seq           = get_u64(in + 8);

    if (h->version != LEAF_PROTO_VERSION)       return -1;
    if (h->channel_count == 0)                  return -1;
    if (h->channel_count > NODE_MAX_CHANNELS)   return -1;
    return 0;
}

void tg_leaf_nonce_derive(const leaf_header_t *h, uint8_t nonce[LEAF_NONCE_LEN])
{
    put_u32(nonce,     h->key_epoch);
    put_u64(nonce + 4, h->seq);
}

/* ── seal / open ─────────────────────────────────────────────────────────── */

long tg_leaf_frame_seal(const uint8_t key[LEAF_KEY_LEN],
                        const leaf_header_t *h,
                        uint64_t timestamp_ms,
                        const channel_reading_t *readings, size_t count,
                        uint8_t *out, size_t out_cap)
{
    uint8_t payload[LEAF_PAYLOAD_LEN(NODE_MAX_CHANNELS)];
    uint8_t nonce[LEAF_NONCE_LEN];
    size_t  payload_len, frame_len, i;

    if (key == NULL || h == NULL || readings == NULL || out == NULL)
        return LEAF_ERR_PARAM;
    if (count == 0 || count > NODE_MAX_CHANNELS)
        return LEAF_ERR_PARAM;
    if (h->channel_count != (uint8_t)count)
        return LEAF_ERR_FORMAT;

    payload_len = LEAF_PAYLOAD_LEN(count);
    frame_len   = LEAF_FRAME_LEN(count);
    if (out_cap < frame_len)
        return LEAF_ERR_TOO_SMALL;

    /* Header first — it is both the wire prefix and the AAD. */
    tg_leaf_header_serialize(h, out);

    put_u64(payload, timestamp_ms);
    for (i = 0; i < count; i++) {
        uint8_t *slot = payload + 8 + 8 * i;
        slot[0] = (uint8_t)i;                  /* channel index within the frame */
        slot[1] = readings[i].quality;
        slot[2] = 0;
        slot[3] = 0;
        put_f32(slot + 4, readings[i].value);
    }

    tg_leaf_nonce_derive(h, nonce);

    if (aead_encrypt(key, nonce,
                     out, LEAF_HEADER_LEN,
                     payload, payload_len,
                     out + LEAF_HEADER_LEN,
                     out + LEAF_HEADER_LEN + payload_len) != AEAD_OK) {
        memset(payload, 0, sizeof(payload));
        return LEAF_ERR_BACKEND;
    }

    /* The plaintext readings do not need to outlive this call. */
    memset(payload, 0, sizeof(payload));
    return (long)frame_len;
}

long tg_leaf_frame_open(const uint8_t key[LEAF_KEY_LEN],
                        const uint8_t *in, size_t len,
                        leaf_header_t *h,
                        uint64_t *timestamp_ms,
                        channel_reading_t *readings, size_t max_readings)
{
    uint8_t payload[LEAF_PAYLOAD_LEN(NODE_MAX_CHANNELS)];
    uint8_t nonce[LEAF_NONCE_LEN];
    size_t  payload_len, i;
    aead_status_t rc;

    if (key == NULL || in == NULL || h == NULL ||
        timestamp_ms == NULL || readings == NULL)
        return LEAF_ERR_PARAM;
    if (len < LEAF_FRAME_LEN(1))
        return LEAF_ERR_FORMAT;

    if (tg_leaf_header_parse(in, h) != 0)
        return LEAF_ERR_FORMAT;

    /*
     * The declared channel count must account for exactly the bytes present.
     * Checking this before decrypting stops a forged header from steering the
     * payload length, and the count is authenticated anyway because the header
     * is the AAD.
     */
    if (len != LEAF_FRAME_LEN(h->channel_count))
        return LEAF_ERR_FORMAT;
    if (h->channel_count > max_readings)
        return LEAF_ERR_TOO_SMALL;

    payload_len = LEAF_PAYLOAD_LEN(h->channel_count);
    tg_leaf_nonce_derive(h, nonce);

    rc = aead_decrypt(key, nonce,
                      in, LEAF_HEADER_LEN,
                      in + LEAF_HEADER_LEN, payload_len,
                      in + LEAF_HEADER_LEN + payload_len,
                      payload);
    if (rc == AEAD_ERR_AUTH_FAILED) return LEAF_ERR_AUTH;
    if (rc != AEAD_OK)              return LEAF_ERR_BACKEND;

    *timestamp_ms = get_u64(payload);
    for (i = 0; i < h->channel_count; i++) {
        const uint8_t *slot = payload + 8 + 8 * i;
        readings[i].quality = slot[1];
        readings[i].value   = get_f32(slot + 4);
    }

    memset(payload, 0, sizeof(payload));
    return (long)h->channel_count;
}
