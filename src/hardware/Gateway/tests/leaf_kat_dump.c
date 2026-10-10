/*
 * leaf_kat_dump.c — emit leaf-link vectors from the C implementation.
 *
 * Paired with test_leaf_link.py. The ESP32 runs this C code and the gateway
 * runs the Python mirror, so any divergence means the gateway cannot decode
 * its own sensors. This diff is the gate.
 *
 * Handshakes use ephemeral keys and so cannot be known-answer tested directly.
 * Instead the deterministic core — derive_session over fixed (hello, ack, dh,
 * psk) — is exercised through node_session_derive_for_test(). The live
 * handshake calls the same path, so pinning this covers it.
 */
#include <stdio.h>
#include <string.h>

#include "channel.h"
#include "cobs.h"
#include "node_frame.h"
#include "node_session.h"
#include "aead_iface.h"

static void put_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    printf("%s ", label);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    uint8_t key[LEAF_KEY_LEN], psk[NODE_PSK_LEN], dh[32];
    uint8_t hello[NODE_HELLO_LEN], ack[NODE_HELLO_ACK_LEN];
    uint8_t buf[1024], enc[1024];
    size_t  i;

    /* The software AEAD backend refuses to encrypt before init, which
     * would silently drop the frame vector from this dump. */
    aead_init();

    for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i * 9 + 4);
    for (i = 0; i < sizeof(psk); i++) psk[i] = (uint8_t)(i * 17 + 3);
    for (i = 0; i < sizeof(dh);  i++) dh[i]  = (uint8_t)(i * 5 + 11);

    /* ── COBS ────────────────────────────────────────────────────────────── */
    {
        static const struct { const char *label; size_t len; int pattern; } cases[] = {
            { "cobs_zero1",   1,   0 },
            { "cobs_zeros32", 32,  0 },
            { "cobs_seq32",   32,  1 },
            { "cobs_alt300",  300, 2 },
            { "cobs_run254",  254, 1 },
            { "cobs_run255",  255, 1 },
            { "cobs_frame80", 80,  3 },
        };
        size_t c;

        for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            size_t n = cases[c].len, out_n;

            for (i = 0; i < n; i++) {
                switch (cases[c].pattern) {
                case 0:  buf[i] = 0; break;
                case 1:  buf[i] = (uint8_t)((i % 255) + 1); break;
                case 2:  buf[i] = (uint8_t)(i % 2); break;
                default: buf[i] = (uint8_t)((i * 37) & 0xFF); break;
                }
            }
            out_n = cobs_encode(buf, n, enc);
            put_hex(cases[c].label, enc, out_n);
        }
    }

    /* ── header and nonce ────────────────────────────────────────────────── */
    {
        leaf_header_t h = { LEAF_PROTO_VERSION, 5, 0xBEEF, 0x01020304, 0x0A0B0C0D0E0FULL };
        uint8_t hdr[LEAF_HEADER_LEN], nonce[LEAF_NONCE_LEN];

        tg_leaf_header_serialize(&h, hdr);
        put_hex("leaf_header", hdr, LEAF_HEADER_LEN);
        tg_leaf_nonce_derive(&h, nonce);
        put_hex("leaf_nonce", nonce, LEAF_NONCE_LEN);
    }

    /* ── sealed telemetry frame ──────────────────────────────────────────── */
    {
        leaf_header_t h = { LEAF_PROTO_VERSION, 5, 0x0007, 11, 4242 };
        channel_reading_t r[5];
        long len;

        for (i = 0; i < 5; i++) {
            r[i].value   = 100.0f + (float)i * 12.25f;
            r[i].quality = (i == 3) ? CH_QUALITY_RANGE : CH_QUALITY_GOOD;
        }
        len = tg_leaf_frame_seal(key, &h, 1757664000123ULL, r, 5, buf, sizeof(buf));
        if (len > 0) put_hex("leaf_frame", buf, (size_t)len);
    }

    /* ── deterministic session derivation ────────────────────────────────── */
    {
        node_session_t s;
        uint8_t tag[16];

        memset(hello, 0, sizeof(hello));
        hello[0] = 0x01;
        hello[1] = NODE_MSG_HELLO;
        hello[2] = 0x00; hello[3] = 0x07;              /* endpoint 7 */
        hello[4] = 0; hello[5] = 0; hello[6] = 0; hello[7] = 11;  /* epoch 11 */
        for (i = 0; i < 32; i++) hello[8 + i]  = (uint8_t)(i * 3 + 1);
        for (i = 0; i < 32; i++) hello[40 + i] = (uint8_t)(i * 7 + 2);

        memset(ack, 0, sizeof(ack));
        ack[0] = 0x01;
        ack[1] = NODE_MSG_HELLO_ACK;
        ack[2] = 0x00; ack[3] = 0x07;
        for (i = 0; i < 32; i++) ack[8 + i]  = (uint8_t)(i * 11 + 5);
        for (i = 0; i < 32; i++) ack[40 + i] = (uint8_t)(i * 13 + 6);

        if (node_session_derive_for_test(hello, ack, dh, psk, &s) == NODE_SESSION_OK) {
            put_hex("hs_transcript", s.transcript, 32);
            put_hex("hs_session_key", s.session_key, NODE_SESSION_KEY_LEN);
            node_session_confirm_tag_for_test(&s, tag);
            put_hex("hs_confirm_tag", tag, 16);
        }
    }

    return 0;
}
