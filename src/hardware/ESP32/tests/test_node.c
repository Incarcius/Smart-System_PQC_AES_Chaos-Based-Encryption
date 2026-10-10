/*
 * test_node.c — host tests for the leaf data path.
 *
 * Covers everything between "a sensor produced a number" and "bytes are on the
 * UART", with no board attached:
 *
 *   1. COBS round trip, including the cases that break naive implementations
 *   2. COBS rejects malformed frames rather than reading past the end
 *   3. Channel sampling: scaling, plausibility flags, fault flags
 *   4. Frame seal/open round trip
 *   5. Tamper detection on every part of the frame
 *   6. The full pipeline: sample -> seal -> COBS -> decode -> open
 *
 * Build: tools\build_tests.bat
 */
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "channel.h"
#include "cobs.h"
#include "node_frame.h"
#include "aead_iface.h"
#include "node_session.h"
#include "node_storage.h"
#include "hal_port.h"

void sensor_hal_host_inject_fault(int channel_id, int count);
void sensor_hal_host_set_tick(uint64_t tick);
void sensor_hal_host_tick(void);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                           \
    ++g_checks;                                         \
    if (!(cond)) {                                      \
        ++g_failures;                                   \
        printf("  [FAIL] %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__);                            \
        printf("\n");                                   \
    }                                                   \
} while (0)

static const uint8_t KEY[LEAF_KEY_LEN] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78, 0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0
};

/* ── COBS ────────────────────────────────────────────────────────────────── */

static void cobs_roundtrip(const char *label, const uint8_t *src, size_t len)
{
    uint8_t enc[COBS_ENCODED_MAX(600) + 1];
    uint8_t dec[600];
    size_t  enc_len, i;
    long    dec_len;
    int     has_zero = 0;

    enc_len = cobs_encode(src, len, enc);
    CHECK(enc_len <= COBS_ENCODED_MAX(len),
          "%s: encoded %zu exceeds bound %u", label, enc_len,
          (unsigned)COBS_ENCODED_MAX(len));

    /* The whole point: no zero byte may survive encoding, because 0x00 is the
     * frame delimiter. */
    for (i = 0; i < enc_len; i++) if (enc[i] == 0) has_zero = 1;
    CHECK(!has_zero, "%s: encoded output contains a zero byte", label);

    dec_len = cobs_decode(enc, enc_len, dec);
    CHECK(dec_len == (long)len, "%s: decoded length %ld != %zu", label, dec_len, len);
    if (dec_len == (long)len) {
        CHECK(memcmp(dec, src, len) == 0, "%s: round trip mismatch", label);
    }
}

static void test_cobs(void)
{
    uint8_t buf[600];
    size_t i;

    printf("== COBS framing ==\n");

    cobs_roundtrip("single non-zero", (const uint8_t *)"A", 1);

    /* A lone zero: the classic off-by-one. */
    buf[0] = 0;
    cobs_roundtrip("single zero", buf, 1);

    memset(buf, 0, 32);
    cobs_roundtrip("all zeros (32)", buf, 32);

    for (i = 0; i < 32; i++) buf[i] = (uint8_t)(i + 1);
    cobs_roundtrip("no zeros (32)", buf, 32);

    /* Runs of exactly 253/254/255 non-zero bytes straddle the 0xFF code
     * boundary, where encoders habitually go wrong. */
    for (i = 0; i < 600; i++) buf[i] = (uint8_t)((i % 255) + 1);
    cobs_roundtrip("253 non-zero", buf, 253);
    cobs_roundtrip("254 non-zero", buf, 254);
    cobs_roundtrip("255 non-zero", buf, 255);
    cobs_roundtrip("600 non-zero", buf, 600);

    /* Zeros at the boundaries. */
    memset(buf, 1, 300);
    buf[0] = 0; buf[299] = 0;
    cobs_roundtrip("leading+trailing zero", buf, 300);

    for (i = 0; i < 300; i++) buf[i] = (uint8_t)(i % 2);
    cobs_roundtrip("alternating zero", buf, 300);

    /* A realistic frame: mostly ciphertext, so roughly 1 byte in 256 is zero. */
    for (i = 0; i < 80; i++) buf[i] = (uint8_t)((i * 37) & 0xFF);
    cobs_roundtrip("80-byte frame", buf, 80);
}

static void test_cobs_malformed(void)
{
    uint8_t dec[64];
    uint8_t bad[8];

    printf("== COBS rejects malformed frames ==\n");

    /* A zero code byte cannot occur in a well-formed frame. */
    bad[0] = 0; bad[1] = 1;
    CHECK(cobs_decode(bad, 2, dec) == -1, "zero code byte must be rejected");

    /* A code that runs past the end of the input = truncated frame. */
    bad[0] = 8; bad[1] = 1; bad[2] = 2;
    CHECK(cobs_decode(bad, 3, dec) == -1, "overrunning code must be rejected");
}

/* ── channel sampling ────────────────────────────────────────────────────── */

static void test_channel_sampling(void)
{
    channel_reading_t readings[NODE_MAX_CHANNELS];
    size_t i;

    printf("== channel sampling and quality flags ==\n");

    sensor_hal_init(NODE_CHANNELS, NODE_CHANNEL_COUNT);
    sensor_hal_host_set_tick(0);

    CHECK(NODE_CHANNEL_COUNT == 5, "prototype table should have 5 channels, has %zu",
          NODE_CHANNEL_COUNT);

    channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, readings);

    for (i = 0; i < NODE_CHANNEL_COUNT; i++) {
        CHECK(readings[i].quality == CH_QUALITY_GOOD,
              "channel %zu (%s) should be GOOD, got 0x%02x",
              i, NODE_CHANNELS[i].name, readings[i].quality);
    }

    /* Scaling must land in engineering units, not raw counts. */
    CHECK(readings[0].value > 200.0f && readings[0].value < 250.0f,
          "voltage %.2f outside the expected band", readings[0].value);
    CHECK(readings[1].value > -20.0f && readings[1].value < 20.0f,
          "current %.2f outside the expected band", readings[1].value);
    CHECK(readings[2].value > 30.0f && readings[2].value < 40.0f,
          "temperature %.2f outside the expected band", readings[2].value);
    CHECK(readings[4].value == 0.0f || readings[4].value == 1.0f,
          "relay should be 0 or 1, got %.2f", readings[4].value);

    /* A failing sensor must produce a FLAGGED sample, never a gap — a gap is
     * indistinguishable from a dropped frame further up the chain. */
    sensor_hal_host_inject_fault(1, 1);
    channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, readings);
    CHECK(readings[1].quality != CH_QUALITY_GOOD,
          "faulted channel must be flagged, got 0x%02x", readings[1].quality);
    CHECK(readings[0].quality == CH_QUALITY_GOOD,
          "one fault must not contaminate other channels");
}

/* ── frame seal / open ───────────────────────────────────────────────────── */

static void make_readings(channel_reading_t *r, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        r[i].value   = 100.0f + (float)i * 1.5f;
        r[i].quality = (i == 2) ? CH_QUALITY_RANGE : CH_QUALITY_GOOD;
    }
}

static void test_frame_roundtrip(void)
{
    uint8_t frame[LEAF_FRAME_MAX];
    channel_reading_t in[5], out[NODE_MAX_CHANNELS];
    leaf_header_t h = { LEAF_PROTO_VERSION, 5, 0x1234, 7, 424242 };
    leaf_header_t got;
    uint64_t ts_in = 1757664000123ULL, ts_out = 0;
    long len, n;
    size_t i;

    printf("== frame seal / open round trip ==\n");
    make_readings(in, 5);

    len = tg_leaf_frame_seal(KEY, &h, ts_in, in, 5, frame, sizeof(frame));
    CHECK(len == (long)LEAF_FRAME_LEN(5),
          "sealed length %ld != %u", len, (unsigned)LEAF_FRAME_LEN(5));
    CHECK(len == 80, "5-channel frame should be 80 bytes, got %ld", len);

    n = tg_leaf_frame_open(KEY, frame, (size_t)len, &got, &ts_out, out,
                           NODE_MAX_CHANNELS);
    CHECK(n == 5, "opened channel count %ld != 5", n);
    CHECK(ts_out == ts_in, "timestamp mismatch");
    CHECK(got.endpoint_id == h.endpoint_id, "endpoint_id mismatch");
    CHECK(got.key_epoch == h.key_epoch, "key_epoch mismatch");
    CHECK(got.seq == h.seq, "seq mismatch");

    for (i = 0; i < 5; i++) {
        CHECK(fabsf(out[i].value - in[i].value) < 1e-6f,
              "channel %zu value %.6f != %.6f", i, out[i].value, in[i].value);
        CHECK(out[i].quality == in[i].quality, "channel %zu quality mismatch", i);
    }

    /* The nonce must be exactly the header fields, matching the uplink. */
    {
        uint8_t nonce[LEAF_NONCE_LEN];
        tg_leaf_nonce_derive(&h, nonce);
        CHECK(nonce[3] == 7, "nonce should carry key_epoch in bytes 0..3");
        CHECK(nonce[11] == (uint8_t)(424242ULL & 0xFF),
              "nonce should carry seq in bytes 4..11");
    }
}

static void test_tamper(void)
{
    uint8_t frame[LEAF_FRAME_MAX];
    channel_reading_t in[5], out[NODE_MAX_CHANNELS];
    leaf_header_t h = { LEAF_PROTO_VERSION, 5, 0x1234, 7, 99 };
    leaf_header_t got;
    uint64_t ts = 1757664000000ULL, ts_out;
    long len;

    printf("== tamper detection ==\n");
    make_readings(in, 5);
    len = tg_leaf_frame_seal(KEY, &h, ts, in, 5, frame, sizeof(frame));

    struct { const char *what; size_t off; } spots[] = {
        { "endpoint_id (header/AAD)", 2  },
        { "key_epoch (header/AAD)",   6  },
        { "seq (header/AAD)",         14 },
        { "ciphertext",               20 },
        { "tag",                      70 },
    };

    for (size_t s = 0; s < sizeof(spots) / sizeof(spots[0]); s++) {
        uint8_t copy[LEAF_FRAME_MAX];
        memcpy(copy, frame, (size_t)len);
        copy[spots[s].off] ^= 0x01;

        long rc = tg_leaf_frame_open(KEY, copy, (size_t)len, &got, &ts_out, out,
                                     NODE_MAX_CHANNELS);
        CHECK(rc < 0, "flipping %s must be rejected, got %ld", spots[s].what, rc);
    }

    /* A wrong key must fail too, not merely produce garbage. */
    {
        uint8_t wrong[LEAF_KEY_LEN];
        memcpy(wrong, KEY, sizeof(wrong));
        wrong[0] ^= 0x01;
        CHECK(tg_leaf_frame_open(wrong, frame, (size_t)len, &got, &ts_out, out,
                                 NODE_MAX_CHANNELS) == LEAF_ERR_AUTH,
              "wrong key must fail authentication");
    }
}

/* ── full pipeline ───────────────────────────────────────────────────────── */

static void test_pipeline(void)
{
    uint8_t frame[LEAF_FRAME_MAX];
    uint8_t wire[COBS_ENCODED_MAX(LEAF_FRAME_MAX) + 1];
    uint8_t rx[LEAF_FRAME_MAX];
    channel_reading_t sampled[NODE_MAX_CHANNELS], out[NODE_MAX_CHANNELS];
    leaf_header_t h = { LEAF_PROTO_VERSION, 0, 0x0001, 1, 0 };
    leaf_header_t got;
    uint64_t ts_out;
    int i;

    printf("== full pipeline: sample -> seal -> COBS -> decode -> open ==\n");

    sensor_hal_init(NODE_CHANNELS, NODE_CHANNEL_COUNT);
    sensor_hal_host_set_tick(0);
    h.channel_count = (uint8_t)NODE_CHANNEL_COUNT;

    for (i = 0; i < 100; i++) {
        long flen, wlen, dlen, n;

        channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, sampled);

        h.seq = (uint64_t)i;
        flen = tg_leaf_frame_seal(KEY, &h, 1757664000000ULL + (uint64_t)i * 100,
                                  sampled, NODE_CHANNEL_COUNT, frame, sizeof(frame));
        if (flen < 0) { CHECK(0, "seal failed at %d: %ld", i, flen); return; }

        wlen = (long)cobs_encode(frame, (size_t)flen, wire);
        wire[wlen] = 0x00;                       /* delimiter */

        dlen = cobs_decode(wire, (size_t)wlen, rx);
        if (dlen != flen) { CHECK(0, "COBS mismatch at %d", i); return; }

        n = tg_leaf_frame_open(KEY, rx, (size_t)dlen, &got, &ts_out, out,
                               NODE_MAX_CHANNELS);
        if (n != (long)NODE_CHANNEL_COUNT) {
            CHECK(0, "open failed at %d: %ld", i, n);
            return;
        }

        sensor_hal_host_tick();
    }

    CHECK(1, "unused");
    printf("    100 frames sampled, sealed, framed, decoded and opened cleanly\n");
    printf("    wire size: %u bytes/frame + 1 delimiter, %u B/s at 10 Hz\n",
           (unsigned)COBS_ENCODED_MAX(LEAF_FRAME_LEN(5)),
           (unsigned)((COBS_ENCODED_MAX(LEAF_FRAME_LEN(5)) + 1) * 10));
}

/* ── persisted nonce guard ───────────────────────────────────────────────── */

static void test_nonce_guard(void)
{
    node_nonce_guard_t g;
    uint64_t seq;
    uint32_t first_epoch, second_epoch;

    printf("== persisted nonce guard ==\n");

    node_storage_host_reset("test_node_storage.txt");
    node_storage_init();

    /* First ever boot. */
    CHECK(node_nonce_boot(&g) == NODE_SESSION_OK, "first boot");
    first_epoch = g.key_epoch;
    CHECK(first_epoch == 1, "first boot epoch should be 1, got %u", first_epoch);
    CHECK(node_nonce_next(&g, &seq) == NODE_SESSION_OK && seq == 0, "first seq is 0");
    CHECK(node_nonce_next(&g, &seq) == NODE_SESSION_OK && seq == 1, "seq increments");

    /*
     * Simulate a reboot. This is the case that matters: seq restarts at 0, so
     * if the epoch also restarted the node would re-emit nonces it has already
     * used. The epoch MUST advance.
     */
    node_storage_deinit();
    node_storage_init();
    CHECK(node_nonce_boot(&g) == NODE_SESSION_OK, "reboot");
    second_epoch = g.key_epoch;
    CHECK(second_epoch > first_epoch,
          "epoch must advance across reboot: %u -> %u", first_epoch, second_epoch);
    CHECK(g.next_seq == 0, "seq restarts at 0 after reboot");

    /* Exhaustion must refuse rather than wrap. */
    g.next_seq = NODE_SEQ_MAX - 1;
    CHECK(node_nonce_next(&g, &seq) == NODE_SESSION_OK, "last seq is issued");
    CHECK(node_nonce_next(&g, &seq) == NODE_SESSION_EXHAUSTED,
          "exhausted epoch must refuse");

    /* Rekey gives a fresh epoch and a fresh seq space. */
    CHECK(node_nonce_rekey(&g) == NODE_SESSION_OK, "rekey");
    CHECK(g.key_epoch > second_epoch, "rekey advances the epoch");
    CHECK(g.next_seq == 0 && !g.exhausted, "rekey resets the seq space");

    node_storage_deinit();
}

/* ── handshake ───────────────────────────────────────────────────────────── */

static const uint8_t PSK[NODE_PSK_LEN] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7, 0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7
};

static void test_handshake(void)
{
    node_handshake_ctx_t ctx;
    node_session_t leaf, gw;
    uint8_t hello[NODE_HELLO_LEN], ack[NODE_HELLO_ACK_LEN];
    uint8_t confirm[NODE_CONFIRM_LEN];

    printf("== handshake: PSK + ephemeral X25519 ==\n");

    CHECK(node_handshake_start(&ctx, 0x0007, 3, hello) == NODE_SESSION_OK, "HELLO");
    CHECK(node_handshake_respond(PSK, hello, &gw, ack) == NODE_SESSION_OK, "HELLO_ACK");
    CHECK(node_handshake_finish(&ctx, PSK, ack, &leaf, confirm) == NODE_SESSION_OK,
          "CONFIRM");

    CHECK(memcmp(leaf.session_key, gw.session_key, NODE_SESSION_KEY_LEN) == 0,
          "both sides must derive the same session key");
    CHECK(memcmp(leaf.transcript, gw.transcript, 32) == 0, "transcripts must match");
    CHECK(leaf.endpoint_id == 0x0007 && leaf.key_epoch == 3, "header fields carried");

    CHECK(node_handshake_verify_confirm(&gw, confirm) == NODE_SESSION_OK,
          "gateway must accept the leaf's CONFIRM");

    /* The ephemeral private key must be gone — forward secrecy depends on it. */
    {
        uint8_t zero[NODE_PUBKEY_LEN] = {0};
        CHECK(memcmp(ctx.leaf_sk, zero, sizeof(zero)) == 0,
              "ephemeral private key must be wiped after finish");
    }

    /* A second handshake must produce a different key: the nonces make each
     * transcript unique, so a replayed HELLO cannot resurrect an old key. */
    {
        node_handshake_ctx_t ctx2;
        node_session_t leaf2, gw2;
        uint8_t hello2[NODE_HELLO_LEN], ack2[NODE_HELLO_ACK_LEN];
        uint8_t confirm2[NODE_CONFIRM_LEN];

        node_handshake_start(&ctx2, 0x0007, 3, hello2);
        node_handshake_respond(PSK, hello2, &gw2, ack2);
        node_handshake_finish(&ctx2, PSK, ack2, &leaf2, confirm2);

        CHECK(memcmp(leaf.session_key, leaf2.session_key, NODE_SESSION_KEY_LEN) != 0,
              "same endpoint and epoch must still give a fresh key");
    }
}

static void test_handshake_attacks(void)
{
    node_handshake_ctx_t ctx;
    node_session_t leaf, gw;
    uint8_t hello[NODE_HELLO_LEN], ack[NODE_HELLO_ACK_LEN];
    uint8_t confirm[NODE_CONFIRM_LEN];

    printf("== handshake attack resistance ==\n");

    /*
     * MITM. The attacker sits between leaf and gateway and substitutes its own
     * ephemeral keypair, which raw ECDHE cannot stop. It does not hold the
     * device PSK, so the key it derives differs from the leaf's -- and the
     * CONFIRM tag is what makes that visible immediately rather than at the
     * first telemetry frame.
     */
    {
        static const uint8_t WRONG_PSK[NODE_PSK_LEN] = {0x11};
        node_session_t attacker;
        uint8_t atk_ack[NODE_HELLO_ACK_LEN];

        node_handshake_start(&ctx, 0x0007, 1, hello);

        /* Attacker answers with its own keypair, but no PSK. */
        CHECK(node_handshake_respond(WRONG_PSK, hello, &attacker, atk_ack)
              == NODE_SESSION_OK, "attacker can still complete the DH");

        node_handshake_finish(&ctx, PSK, atk_ack, &leaf, confirm);

        CHECK(memcmp(leaf.session_key, attacker.session_key, NODE_SESSION_KEY_LEN) != 0,
              "MITM without the PSK must not reach the leaf's key");
        CHECK(node_handshake_verify_confirm(&attacker, confirm) == NODE_SESSION_ERR_CONFIRM,
              "attacker must fail to verify the leaf's CONFIRM");
    }

    /* A tampered HELLO_ACK changes the transcript, so the keys diverge. */
    {
        node_handshake_ctx_t c;
        uint8_t bad_ack[NODE_HELLO_ACK_LEN];

        node_handshake_start(&c, 0x0007, 1, hello);
        node_handshake_respond(PSK, hello, &gw, ack);
        memcpy(bad_ack, ack, sizeof(bad_ack));
        bad_ack[45] ^= 0x01;                 /* flip a gateway nonce byte */

        node_handshake_finish(&c, PSK, bad_ack, &leaf, confirm);
        CHECK(node_handshake_verify_confirm(&gw, confirm) == NODE_SESSION_ERR_CONFIRM,
              "tampered HELLO_ACK must break confirmation");
    }

    /* An endpoint id that does not match what we sent = wrong conversation. */
    {
        node_handshake_ctx_t c;
        uint8_t bad_ack[NODE_HELLO_ACK_LEN];

        node_handshake_start(&c, 0x0007, 1, hello);
        node_handshake_respond(PSK, hello, &gw, ack);
        memcpy(bad_ack, ack, sizeof(bad_ack));
        bad_ack[3] ^= 0xFF;

        CHECK(node_handshake_finish(&c, PSK, bad_ack, &leaf, confirm)
              == NODE_SESSION_ERR_PEER, "mismatched endpoint id must be rejected");
    }

    /* Low-order gateway public key: the DH output is all-zero and carries no
     * secret, so it must be refused rather than fed to the KDF. */
    {
        node_handshake_ctx_t c;
        uint8_t bad_ack[NODE_HELLO_ACK_LEN];

        node_handshake_start(&c, 0x0007, 1, hello);
        node_handshake_respond(PSK, hello, &gw, ack);
        memcpy(bad_ack, ack, sizeof(bad_ack));
        memset(bad_ack + 8, 0, NODE_PUBKEY_LEN);   /* the order-1 point */

        CHECK(node_handshake_finish(&c, PSK, bad_ack, &leaf, confirm)
              == NODE_SESSION_ERR_PEER, "low-order peer key must be rejected");
    }

    /* Wrong message type. */
    {
        node_handshake_ctx_t c;
        uint8_t bad_ack[NODE_HELLO_ACK_LEN];

        node_handshake_start(&c, 0x0007, 1, hello);
        node_handshake_respond(PSK, hello, &gw, ack);
        memcpy(bad_ack, ack, sizeof(bad_ack));
        bad_ack[1] = NODE_MSG_HELLO;

        CHECK(node_handshake_finish(&c, PSK, bad_ack, &leaf, confirm)
              == NODE_SESSION_ERR_FORMAT, "wrong message type must be rejected");
    }
}

/* The session key really does open the telemetry frames it is meant to. */
static void test_session_to_telemetry(void)
{
    node_handshake_ctx_t ctx;
    node_session_t leaf, gw;
    node_nonce_guard_t guard;
    uint8_t hello[NODE_HELLO_LEN], ack[NODE_HELLO_ACK_LEN];
    uint8_t confirm[NODE_CONFIRM_LEN];
    uint8_t frame[LEAF_FRAME_MAX];
    channel_reading_t sampled[NODE_MAX_CHANNELS], out[NODE_MAX_CHANNELS];
    leaf_header_t h, got;
    uint64_t ts_out, seq;
    long flen, n;

    printf("== handshake key opens real telemetry frames ==\n");

    node_storage_host_reset("test_node_storage2.txt");
    node_storage_init();
    node_nonce_boot(&guard);

    node_handshake_start(&ctx, 0x0007, guard.key_epoch, hello);
    node_handshake_respond(PSK, hello, &gw, ack);
    node_handshake_finish(&ctx, PSK, ack, &leaf, confirm);

    sensor_hal_init(NODE_CHANNELS, NODE_CHANNEL_COUNT);
    channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, sampled);

    node_nonce_next(&guard, &seq);
    h.version       = LEAF_PROTO_VERSION;
    h.channel_count = (uint8_t)NODE_CHANNEL_COUNT;
    h.endpoint_id   = leaf.endpoint_id;
    h.key_epoch     = guard.key_epoch;
    h.seq           = seq;

    flen = tg_leaf_frame_seal(leaf.session_key, &h, 1757664000000ULL,
                              sampled, NODE_CHANNEL_COUNT, frame, sizeof(frame));
    CHECK(flen > 0, "seal with the handshake key");

    n = tg_leaf_frame_open(gw.session_key, frame, (size_t)flen, &got, &ts_out,
                           out, NODE_MAX_CHANNELS);
    CHECK(n == (long)NODE_CHANNEL_COUNT,
          "gateway opens the frame with its derived key (got %ld)", n);

    node_session_wipe(&leaf);
    node_session_wipe(&gw);
    node_storage_deinit();
}

/* ── latency ─────────────────────────────────────────────────────────────── */

/*
 * Per-frame cost of the leaf's C data path, against the 100 ms sampling
 * budget. This is the "per-node encryption time" metric from slides 20-23,
 * measured rather than assumed.
 *
 * Numbers here are host numbers. The ESP32 is roughly an order of magnitude
 * slower on software AES and far more than that on X25519, so treat these as
 * a lower bound and re-measure on the board — hal_get_time_us() is already
 * wired for exactly that.
 */
static void bench_leaf_path(void)
{
    channel_reading_t readings[NODE_MAX_CHANNELS];
    uint8_t frame[LEAF_FRAME_MAX];
    uint8_t wire[COBS_ENCODED_MAX(LEAF_FRAME_MAX) + 1];
    leaf_header_t h = { LEAF_PROTO_VERSION, 0, 0x0001, 1, 0 };
    int64_t t0, t1;
    int i;
    const int N = 2000;

    printf("== per-frame latency (host; ESP32 will be slower) ==\n");

    sensor_hal_init(NODE_CHANNELS, NODE_CHANNEL_COUNT);
    h.channel_count = (uint8_t)NODE_CHANNEL_COUNT;

    t0 = hal_get_time_us();
    for (i = 0; i < N; i++) channel_sample_all(NODE_CHANNELS, NODE_CHANNEL_COUNT, readings);
    t1 = hal_get_time_us();
    printf("    sample 5 channels      %8.3f ms\n", (double)(t1 - t0) / N / 1000.0);

    t0 = hal_get_time_us();
    for (i = 0; i < N; i++) {
        h.seq = (uint64_t)i;
        tg_leaf_frame_seal(KEY, &h, 1757664000000ULL, readings,
                           NODE_CHANNEL_COUNT, frame, sizeof(frame));
    }
    t1 = hal_get_time_us();
    printf("    AES-GCM seal (48 B)    %8.3f ms\n", (double)(t1 - t0) / N / 1000.0);

    t0 = hal_get_time_us();
    for (i = 0; i < N; i++) cobs_encode(frame, LEAF_FRAME_LEN(5), wire);
    t1 = hal_get_time_us();
    printf("    COBS encode (80 B)     %8.3f ms\n", (double)(t1 - t0) / N / 1000.0);

    /* Handshake runs once per epoch, not per frame, but it is the single
     * most expensive thing the leaf does and it gates startup. */
    {
        node_handshake_ctx_t ctx;
        node_session_t leaf, gw;
        uint8_t hello[NODE_HELLO_LEN], ack[NODE_HELLO_ACK_LEN];
        uint8_t confirm[NODE_CONFIRM_LEN];
        const int HN = 100;

        t0 = hal_get_time_us();
        for (i = 0; i < HN; i++) {
            node_handshake_start(&ctx, 0x0007, 1, hello);
            node_handshake_respond(PSK, hello, &gw, ack);
            node_handshake_finish(&ctx, PSK, ack, &leaf, confirm);
        }
        t1 = hal_get_time_us();
        printf("    full handshake         %8.3f ms  (once per epoch)\n",
               (double)(t1 - t0) / HN / 1000.0);
    }

    printf("    UART wall time         %8.3f ms  (81 B at 115200 baud)\n",
           81.0 * 10.0 / 115200.0 * 1000.0);
}

int main(void)
{
    printf("=== Leaf node tests ===\n");
    aead_init();

    test_cobs();
    test_cobs_malformed();
    test_channel_sampling();
    test_frame_roundtrip();
    test_tamper();
    test_pipeline();
    test_nonce_guard();
    test_handshake();
    test_handshake_attacks();
    test_session_to_telemetry();
    bench_leaf_path();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
