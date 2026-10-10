/*
 * accm_kat_dump.c — emit ACCM v2 keystreams and header encodings as hex.
 *
 * Paired with test_accm_kat.py. The gateway masks in C and the server unmasks
 * in Python, so this diff is the gate that keeps the link working: if the two
 * implementations ever diverge by a single byte, telemetry decodes to noise.
 *
 * Build (from repo root, MSVC shell):
 *   cl /nologo /W3 /O2 /I include /I src\security\ACCM\include ^
 *      /I temp_codes\RXCR-KMAC-KDF\c\include ^
 *      src\protocol.c src\security\ACCM\src\accm.c ^
 *      temp_codes\RXCR-KMAC-KDF\c\src\kmac.c ^
 *      src\security\ACCM\tests\accm_kat_dump.c /Fe:accm_kat.exe
 */
#include <stdio.h>
#include <string.h>
#include "accm.h"
#include "protocol.h"

static void put_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    printf("%s ", label);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static void dump_case(const char *label,
                      const uint8_t key[32],
                      uint8_t posture,
                      uint16_t node_id,
                      uint32_t key_epoch,
                      uint64_t seq,
                      uint64_t ts,
                      const uint8_t tail[8],
                      size_t stream_len)
{
    accm_ctx_t  ctx;
    tg_header_t h;
    uint8_t     stream[512];

    h.version      = TG_PROTO_VERSION;
    h.posture      = posture;
    h.node_id      = node_id;
    h.key_epoch    = key_epoch;
    h.seq          = seq;
    h.timestamp_ms = ts;

    accm_init(&ctx, key, &h, tail);
    accm_generate_stream(&ctx, stream, stream_len);
    put_hex(label, stream, stream_len);
}

int main(void)
{
    uint8_t key_a[32], key_b[32], tail[8], hdr[TG_HEADER_LEN];
    uint8_t nonce[TG_NONCE_LEN];
    tg_header_t h;
    size_t i;

    for (i = 0; i < 32; i++) key_a[i] = (uint8_t)(i * 11 + 3);
    for (i = 0; i < 32; i++) key_b[i] = (uint8_t)(i * 11 + 3);
    /* key_b differs only in byte 31 — v1 ignored bytes 10..31 entirely, so
     * this pair produced an IDENTICAL keystream under the old derivation. */
    key_b[31] ^= 0x01;

    for (i = 0; i < 8; i++) tail[i] = (uint8_t)(0xA0 + i);

    /* Header serialisation and nonce derivation */
    h.version      = TG_PROTO_VERSION;
    h.posture      = TG_POSTURE_SUSPICIOUS;
    h.node_id      = 0x1234;
    h.key_epoch    = 0xDEADBEEFu;
    h.seq          = 0x0102030405060708ULL;
    h.timestamp_ms = 1757664000000ULL;
    tg_header_serialize(&h, hdr);
    put_hex("header", hdr, TG_HEADER_LEN);
    tg_nonce_derive(&h, nonce);
    put_hex("nonce", nonce, TG_NONCE_LEN);

    /* Keystreams across every posture */
    dump_case("ks_normal",     key_a, TG_POSTURE_NORMAL,     1, 7, 42, 1757664000000ULL, tail, 64);
    dump_case("ks_suspicious", key_a, TG_POSTURE_SUSPICIOUS, 1, 7, 42, 1757664000000ULL, tail, 64);
    dump_case("ks_anomaly",    key_a, TG_POSTURE_ANOMALY,    1, 7, 42, 1757664000000ULL, tail, 64);

    /* Sensitivity to the high key bytes that v1 discarded */
    dump_case("ks_keyb",       key_b, TG_POSTURE_NORMAL,     1, 7, 42, 1757664000000ULL, tail, 64);

    /* Sensitivity to each context field */
    dump_case("ks_seq43",      key_a, TG_POSTURE_NORMAL,     1, 7, 43, 1757664000000ULL, tail, 64);
    dump_case("ks_epoch8",     key_a, TG_POSTURE_NORMAL,     1, 8, 42, 1757664000000ULL, tail, 64);
    dump_case("ks_node2",      key_a, TG_POSTURE_NORMAL,     2, 7, 42, 1757664000000ULL, tail, 64);
    dump_case("ks_ts",         key_a, TG_POSTURE_NORMAL,     1, 7, 42, 1757664000100ULL, tail, 64);
    dump_case("ks_zerotail",   key_a, TG_POSTURE_NORMAL,     1, 7, 42, 1757664000000ULL, NULL, 64);

    /* A long stream, to exercise many map iterations */
    dump_case("ks_long",       key_a, TG_POSTURE_ANOMALY,    9, 3, 1, 1700000000000ULL, tail, 512);

    return 0;
}
