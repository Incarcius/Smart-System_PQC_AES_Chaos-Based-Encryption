/*
 * accm_stream_gen.c — write a large ACCM v2 keystream corpus to a file.
 *
 * Emits the stream the way the link actually uses it: re-derived per frame
 * from an advancing (seq, timestamp, prev_tail), not one long run of a single
 * map. Testing a single long orbit would flatter the design; this measures
 * what an attacker would actually observe on the wire.
 *
 * Usage:  accm_stream_gen <out-file> <total-bytes> [frame-bytes] [posture]
 *
 * Feed the output to the statistics script alongside it, or to NIST STS:
 *   assess 1000000  ->  input file, 10 sequences, all tests
 *
 * Build (from repo root, MSVC shell):
 *   cl /nologo /W3 /O2 /I include /I src\security\ACCM\include ^
 *      /I temp_codes\RXCR-KMAC-KDF\c\include ^
 *      src\protocol.c src\security\ACCM\src\accm.c ^
 *      temp_codes\RXCR-KMAC-KDF\c\src\kmac.c ^
 *      src\security\ACCM\tests\accm_stream_gen.c /Fe:accm_stream_gen.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "accm.h"
#include "protocol.h"

int main(int argc, char **argv)
{
    const char *path;
    size_t      total, frame_len, written = 0;
    uint8_t     posture = TG_POSTURE_NORMAL;
    uint8_t     key[32], tail[TG_TAIL_LEN], *buf;
    accm_ctx_t  ctx;
    tg_header_t h;
    FILE       *f;
    uint64_t    seq = 0;
    size_t      i;

    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <out-file> <total-bytes> [frame-bytes] [posture]\n",
                argv[0]);
        return 2;
    }

    path      = argv[1];
    total     = (size_t)strtoull(argv[2], NULL, 10);
    frame_len = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : 64;
    if (argc > 4) posture = (uint8_t)atoi(argv[4]);

    if (total == 0 || frame_len == 0) {
        fprintf(stderr, "total-bytes and frame-bytes must be non-zero\n");
        return 2;
    }

    buf = (uint8_t *)malloc(frame_len);
    if (buf == NULL) { fprintf(stderr, "out of memory\n"); return 1; }

    /* Fixed session key — we are measuring the stream, not key generation. */
    for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i * 37 + 11);
    memset(tail, 0, sizeof(tail));

    f = fopen(path, "wb");
    if (f == NULL) { fprintf(stderr, "cannot open %s\n", path); free(buf); return 1; }

    h.version      = TG_PROTO_VERSION;
    h.posture      = posture;
    h.node_id      = 1;
    h.key_epoch    = 1;
    h.timestamp_ms = 1757664000000ULL;

    while (written < total) {
        size_t n = (total - written) < frame_len ? (total - written) : frame_len;

        h.seq           = seq;
        h.timestamp_ms += 100;            /* 10 Hz telemetry */

        accm_init(&ctx, key, &h, tail);
        accm_generate_stream(&ctx, buf, n);

        if (fwrite(buf, 1, n, f) != n) {
            fprintf(stderr, "short write\n");
            fclose(f); free(buf); return 1;
        }

        /* Chain exactly as the live path does. */
        accm_chain_update(&ctx, buf, n);
        memcpy(tail, ctx.prev_tail, TG_TAIL_LEN);

        written += n;
        seq++;
    }

    fclose(f);
    free(buf);
    fprintf(stderr, "wrote %zu bytes to %s (%llu frames of %zu, posture=%u)\n",
            written, path, (unsigned long long)seq, frame_len, posture);
    return 0;
}
