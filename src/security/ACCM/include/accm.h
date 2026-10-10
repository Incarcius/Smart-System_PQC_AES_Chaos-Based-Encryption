/*
 * accm.h — ACCM v2: Adaptive Coupled Chaotic Map masking layer.
 *
 * Applied OUTSIDE AES-256-GCM on the gateway -> main-server telemetry link.
 * See include/protocol.h for the frame layout.
 *
 *
 * What changed from v1 (temp_codes/Chaos/Chaos/chaos_custom.C)
 * ===========================================================
 *
 * 1. Full 256-bit key dependence.
 *    v1 fed the map from session_key[0..5] (Lorenz seed; bytes 6-7 were
 *    computed and then discarded) plus session_key[8] and [9] (the two rate
 *    parameters). Bytes 10..31 were never read. That is 64 bits of secret
 *    entropy in the entire masking layer -- brute-forceable, and the first
 *    thing a reviewer would find.
 *
 *    v2 derives every map parameter with KMACXOF256 keyed on the whole
 *    32-byte session key, so all 256 bits are in play.
 *
 * 2. Exact fixed-point arithmetic.
 *    v1 used IEEE-754 double. The gateway is C on ARM and the server is
 *    CPython on x86-64; a chaotic map amplifies a one-ULP difference
 *    exponentially, so any divergence in FMA contraction, x87 excess
 *    precision, or -ffast-math would desynchronise the keystream within a few
 *    dozen iterations and silently corrupt telemetry. v2 is integer-only
 *    (Q32 for the logistic pair, Q16 for Lorenz), so sender and receiver are
 *    bit-identical by construction, not by compiler-flag discipline.
 *
 * 3. Posture instead of an implicit boolean.
 *    Epsilon is selected by the authenticated `posture` field in the frame
 *    header, so the two ends cannot disagree about which attractor is live.
 *
 *
 * Security claim (deliberately modest)
 * ====================================
 * The mask is a key-derived XOR keystream applied over an already-complete
 * AES-256-GCM ciphertext. XORing a ciphertext with any independently keyed
 * stream cannot reduce its security, so the floor of this link is exactly
 * "AES-256-GCM", whatever the chaotic map does. ACCM's contribution is
 * traffic-shape obfuscation and an attacker-visible-but-unforgeable state
 * change -- it is defence in depth, and the paper should not claim the chaos
 * itself carries the confidentiality guarantee.
 *
 * The parameters are unpredictable because KMACXOF256 makes them so. The
 * Lorenz stage is in the chain but cannot weaken it: its output is folded
 * back through a second KMACXOF256 call, so the final parameters are
 * 256-bit-strong even if the fixed-point Lorenz orbit were to degenerate.
 *
 *
 * Note on cycle length
 * ====================
 * A fixed-point map is a finite state machine, so the Q32 pair has an
 * eventual cycle (expected order 2^32 by the birthday bound). This does not
 * matter here: the stream is re-derived per frame from (header || prev_tail),
 * and a frame is at most a few kilobytes. Do not reuse one context to
 * generate a long stream.
 */
#ifndef ACCM_H
#define ACCM_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#define ACCM_KEY_LEN   32
#define ACCM_TAIL_LEN  TG_TAIL_LEN

typedef struct {
    const uint8_t *session_key;              /* ACCM_KEY_LEN bytes          */
    tg_header_t    header;                   /* authenticated frame header  */
    uint8_t        prev_tail[ACCM_TAIL_LEN]; /* last 8 masked bytes, or 0s  */
} accm_ctx_t;

/*
 * Initialise a context. `prev_tail` may be NULL for the first frame of an
 * epoch, which zero-fills it. The chaining makes each frame's keystream
 * depend on the previous frame, so a receiver that misses a frame cannot
 * unmask the next one -- acceptable on the TCP link this runs over, but it
 * must be dropped if the transport ever becomes lossy.
 */
void accm_init(accm_ctx_t *ctx,
               const uint8_t session_key[ACCM_KEY_LEN],
               const tg_header_t *header,
               const uint8_t prev_tail[ACCM_TAIL_LEN]);

/* Generate `len` keystream bytes for this context. */
void accm_generate_stream(const accm_ctx_t *ctx, uint8_t *stream, size_t len);

/* XOR mask. Self-inverse: accm_unmask is the same operation. */
void accm_mask(const accm_ctx_t *ctx,
               const uint8_t *in, uint8_t *out, size_t len);
void accm_unmask(const accm_ctx_t *ctx,
                 const uint8_t *in, uint8_t *out, size_t len);

/*
 * Roll the chaining state forward: copies the last ACCM_TAIL_LEN bytes of the
 * masked frame into ctx->prev_tail. Call on both ends after each frame. If
 * the frame is shorter than ACCM_TAIL_LEN it is left-padded with zeros.
 */
void accm_chain_update(accm_ctx_t *ctx, const uint8_t *masked, size_t len);

/* Coupling strength for a posture, as Q32. Exposed for tests and analysis. */
uint64_t accm_epsilon_q32(uint8_t posture);

#endif /* ACCM_H */
