/*
 * aead_iface.h — the AEAD contract every backend implements.
 *
 * One header, several interchangeable implementations: portable software
 * (tiny-AES), ESP32 via mbedTLS, ESP32 via direct register access. Callers
 * include only this file and never learn which one they linked against;
 * aead_backend_select.h decides at build time.
 *
 * Algorithm: AES-256-GCM, 96-bit nonce, 128-bit tag. Those three parameters
 * are fixed, not configurable — see the note on nonce length below, which is
 * the one that will bite you if it is ever "improved".
 *
 *
 * Nonce length is 96 bits and cannot be changed
 * =============================================
 * AEAD_NONCE_LEN is 12 bytes, and this is load-bearing in a way that is not
 * obvious from the constant.
 *
 * NIST SP 800-38D §7.1 defines the GCM pre-counter block J0 by cases:
 *
 *     |IV| == 96 bits :  J0 = IV || 0^31 || 1          (cheap, one memcpy)
 *     |IV| != 96 bits :  J0 = GHASH(H, {}, IV)         (a whole GHASH pass)
 *
 * gcm_core.c implements ONLY the first case. If someone edits
 * AEAD_NONCE_LEN to 16 to "get more nonce space", the code keeps compiling
 * and keeps round-tripping with itself, but silently stops being GCM: every
 * ciphertext and tag becomes non-standard, and interop with the Python
 * server (which uses a conforming implementation) breaks. A static assertion
 * in gcm_core.c makes that edit a build failure instead of a field failure.
 *
 * This is the same failure mode that made this module ship as AES-128 for a
 * while: self-consistent, superficially working, wrong algorithm. See
 * docs/PROJECT_STATUS.md §3.5.1.
 *
 * 96 bits is also the right choice on the merits. It is the only IV length
 * GCM treats natively, it is what every other implementation optimises for,
 * and the project's deterministic nonce
 * (key_epoch:32 || seq:64, see include/protocol.h) fits it exactly with no
 * room to spare and none needed.
 *
 *
 * Caller obligations
 * ==================
 * NONCE UNIQUENESS IS THE CALLER'S JOB AND IT IS ABSOLUTE. Reusing a
 * (key, nonce) pair under GCM is not a degradation, it is a collapse: an
 * attacker who sees two messages under the same pair recovers the XOR of the
 * plaintexts and, worse, can recover the GHASH subkey and forge arbitrary
 * messages under that key. This module cannot detect reuse — it has no memory
 * between calls. The project's answer is tg_nonce_guard_t in
 * include/protocol.h, which derives the nonce from a persisted epoch and a
 * monotonic counter so that reuse is unreachable rather than merely
 * discouraged.
 *
 * Buffer sizes, all caller-allocated:
 *
 *     key          AEAD_KEY_LEN   (32)
 *     nonce        AEAD_NONCE_LEN (12)   — exactly, see above
 *     tag          AEAD_TAG_LEN   (16)
 *     ciphertext   pt_len                — same length as the plaintext
 *     plaintext    ct_len                — GCM is a stream mode, no padding
 *
 * Plaintext and ciphertext buffers may be the same pointer (in-place is
 * safe); partial overlap is not.
 */
#ifndef AEAD_IFACE_H
#define AEAD_IFACE_H

#include <stdint.h>
#include <stddef.h>

#define AEAD_KEY_LEN    32   /* AES-256                                    */
#define AEAD_NONCE_LEN  12   /* 96-bit GCM IV — fixed, see the header note */
#define AEAD_TAG_LEN    16   /* full-length GCM tag, never truncated       */

typedef enum {
    AEAD_OK               =  0,
    AEAD_ERR_BAD_PARAM    = -1,
    /*
     * Authentication failed: the tag did not match. The plaintext buffer has
     * been zeroed. Treat this as hostile until proven otherwise — on the
     * telemetry link it means tampering, a forged frame, or a sender that has
     * desynchronised its key schedule. A burst of these is the cheapest
     * intrusion signal the gateway has; feed it to the DQN.
     */
    AEAD_ERR_AUTH_FAILED  = -2,
    AEAD_ERR_BACKEND      = -3,   /* the underlying cipher/hardware failed */
    AEAD_ERR_NOT_INIT     = -4    /* aead_init() was not called            */
} aead_status_t;

/*
 * Bring the backend up. Must be called before any encrypt/decrypt; safe to
 * call more than once. Hardware backends may claim a peripheral here.
 */
aead_status_t aead_init(void);

/*
 * Encrypt and authenticate.
 *
 *   aad        additional authenticated data — covered by the tag but NOT
 *              encrypted. The telemetry link puts the 24-byte frame header
 *              here, which is what makes the cleartext posture and epoch
 *              fields unforgeable. May be NULL when aad_len is 0.
 *   plaintext  may be NULL when pt_len is 0 (AAD-only authentication).
 *
 * Writes pt_len bytes to ciphertext_out and AEAD_TAG_LEN bytes to tag_out.
 */
aead_status_t aead_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_out
);

/*
 * Verify and decrypt.
 *
 * Returns AEAD_OK only when the tag verifies. On AEAD_ERR_AUTH_FAILED the
 * plaintext buffer is zeroed before returning, so a caller that ignores the
 * status code still cannot act on unverified data. Do not restructure this
 * into a "decrypt, then let the caller check" API.
 *
 * The tag comparison is constant-time.
 */
aead_status_t aead_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *tag,
    uint8_t *plaintext_out
);

/* 1 if the linked backend uses a hardware AES engine, 0 if pure software. */
int aead_backend_is_hardware(void);

/* Stable identifier for logging and for the benchmark table, e.g.
 * "software-tinyAES", "esp32-hw". */
const char *aead_backend_name(void);

/* Release anything aead_init() claimed. */
void aead_deinit(void);

#endif /* AEAD_IFACE_H */
