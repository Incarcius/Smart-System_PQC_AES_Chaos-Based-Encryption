/*
 * gcm_core.c — GCM mode (NIST SP 800-38D) over a supplied AES block function.
 *
 * Structure, in the order the code runs:
 *
 *   H   = AES_K(0^128)                     the GHASH subkey
 *   J0  = IV || 0^31 || 1                  pre-counter block (96-bit IV only)
 *   C   = CTR encryption starting at J0+1  payload
 *   S   = GHASH_H(AAD, C)                  authenticator over AAD and ciphertext
 *   T   = S XOR AES_K(J0)                  tag
 *
 * Two details that are easy to get wrong and are worth naming:
 *
 *   - GHASH runs over the CIPHERTEXT, not the plaintext. That is what makes
 *     GCM encrypt-then-MAC, so a forged message is rejected before its
 *     plaintext is ever exposed to a caller.
 *
 *   - The keystream starts at J0+1, not J0. J0 itself is reserved for masking
 *     the tag. Starting the keystream at J0 would leak the tag mask as
 *     keystream and let an attacker forge freely.
 *
 * No lookup tables are used anywhere in GHASH: gfmul() is the bitwise
 * shift-and-xor form, which is slow but has no key-dependent memory access
 * pattern. On a substation gateway that is the right trade — a table-driven
 * GHASH is the classic cache-timing side channel.
 */
#include <string.h>

#include "gcm_core.h"

/* ── compile-time invariants ─────────────────────────────────────────────── */

/*
 * Static assertion.
 *
 * Prefer _Static_assert, which reports the message text and makes the failure
 * self-explanatory. Fall back to the negative-array-size trick for pre-C11
 * toolchains — ESP-IDF still builds some components as gnu99. The fallback
 * reports something unhelpful ("negative subscript" on MSVC, "size of array
 * is negative" on GCC), so the assertion name and the comment above each use
 * are what tell the reader what actually went wrong.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #define GCM_STATIC_ASSERT(cond, name) _Static_assert(cond, #name)
#else
  #define GCM_STATIC_ASSERT(cond, name) \
      typedef char gcm_static_assert_##name[(cond) ? 1 : -1]
#endif

/*
 * THE J0 CONSTRUCTION BELOW IS VALID ONLY FOR A 96-BIT IV.
 *
 * SP 800-38D §7.1 requires J0 = GHASH(H, {}, IV) for any other IV length.
 * This file does not implement that case, so widening AEAD_NONCE_LEN would
 * silently produce output that is not GCM — self-consistent, and wrong. That
 * exact failure mode already cost this module once (it shipped as AES-128
 * while passing all its own round-trip tests; docs/PROJECT_STATUS.md §3.5.1).
 *
 * If you genuinely need a different IV length, implement the GHASH-based J0
 * derivation first, then relax this assertion — do not relax it alone.
 */
GCM_STATIC_ASSERT(AEAD_NONCE_LEN == 12, nonce_must_be_96_bits);

/* The tag is never truncated; GHASH produces exactly one 128-bit block. */
GCM_STATIC_ASSERT(AEAD_TAG_LEN == 16, tag_must_be_128_bits);

/* This module is AES-256; a 16- or 24-byte key here means a backend has been
 * misconfigured. See the tiny-AES key-size note in backends/tiny_aes/aes.h. */
GCM_STATIC_ASSERT(AEAD_KEY_LEN == 32, key_must_be_256_bits);

/*
 * Maximum payload for GCM with a 96-bit IV: 2^39 - 256 bits, i.e.
 * (2^32 - 2) * 16 = 68,719,476,704 bytes. The 32-bit block counter must not
 * wrap back onto J0, which is what this bound prevents.
 *
 * On a 32-bit target size_t cannot hold this value, so the comparison is
 * vacuous there — which is fine, since size_t also cannot hold a payload that
 * large. Computed in uint64_t so the expression itself never overflows.
 */
#define GCM_MAX_PAYLOAD_BYTES  (((uint64_t)0xFFFFFFFFu - 1u) * 16u)

static int payload_too_long(size_t len)
{
    return (uint64_t)len > GCM_MAX_PAYLOAD_BYTES;
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static const uint8_t ZERO_BLOCK[16] = {0};

static void xor16(uint8_t *x, const uint8_t *y)
{
    for (int i = 0; i < 16; ++i) x[i] ^= y[i];
}

/*
 * Multiply two elements of GF(2^128) under the GCM field polynomial
 * x^128 + x^7 + x^2 + x + 1.
 *
 * GCM numbers bits "backwards" relative to the usual convention, so the
 * reduction shifts RIGHT and xors 0xe1 into the leading byte rather than
 * shifting left against 0x87. Getting this backwards produces a function that
 * is still a valid field multiply but not GCM's, which shows up as a tag
 * mismatch against every published vector and nothing else.
 *
 * Runs in constant time with respect to the operand values: the branch on
 * `xbyte` tests a bit of the accumulator argument, and both paths do the same
 * shift work. There is no data-dependent indexing.
 */
static void gfmul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
    uint8_t z[16];
    uint8_t v[16];
    int i, j, bit;

    memset(z, 0, sizeof(z));
    memcpy(v, y, sizeof(v));

    for (i = 0; i < 16; ++i) {
        uint8_t xbyte = x[i];
        for (bit = 7; bit >= 0; --bit) {
            if (xbyte & (1u << bit)) {
                xor16(z, v);                    /* z ^= v  */
            }

            /* v >>= 1 across the whole 128-bit value, then reduce. */
            uint8_t lsb = v[15] & 1u;
            for (j = 15; j > 0; --j) {
                v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
            }
            v[0] >>= 1;
            if (lsb) {
                v[0] ^= 0xe1;                   /* the field polynomial */
            }
        }
    }
    memcpy(out, z, sizeof(z));
}

/*
 * Increment the rightmost 32 bits of a counter block, per GCM's inc32.
 *
 * Only the last four bytes move; the leading 12 bytes hold the IV and must
 * stay fixed. Wrap-around is deliberately not an error here — the payload
 * length check in the callers is what guarantees the counter cannot reach
 * J0 again.
 */
static void inc32(uint8_t block[16])
{
    uint32_t v =
        ((uint32_t)block[12] << 24) |
        ((uint32_t)block[13] << 16) |
        ((uint32_t)block[14] <<  8) |
        ((uint32_t)block[15]);
    v = (uint32_t)(v + 1u);
    block[12] = (uint8_t)(v >> 24);
    block[13] = (uint8_t)(v >> 16);
    block[14] = (uint8_t)(v >>  8);
    block[15] = (uint8_t)(v);
}

/*
 * GHASH_H(AAD, C) — the authenticator.
 *
 * Absorbs AAD blocks, then ciphertext blocks, then one final block holding
 * the two lengths in bits. Short trailing blocks are zero-padded.
 *
 * The length block is not decoration: without it, an attacker could move
 * bytes across the AAD/ciphertext boundary and keep the same tag. It is what
 * makes the split between "authenticated" and "authenticated and encrypted"
 * unambiguous.
 */
static void ghash(const uint8_t h[16],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct,  size_t ct_len,
                  uint8_t s[16])
{
    uint8_t acc[16];
    uint8_t tmp[16];
    uint8_t block[16];
    size_t remain, off;
    uint64_t aad_bits, ct_bits;
    int i;

    memset(acc, 0, sizeof(acc));

    /* acc = (acc XOR block) * H, with the block zero-padded to 16 bytes. */
#define GHASH_BLOCK(src, take) do {                     \
        memset(block, 0, sizeof(block));                \
        memcpy(block, (src), (take));                   \
        xor16(acc, block);                              \
        gfmul(acc, h, tmp);                             \
        memcpy(acc, tmp, sizeof(acc));                  \
    } while (0)

    /* AAD */
    remain = aad_len;
    off = 0;
    while (remain >= 16) {
        GHASH_BLOCK(aad + off, 16);
        off += 16; remain -= 16;
    }
    if (remain) {
        GHASH_BLOCK(aad + off, remain);
    }

    /* Ciphertext */
    remain = ct_len;
    off = 0;
    while (remain >= 16) {
        GHASH_BLOCK(ct + off, 16);
        off += 16; remain -= 16;
    }
    if (remain) {
        GHASH_BLOCK(ct + off, remain);
    }

    /* Final block: len(AAD) || len(C), each a 64-bit big-endian bit count. */
    aad_bits = (uint64_t)(aad_len) << 3;
    ct_bits  = (uint64_t)(ct_len)  << 3;
    memset(block, 0, sizeof(block));
    for (i = 0; i < 8; ++i) {
        block[i]     = (uint8_t)(aad_bits >> (56 - 8 * i));
        block[8 + i] = (uint8_t)(ct_bits  >> (56 - 8 * i));
    }
    xor16(acc, block);
    gfmul(acc, h, tmp);
    memcpy(acc, tmp, sizeof(acc));

#undef GHASH_BLOCK
    memcpy(s, acc, sizeof(acc));
}

/* ── public entry points ─────────────────────────────────────────────────── */

int gcm_core_encrypt(aead_raw_block_fn blk,
                     const uint8_t key[AEAD_KEY_LEN],
                     const uint8_t iv[AEAD_NONCE_LEN],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt,  size_t pt_len,
                     uint8_t *ct, uint8_t tag[AEAD_TAG_LEN])
{
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t j0_orig[16];
    uint8_t ebc[16];          /* encrypted block / keystream scratch */
    uint8_t s[16];
    size_t off;

    if (!blk || !key || !iv || !tag) return -2;
    if (pt_len > 0 && (!pt || !ct)) return -2;
    if (aad_len > 0 && !aad) return -2;
    if (payload_too_long(pt_len)) return -2;

    /* H = AES_K(0^128) */
    if (blk(key, ZERO_BLOCK, h) != 0) return -1;

    /*
     * J0 = IV || 0^31 || 1.
     * Exactly AEAD_NONCE_LEN bytes are read from `iv`; the static assertion
     * above pins that at 12, so the three zero bytes plus the 0x01 always
     * land in the counter field.
     */
    memcpy(j0, iv, AEAD_NONCE_LEN);
    memset(j0 + AEAD_NONCE_LEN, 0, 3);
    j0[15] = 0x01;
    memcpy(j0_orig, j0, sizeof(j0_orig));

    /*
     * CTR over the payload, starting at J0+1. j0 is advanced in place; j0_orig
     * is kept back for the tag mask.
     */
    for (off = 0; off < pt_len; off += 16) {
        size_t take = pt_len - off; if (take > 16) take = 16;
        inc32(j0);
        if (blk(key, j0, ebc) != 0) return -1;
        for (size_t i = 0; i < take; ++i)
            ct[off + i] = (uint8_t)(pt[off + i] ^ ebc[i]);
    }

    /* T = GHASH_H(AAD, C) XOR AES_K(J0) */
    ghash(h, aad, aad_len, ct, pt_len, s);
    if (blk(key, j0_orig, ebc) != 0) return -1;
    for (int i = 0; i < AEAD_TAG_LEN; ++i)
        tag[i] = (uint8_t)(s[i] ^ ebc[i]);

    return 0;
}

int gcm_core_decrypt(aead_raw_block_fn blk,
                     const uint8_t key[AEAD_KEY_LEN],
                     const uint8_t iv[AEAD_NONCE_LEN],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct,  size_t ct_len,
                     const uint8_t *tag,
                     uint8_t *pt)
{
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t j0_orig[16];
    uint8_t ebc[16];
    uint8_t s[16];
    uint8_t expect[AEAD_TAG_LEN];
    size_t off;
    unsigned diff = 0;

    if (!blk || !key || !iv || !tag) return -2;
    if (ct_len > 0 && (!ct || !pt)) return -2;
    if (aad_len > 0 && !aad) return -2;
    if (payload_too_long(ct_len)) return -2;

    if (blk(key, ZERO_BLOCK, h) != 0) return -1;

    memcpy(j0, iv, AEAD_NONCE_LEN);
    memset(j0 + AEAD_NONCE_LEN, 0, 3);
    j0[15] = 0x01;
    memcpy(j0_orig, j0, sizeof(j0_orig));

    /*
     * The plaintext is produced before the tag is checked, then wiped below if
     * verification fails. That ordering is an implementation detail, not an
     * API contract: no unverified plaintext ever escapes this function. It is
     * done this way to keep a single CTR pass on constrained nodes. If this
     * ever grows a streaming API, the order must change — a streaming caller
     * would see plaintext before the tag is known, which is the classic
     * release-unverified-plaintext weakness.
     */
    for (off = 0; off < ct_len; off += 16) {
        size_t take = ct_len - off; if (take > 16) take = 16;
        inc32(j0);
        if (blk(key, j0, ebc) != 0) return -1;
        for (size_t i = 0; i < take; ++i)
            pt[off + i] = (uint8_t)(ct[off + i] ^ ebc[i]);
    }

    ghash(h, aad, aad_len, ct, ct_len, s);
    if (blk(key, j0_orig, ebc) != 0) return -1;
    for (int i = 0; i < AEAD_TAG_LEN; ++i)
        expect[i] = (uint8_t)(s[i] ^ ebc[i]);

    /*
     * Constant-time tag comparison: accumulate every byte difference and test
     * once. A memcmp() here would return early on the first differing byte,
     * and that timing difference is enough to forge a tag byte at a time.
     */
    for (int i = 0; i < AEAD_TAG_LEN; ++i)
        diff |= (unsigned)(expect[i] ^ tag[i]);

    if (diff) {
        if (ct_len) memset(pt, 0, ct_len);
        return 0;   /* tag mismatch — see the return convention in gcm_core.h */
    }
    return 1;       /* verified */
}
