/*
 * esp32_hw_registers.c — AES-256-GCM on the ESP32 AES peripheral, driven by
 * direct register access, with no mbedTLS dependency.
 *
 * Supplies only the raw block function; GHASH and CTR come from gcm_core.c,
 * so this backend shares the mode logic with the software build rather than
 * reimplementing it.
 *
 * Choose this over esp32_hw.c (mbedTLS) when you want to avoid pulling
 * mbedTLS into the image at all. Otherwise prefer esp32_hw.c — it is the path
 * ESP-IDF actually maintains.
 *
 *
 * ⚠ STATUS: UNVERIFIED ON HARDWARE ⚠
 * ==================================
 * This backend has never been run against a known-answer vector on a real
 * ESP32. It cannot be exercised by the host test suite, because it writes to
 * physical addresses. Two things must happen before it is trusted:
 *
 *  1. Check the register map and the mode encoding against the ESP32
 *     Technical Reference Manual for your exact silicon revision. In
 *     particular AES_MODE_REG below is written as
 *     (AES_MODE_ENCRYPT | AES_MODE_KEY_LEN_256) = 0x21, treating direction
 *     and key length as independent bitfields. The ESP32 TRM encodes them as
 *     a single enumerated value instead, so this is very likely wrong and is
 *     the first thing to check.
 *
 *  2. Run tests/test_aead.c on the device. The vectors in tests/vectors.json
 *     are independently validated against a conforming implementation, so
 *     they are a real oracle. A backend that passes round-trip tests but
 *     fails these is producing self-consistent non-GCM — the exact failure
 *     this module already shipped once (docs/PROJECT_STATUS.md §3.5.1).
 *
 * Until both are done, build ESP32 targets with AEAD_BACKEND_ESP32_HW.
 *
 *
 * Not reentrant
 * =============
 * The AES peripheral is a single shared resource and this code holds no lock.
 * If two tasks call in concurrently, or if mbedTLS touches the same
 * peripheral from another thread, their register writes interleave and both
 * get wrong answers — with no error reported. If the gateway firmware ever
 * encrypts from more than one task, wrap aes_hw_raw_block() in a mutex.
 */
#include "aead_iface.h"
#include "aead_backend_select.h"

#ifdef AEAD_BACKEND_ESP32_REGS

#include "gcm_core.h"
#include <stdint.h>
#include <string.h>

#define AES_KEY_REG_WORDS    8   /* 8 x 32-bit = 256-bit key */
#define AES_TEXT_WORDS       4   /* 4 x 32-bit = 128-bit block */

/* Original ESP32 AES peripheral. The S3 and C3 use a different map, which is
 * why those backends are stubs rather than aliases of this one. */
#ifndef AES_BASE
#define AES_BASE 0x3ff01000u
#endif

#define AES_KEY_REG(w)        (AES_BASE + 0x00u + (uint32_t)(w) * 4u)
#define AES_TEXT_IN_REG(w)    (AES_BASE + 0x80u + (uint32_t)(w) * 4u)
#define AES_TEXT_OUT_REG(w)   (AES_BASE + 0xa0u + (uint32_t)(w) * 4u)
#define AES_MODE_REG          (AES_BASE + 0xc0u)
#define AES_START_REG         (AES_BASE + 0xc4u)
#define AES_IDLE_REG          (AES_BASE + 0xc8u)
#define AES_ENDIAN_REG        (AES_BASE + 0xccu)

#define AES_MODE_ENCRYPT      0x0001u
#define AES_MODE_KEY_LEN_256  0x0020u   /* see the status note above */

/* How long to spin waiting for the peripheral. A single AES block takes on
 * the order of a dozen cycles, so anything approaching this bound means the
 * peripheral is wedged, not busy. */
#define AES_IDLE_SPIN_LIMIT   0xFFFFu

#define HW_READ32(a)          (*(volatile uint32_t *)(uintptr_t)(a))
#define HW_WRITE32(a, v)      (*(volatile uint32_t *)(uintptr_t)(a) = (uint32_t)(v))

/* Text blocks go in big-endian word order; the key registers are written
 * little-endian. That asymmetry is intentional in this driver and is one of
 * the things to confirm against the TRM. */
static void block_be_to_words(const uint8_t in[16], uint32_t words[4])
{
    for (int w = 0; w < 4; ++w) {
        words[w] = ((uint32_t)in[w*4+0] << 24) | ((uint32_t)in[w*4+1] << 16) |
                   ((uint32_t)in[w*4+2] <<  8) | ((uint32_t)in[w*4+3]);
    }
}

static void words_to_block_be(const uint32_t words[4], uint8_t out[16])
{
    for (int w = 0; w < 4; ++w) {
        out[w*4+0] = (uint8_t)(words[w] >> 24);
        out[w*4+1] = (uint8_t)(words[w] >> 16);
        out[w*4+2] = (uint8_t)(words[w] >>  8);
        out[w*4+3] = (uint8_t)(words[w]);
    }
}

/*
 * One AES-256 block encryption on the peripheral.
 *
 * The key is rewritten on every block because aead_raw_block_fn is stateless.
 * That is ~8 extra register writes per 16 bytes; if this backend ever becomes
 * the bottleneck, cache the loaded key and skip the reload when it is
 * unchanged.
 *
 * Returns 0 on success, -1 if the peripheral did not report idle in time.
 */
static int aes_hw_raw_block(const uint8_t key[AEAD_KEY_LEN],
                            const uint8_t in[16],
                            uint8_t out[16])
{
    uint32_t words[4];
    int      w;
    uint32_t spin;
    int      idle = 0;

    for (w = 0; w < AES_KEY_REG_WORDS; ++w)
        HW_WRITE32(AES_KEY_REG(w),
                   ((uint32_t)key[w*4+3] << 24) | ((uint32_t)key[w*4+2] << 16) |
                   ((uint32_t)key[w*4+1] <<  8) | ((uint32_t)key[w*4+0]));

    HW_WRITE32(AES_MODE_REG, AES_MODE_ENCRYPT | AES_MODE_KEY_LEN_256);
    HW_WRITE32(AES_ENDIAN_REG, 1u);

    block_be_to_words(in, words);
    for (w = 0; w < AES_TEXT_WORDS; ++w)
        HW_WRITE32(AES_TEXT_IN_REG(w), words[w]);

    HW_WRITE32(AES_START_REG, 1u);

    for (spin = 0; spin < AES_IDLE_SPIN_LIMIT; ++spin) {
        if (HW_READ32(AES_IDLE_REG) & 0x1u) { idle = 1; break; }
    }

    /*
     * Previously the timeout was ignored: the loop could fall through without
     * the peripheral ever going idle, and the output registers were read and
     * returned anyway with a success status. A wedged AES engine therefore
     * produced silent garbage ciphertext instead of an error — and because
     * GCM is a stream mode, that garbage would have been indistinguishable
     * from valid output until the receiver's tag check failed.
     *
     * gcm_core treats a non-zero return as a hard failure, which propagates
     * to AEAD_ERR_BACKEND. Fail loudly rather than encrypt with nothing.
     */
    if (!idle) return -1;

    for (w = 0; w < AES_TEXT_WORDS; ++w)
        words[w] = HW_READ32(AES_TEXT_OUT_REG(w));
    words_to_block_be(words, out);

    return 0;
}

static int g_initialized = 0;

aead_status_t aead_init(void) { g_initialized = 1; return AEAD_OK; }
void aead_deinit(void) { g_initialized = 0; }
int aead_backend_is_hardware(void) { return 1; }
const char *aead_backend_name(void) { return "esp32-hw-registers"; }

aead_status_t aead_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext_out, uint8_t *tag_out)
{
    if (!g_initialized) return AEAD_ERR_NOT_INIT;
    if (!key || !nonce || !ciphertext_out || !tag_out) return AEAD_ERR_BAD_PARAM;
    if (pt_len > 0 && !plaintext) return AEAD_ERR_BAD_PARAM;
    if (aad_len > 0 && !aad) return AEAD_ERR_BAD_PARAM;

    int rc = gcm_core_encrypt(aes_hw_raw_block, key, nonce,
                              aad, aad_len, plaintext, pt_len,
                              ciphertext_out, tag_out);
    return (rc == 0) ? AEAD_OK : AEAD_ERR_BACKEND;
}

aead_status_t aead_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *tag, uint8_t *plaintext_out)
{
    if (!g_initialized) return AEAD_ERR_NOT_INIT;
    if (!key || !nonce || !tag || !plaintext_out) return AEAD_ERR_BAD_PARAM;
    if (ct_len > 0 && !ciphertext) return AEAD_ERR_BAD_PARAM;
    if (aad_len > 0 && !aad) return AEAD_ERR_BAD_PARAM;

    int rc = gcm_core_decrypt(aes_hw_raw_block, key, nonce,
                              aad, aad_len, ciphertext, ct_len,
                              tag, plaintext_out);

    /* 1 = verified, 0 = tag mismatch, negative = backend failure. */
    if (rc < 0) return AEAD_ERR_BACKEND;
    return (rc == 1) ? AEAD_OK : AEAD_ERR_AUTH_FAILED;
}

#endif /* AEAD_BACKEND_ESP32_REGS */
