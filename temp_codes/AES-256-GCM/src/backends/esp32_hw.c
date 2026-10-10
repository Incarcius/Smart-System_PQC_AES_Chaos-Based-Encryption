/*
 * esp32_hw.c — AES-256-GCM on ESP32 via mbedTLS.
 *
 * The recommended ESP32 backend. mbedTLS implements the complete AEAD, so
 * gcm_core.c is bypassed entirely here — this file is a thin adapter from
 * aead_iface.h onto mbedtls_gcm_*.
 *
 * Under ESP-IDF, mbedTLS is compiled against the hardware AES driver, so this
 * still uses the AES peripheral; it just gets ESP-IDF's maintained,
 * concurrency-safe driver instead of the hand-rolled register writes in
 * esp32_hw_registers.c. Prefer this one unless you specifically need to keep
 * mbedTLS out of the image.
 *
 * Requires ESP-IDF (or any mbedTLS with MBEDTLS_GCM_C enabled). It will not
 * build on the host test runner, which is why the host suite exercises the
 * software backend instead.
 */
#include "aead_iface.h"
#include "aead_backend_select.h"

#ifdef AEAD_BACKEND_ESP32_HW

#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include <string.h>

static int g_initialized = 0;

aead_status_t aead_init(void) { g_initialized = 1; return AEAD_OK; }
void aead_deinit(void) { g_initialized = 0; }
int aead_backend_is_hardware(void) { return 1; }
const char *aead_backend_name(void) { return "esp32-hw"; }

/*
 * The GCM context is set up and torn down per call, which re-runs the key
 * schedule and the H precomputation every time. That mirrors the stateless
 * aead_iface.h contract and keeps this adapter simple; if per-packet AES cost
 * turns out to breach a node's timing budget, caching a context per session
 * key is the first optimisation to reach for.
 */
aead_status_t aead_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext_out, uint8_t *tag_out)
{
    if (!g_initialized) return AEAD_ERR_NOT_INIT;
    if (!key || !nonce || !ciphertext_out || !tag_out) return AEAD_ERR_BAD_PARAM;

    /* Accept a NULL payload when pt_len is 0, matching the software backend.
     * The two used to disagree here: this backend rejected AAD-only calls,
     * which the control channel relies on. */
    if (pt_len > 0 && !plaintext) return AEAD_ERR_BAD_PARAM;
    if (aad_len > 0 && !aad) return AEAD_ERR_BAD_PARAM;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    /* AEAD_KEY_LEN * 8 = 256. mbedTLS DOES validate the key length, unlike
     * tiny-AES — which is why this backend never had the AES-128 bug. */
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AEAD_KEY_LEN * 8);
    if (rc != 0) { mbedtls_gcm_free(&ctx); return AEAD_ERR_BACKEND; }

    rc = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
        nonce, AEAD_NONCE_LEN, aad, aad_len,
        plaintext, ciphertext_out, AEAD_TAG_LEN, tag_out
    );

    mbedtls_gcm_free(&ctx);
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

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AEAD_KEY_LEN * 8);
    if (rc != 0) { mbedtls_gcm_free(&ctx); return AEAD_ERR_BACKEND; }

    /* mbedtls_gcm_auth_decrypt verifies before returning the plaintext and
     * zeroes the output on failure, matching the aead_iface.h contract. */
    rc = mbedtls_gcm_auth_decrypt(
        &ctx, ct_len, nonce, AEAD_NONCE_LEN, aad, aad_len,
        tag, AEAD_TAG_LEN, ciphertext, plaintext_out
    );

    mbedtls_gcm_free(&ctx);

    /* Keep the authentication failure distinct from a backend error — the
     * gateway treats a burst of AUTH_FAILED as an intrusion signal, and
     * folding it into a generic error would lose that. */
    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) return AEAD_ERR_AUTH_FAILED;
    return (rc == 0) ? AEAD_OK : AEAD_ERR_BACKEND;
}

#endif /* AEAD_BACKEND_ESP32_HW */
