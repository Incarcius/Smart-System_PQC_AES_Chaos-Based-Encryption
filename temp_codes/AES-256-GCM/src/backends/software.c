/*
 * software.c — portable AES-256-GCM backend over tiny-AES.
 *
 * The reference backend: no hardware, no external library, builds anywhere.
 * It is what the host test suite and the Python-interop vectors run against,
 * so when a hardware backend disagrees with this one, this one is right.
 *
 * The mode logic lives in gcm_core.c; this file supplies only the raw AES
 * block function and the aead_iface.h wrapper around it.
 *
 *
 * Key size
 * ========
 * tiny-AES selects its key length at COMPILE time and does not validate the
 * key you hand it — AES_init_ctx() simply reads the first AES_KEYLEN bytes.
 * With the upstream default of AES128 that silently truncates the 32-byte
 * session key to 16 and builds an AES-128 schedule, which round-trips
 * perfectly against itself while failing every AES-256 test vector. That is
 * exactly what happened here; see docs/PROJECT_STATUS.md §3.5.1. The key size
 * is now pinned in backends/tiny_aes/aes.h and cross-checked by a static
 * assertion in gcm_core.c.
 *
 *
 * Performance
 * ===========
 * software_block_encrypt() runs a full AES-256 key expansion on EVERY 16-byte
 * block, because the aead_raw_block_fn contract is stateless. For a 64-byte
 * telemetry frame that is 7 key expansions (4 payload blocks + H + the tag
 * mask) where 1 would do.
 *
 * This is the obvious optimisation if the software path ever needs to meet
 * the per-node timing budgets on an ESP32: cache the expanded schedule keyed
 * on a pointer/generation, or widen aead_raw_block_fn to take a prepared
 * context. It is deliberately NOT done yet — on the gateway and the host this
 * backend is far from the bottleneck, and a schedule cache is exactly the
 * kind of shared mutable state that turns into a thread-safety bug. Measure
 * before changing it.
 */
#include "aead_iface.h"
#include "aead_backend_select.h"

#ifdef AEAD_BACKEND_SOFTWARE

#include "tiny_aes/aes.h"
#include "gcm_core.h"
#include <string.h>

static int g_initialized = 0;

/*
 * Raw AES-256 block encryption. GCM needs the forward direction only, for
 * both encrypt and decrypt, so AES_ECB_decrypt is never referenced.
 *
 * The local copy exists because AES_ECB_encrypt() works in place; copying
 * keeps the caller's `in` buffer untouched and lets `in` and `out` alias.
 */
static int software_block_encrypt(const uint8_t key[AEAD_KEY_LEN],
                                  const uint8_t in[16],
                                  uint8_t out[16])
{
    struct AES_ctx ctx;
    uint8_t block[16];

    AES_init_ctx(&ctx, key);
    memcpy(block, in, 16);
    AES_ECB_encrypt(&ctx, block);
    memcpy(out, block, 16);
    return 0;
}

aead_status_t aead_init(void) { g_initialized = 1; return AEAD_OK; }
void aead_deinit(void) { g_initialized = 0; }
int aead_backend_is_hardware(void) { return 0; }
const char *aead_backend_name(void) { return "software-tinyAES"; }

aead_status_t aead_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext_out, uint8_t *tag_out)
{
    if (!g_initialized) return AEAD_ERR_NOT_INIT;
    if (!key || !nonce || !ciphertext_out || !tag_out) return AEAD_ERR_BAD_PARAM;

    /* A NULL payload is legal when its length is 0 — that is AAD-only
     * authentication, which the control channel uses. */
    if (pt_len > 0 && !plaintext) return AEAD_ERR_BAD_PARAM;
    if (aad_len > 0 && !aad) return AEAD_ERR_BAD_PARAM;

    int rc = gcm_core_encrypt(software_block_encrypt, key, nonce,
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

    int rc = gcm_core_decrypt(software_block_encrypt, key, nonce,
                              aad, aad_len, ciphertext, ct_len,
                              tag, plaintext_out);

    /* gcm_core_decrypt returns 1 for verified, 0 for tag mismatch, negative
     * for errors. Mapping 0 to AEAD_OK here would accept forgeries. */
    if (rc < 0) return AEAD_ERR_BACKEND;
    return (rc == 1) ? AEAD_OK : AEAD_ERR_AUTH_FAILED;
}

#endif /* AEAD_BACKEND_SOFTWARE */
