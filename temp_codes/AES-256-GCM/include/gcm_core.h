/*
 * gcm_core.h — portable GCM mode, parameterised by a raw AES block function.
 *
 * Why this layer exists
 * =====================
 * GCM is built entirely out of one primitive: "encrypt this 16-byte block
 * with this key". Everything else — the CTR keystream, the GHASH
 * authenticator, the tag — is mode logic that does not care how that block
 * encryption happens.
 *
 * So the mode lives here once, in portable C, and each backend supplies only
 * the block function: tiny-AES in software, or a hardware AES peripheral via
 * register writes. That means the ESP32 register backend gets its GHASH and
 * CTR logic from the same tested code as the software build, instead of
 * reimplementing the fiddly parts per platform.
 *
 * The mbedTLS backend (esp32_hw.c) is the exception — mbedTLS already
 * implements the whole AEAD, so it bypasses this file entirely.
 *
 * Scope: 96-bit IV and 128-bit tag only. See aead_iface.h for why the IV
 * length is not negotiable, and for the nonce-uniqueness obligation that
 * this layer cannot enforce on the caller's behalf.
 */
#ifndef GCM_CORE_H
#define GCM_CORE_H

#include <stdint.h>
#include <stddef.h>

#include "aead_iface.h"   /* AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Raw AES block encryption, supplied by the backend.
 *
 *   key  AEAD_KEY_LEN bytes
 *   in   one 16-byte block
 *   out  one 16-byte block; may alias `in`
 *
 * Returns 0 on success, non-zero if the backend failed (hardware timeout,
 * peripheral busy). GCM uses the FORWARD direction only, for both encryption
 * and decryption — a backend never needs to implement AES decryption.
 *
 * This is called once per 16 bytes of payload plus twice more per message, so
 * it is the hot path; a backend that sets up a key schedule on every call
 * (as the software backend currently does) pays for it here.
 */
typedef int (*aead_raw_block_fn)(const uint8_t key[AEAD_KEY_LEN],
                                 const uint8_t in[16],
                                 uint8_t out[16]);

/*
 * Encrypt-and-authenticate.
 *
 * Writes pt_len bytes to `ct` and AEAD_TAG_LEN bytes to `tag`.
 * `pt`/`ct` may be the same pointer. `aad` and `pt` may each be NULL when
 * the corresponding length is 0.
 *
 * Returns  0  success
 *         -1  the backend block function failed
 *         -2  invalid arguments, or the payload exceeds the GCM length limit
 */
int gcm_core_encrypt(aead_raw_block_fn blk,
                     const uint8_t key[AEAD_KEY_LEN],
                     const uint8_t iv[AEAD_NONCE_LEN],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt,  size_t pt_len,
                     uint8_t *ct, uint8_t tag[AEAD_TAG_LEN]);

/*
 * Verify-and-decrypt.
 *
 * NOTE THE RETURN CONVENTION — it is not the usual 0-means-success:
 *
 *      1  tag verified, plaintext is valid
 *      0  TAG MISMATCH — plaintext buffer has been zeroed, discard
 *     -1  the backend block function failed
 *     -2  invalid arguments
 *
 * A caller writing `if (gcm_core_decrypt(...) == 0)` to mean success would
 * accept exactly the forged messages it was supposed to reject. Callers
 * should prefer the aead_decrypt() wrapper in aead_iface.h, which converts
 * this to the ordinary aead_status_t convention.
 */
int gcm_core_decrypt(aead_raw_block_fn blk,
                     const uint8_t key[AEAD_KEY_LEN],
                     const uint8_t iv[AEAD_NONCE_LEN],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct,  size_t ct_len,
                     const uint8_t *tag,
                     uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif /* GCM_CORE_H */
