/**
 * @file iiot_ecdhe.c
 * @brief Hardware-agnostic X25519 ECDHE core.
 *
 * HARD RULE: this file includes ONLY <stdint.h>/<string.h>-class headers,
 * "hal_port.h", and "monocypher.h". No esp_*.h, no driver/*.h. If a future
 * edit needs a hardware call, add the primitive to hal_port.h/.c instead of
 * reaching around it here.
 */

#include "iiot_ecdhe.h"
#include "hal_port.h"
#include "monocypher.h"

#include <string.h>

/*
 * Monocypher 4.x API note
 * -----------------------
 * The vendored library is Monocypher 4.0.2, but this file was originally
 * written against the 3.x API and therefore never compiled:
 *
 *   3.x:  int  crypto_x25519(...)          returned -1 on all-zero output
 *         void crypto_x25519_public(...)
 *
 *   4.x:  void crypto_x25519(...)          NO return value
 *         void crypto_x25519_public_key(...)
 *
 * 4.x dropped the return value deliberately - the caller is expected to check
 * the output against zero itself. Losing that check silently is exactly the
 * kind of upgrade hazard that makes a contributory-behaviour bug: the code
 * looks like it validates the peer key, and does not. The check is now
 * explicit below.
 */

/* All-zero X25519 output, the signature of a low-order peer public key. */
static const uint8_t IIOT_ECDHE_ZERO[IIOT_ECDHE_KEY_LEN] = { 0 };

void iiot_ecdhe_generate_keypair(uint8_t public_key[IIOT_ECDHE_KEY_LEN],
                                 uint8_t secret_key[IIOT_ECDHE_KEY_LEN])
{
    if (public_key == NULL || secret_key == NULL) {
        return;
    }

    /* 1. Seed the secret key material from the HAL TRNG. */
    hal_trng_fill(secret_key, IIOT_ECDHE_KEY_LEN);

    /*
     * 2. Derive the public key. Monocypher performs RFC 7748 scalar clamping
     *    internally when it reads secret_key - the raw TRNG bytes are the
     *    valid input format; do not clamp manually here (double-clamping is
     *    harmless but redundant, and a maintenance footgun if Monocypher's
     *    internal behaviour ever changes).
     */
    crypto_x25519_public_key(public_key, secret_key);
}

iiot_ecdhe_status_t iiot_ecdhe_compute_shared_secret(
    uint8_t shared_secret[IIOT_ECDHE_KEY_LEN],
    const uint8_t my_secret_key[IIOT_ECDHE_KEY_LEN],
    const uint8_t their_public_key[IIOT_ECDHE_KEY_LEN])
{
    if (shared_secret == NULL || my_secret_key == NULL ||
        their_public_key == NULL) {
        return IIOT_ECDHE_ERR_BAD_PARAM;
    }

    crypto_x25519(shared_secret, my_secret_key, their_public_key);

    /*
     * The output is all-zero iff `their_public_key` is a low-order /
     * degenerate point (all-zero, or one of the small-order torsion points).
     * That is the all-zero-output check RFC 7748 §6.1 calls for, and under
     * Monocypher 4.x it is the caller's job - see the API note above.
     *
     * crypto_verify32() returns 0 when the buffers are equal and is
     * constant-time. The comparand is public (all zeros), so timing leaks
     * nothing here either way, but there is no reason to reach for memcmp.
     *
     * Treat a hit as a fatal input-validation failure: wipe the output and
     * report, so the caller aborts the handshake.
     *
     * This used to trap in `while (1) {}` under !NDEBUG and return silently
     * with a zeroed buffer otherwise. Both were wrong in different ways - the
     * first is a hang an attacker triggers by sending one degenerate public
     * key, the second hands the caller a "shared secret" the attacker also
     * knows. See the note in iiot_ecdhe.h.
     */
    if (crypto_verify32(shared_secret, IIOT_ECDHE_ZERO) == 0) {
        hal_secure_wipe(shared_secret, IIOT_ECDHE_KEY_LEN);
        return IIOT_ECDHE_ERR_LOW_ORDER_POINT;
    }

    return IIOT_ECDHE_OK;
}

void iiot_ecdhe_wipe_secret(uint8_t secret[IIOT_ECDHE_KEY_LEN])
{
    if (secret == NULL) {
        return;
    }
    hal_secure_wipe(secret, IIOT_ECDHE_KEY_LEN);
}
