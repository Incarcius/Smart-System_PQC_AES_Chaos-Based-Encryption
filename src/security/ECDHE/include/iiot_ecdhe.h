/**
 * @file iiot_ecdhe.h
 * @brief Hardware-agnostic ECDHE (X25519) wrapper over Monocypher.
 *
 * This module and its .c file must compile for ANY target (ESP32 today,
 * Cortex-M4/M7 RTU tomorrow, and the host for tests) provided a conforming
 * hal_port.c is linked in. No hardware headers may be included here,
 * directly or transitively.
 *
 * Role in the system
 * ------------------
 * This establishes the LEAF -> GATEWAY session keys. It is deliberately NOT
 * part of the ROOT_KEY hierarchy: leaf nodes never hold the ROOT_KEY, so a
 * compromised sensor node cannot derive keys for the rest of the system.
 *
 * Note the consequence, and state it plainly in the paper: X25519 is
 * classically sound but NOT post-quantum. Traffic on the leaf tier recorded
 * today is decryptable by a future quantum adversary, so the project's
 * post-quantum claim covers the gateway<->server tier only. Moving the leaf
 * tier to ML-KEM is tracked in docs/PROJECT_STATUS.md (P1).
 *
 * Threat-model notes
 * ------------------
 *  - X25519 (Curve25519 Diffie-Hellman), constant-time per Monocypher's
 *    design.
 *  - The caller must wipe `my_secret_key` via iiot_ecdhe_wipe_secret() once
 *    the shared secret has been derived and is no longer needed.
 *  - The shared secret is RAW X25519 output. Per RFC 7748 it MUST be passed
 *    through a KDF before use as a symmetric key - it is not directly
 *    suitable as an AES key, because it is a uniformly random point encoding
 *    rather than a uniformly random bit string. Feed it to RXCR-KMAC-KDF.
 *    This module intentionally contains no KDF, to keep responsibilities
 *    separated.
 */

#ifndef IIOT_ECDHE_H
#define IIOT_ECDHE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IIOT_ECDHE_KEY_LEN 32U

/**
 * @brief Result of a key-agreement operation.
 */
typedef enum {
    IIOT_ECDHE_OK = 0,

    /**
     * The peer's public key is a low-order / small-subgroup point, so the
     * X25519 output is all-zero and carries no shared secret. This is not a
     * transient error: it means the peer sent a degenerate key, either
     * through a broken implementation or deliberately. Abort the handshake.
     */
    IIOT_ECDHE_ERR_LOW_ORDER_POINT = -1,

    /** A required pointer was NULL. */
    IIOT_ECDHE_ERR_BAD_PARAM = -2
} iiot_ecdhe_status_t;

/**
 * @brief Generate an X25519 keypair.
 *
 * secret_key is filled via hal_trng_fill(). Monocypher's
 * crypto_x25519_public() performs the RFC 7748 scalar clamping internally
 * when it reads secret_key, so raw TRNG bytes are the correct input format -
 * do not clamp manually.
 *
 * @param public_key  [out] 32-byte public key.
 * @param secret_key  [out] 32-byte secret key (handle as sensitive).
 */
void iiot_ecdhe_generate_keypair(uint8_t public_key[IIOT_ECDHE_KEY_LEN],
                                 uint8_t secret_key[IIOT_ECDHE_KEY_LEN]);

/**
 * @brief Compute the X25519 shared secret (raw DH output).
 *
 * @param shared_secret     [out] 32-byte raw shared secret. MUST be passed
 *                                through a KDF before use as a symmetric
 *                                key. Zeroed on any error.
 * @param my_secret_key     [in]  Caller's own secret key.
 * @param their_public_key  [in]  Peer's public key.
 *
 * @return IIOT_ECDHE_OK on success, or a negative iiot_ecdhe_status_t.
 *
 * @note This returns a status rather than void. The previous void signature
 *       handled a low-order peer key by wiping the output and then, in debug
 *       builds, spinning in `while (1) {}`. On a substation gateway that is a
 *       hang an attacker triggers by sending one degenerate public key - a
 *       remote denial of service in the error path. In release builds it was
 *       worse: it returned silently with an all-zero shared secret, and a
 *       caller that did not separately check for all-zero would derive
 *       session keys from a value the attacker also knows. Callers MUST check
 *       this return value.
 */
iiot_ecdhe_status_t iiot_ecdhe_compute_shared_secret(
    uint8_t shared_secret[IIOT_ECDHE_KEY_LEN],
    const uint8_t my_secret_key[IIOT_ECDHE_KEY_LEN],
    const uint8_t their_public_key[IIOT_ECDHE_KEY_LEN]);

/**
 * @brief Securely wipe a 32-byte secret buffer (keys, secrets).
 *
 * Thin, semantically-named wrapper over hal_secure_wipe() for crypto call
 * sites.
 *
 * @param secret  Buffer to wipe (any IIOT_ECDHE_KEY_LEN buffer).
 */
void iiot_ecdhe_wipe_secret(uint8_t secret[IIOT_ECDHE_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* IIOT_ECDHE_H */
