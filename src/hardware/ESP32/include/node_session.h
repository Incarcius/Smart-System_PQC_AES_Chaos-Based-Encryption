/*
 * node_session.h — leaf session establishment and nonce discipline.
 *
 *
 * The handshake: PSK + ephemeral X25519
 * =====================================
 * Raw ECDHE is unauthenticated, so a man in the middle between the ESP32 and
 * the gateway can complete two handshakes and relay everything. On a UART run
 * inside a cabinet that is a modest risk; on a substation bus it is not.
 *
 * So the leaf is provisioned at manufacture with a 32-byte device PSK, and the
 * session key is derived from BOTH the ephemeral DH output and that PSK:
 *
 *     ikm = X25519(leaf_sk, gw_pub) || device_psk        (64 bytes)
 *
 * This is the PSK-DHE shape used by TLS-PSK-with-DHE, and it buys two things
 * at once:
 *
 *   - authentication: only the real gateway holds this leaf's PSK, so a MITM
 *     cannot derive the session key even though it can relay the public keys;
 *   - forward secrecy: the DH keys are ephemeral and wiped after use, so
 *     recovering the PSK later does NOT decrypt recorded traffic.
 *
 * Worth stating plainly in the paper: if the PSK leaks, an attacker can MITM
 * *future* handshakes for that node. Past sessions stay safe. Re-provisioning
 * one ESP32 is the cheapest recovery in the system.
 *
 * No signatures are needed on the leaf, which matters — ML-DSA verification is
 * ~13 ms and the leaf has a 100 ms sampling budget to protect.
 *
 *
 * Message flow
 * ============
 *     leaf -> gw   HELLO      version, type, endpoint_id, key_epoch,
 *                             leaf_pub(32), leaf_nonce(32)        72 bytes
 *     gw -> leaf   HELLO_ACK  version, type, endpoint_id, reserved,
 *                             gw_pub(32), gw_nonce(32)            72 bytes
 *     leaf -> gw   CONFIRM    version, type, endpoint_id, reserved,
 *                             tag(16)                             24 bytes
 *
 * Both HELLO and HELLO_ACK are fixed-length, so the transcript can concatenate
 * them without length prefixes and stay unambiguous.
 *
 *     transcript  = SHA3-256(HELLO || HELLO_ACK)
 *     session_key = RXCR-KMAC-KDF(ikm, salt=transcript,
 *                                 info="leaf-session/v1",
 *                                 node_id=endpoint_id BE16, algo="AES-GCM")
 *     confirm_tag = KMACXOF256(session_key, transcript, 16,
 *                              custom="leaf-confirm/v1")
 *
 * The nonces make each transcript unique, so a replayed HELLO cannot force a
 * repeat of an earlier session key. CONFIRM lets both ends find out
 * immediately that they derived the same key, instead of discovering it when
 * the first telemetry frame fails to open.
 */
#ifndef NODE_SESSION_H
#define NODE_SESSION_H

#include <stdint.h>
#include <stddef.h>

#define NODE_PSK_LEN         32
#define NODE_SESSION_KEY_LEN 32
#define NODE_PUBKEY_LEN      32
#define NODE_HS_NONCE_LEN    32

#define NODE_MSG_HELLO       0x01
#define NODE_MSG_HELLO_ACK   0x02
#define NODE_MSG_CONFIRM     0x03

#define NODE_HELLO_LEN       72
#define NODE_HELLO_ACK_LEN   72
#define NODE_CONFIRM_LEN     24

/* NVS / file key for the persisted epoch. */
#define NODE_EPOCH_KEY       "key_epoch"

/*
 * Ceiling on frames per key_epoch, mirroring TG_SEQ_MAX on the uplink. Far
 * below the 2^32 GCM block-counter limit, so a rekey is forced long before
 * anything approaches a birthday bound. At 10 Hz this is ~3.4 years.
 */
#define NODE_SEQ_MAX  ((uint64_t)1 << 30)

typedef enum {
    NODE_SESSION_OK          =  0,
    NODE_SESSION_ERR_PARAM   = -1,
    NODE_SESSION_ERR_STORAGE = -2,
    NODE_SESSION_ERR_FORMAT  = -3,   /* malformed handshake message        */
    NODE_SESSION_ERR_CRYPTO  = -4,   /* KDF or DH failure                  */
    NODE_SESSION_ERR_PEER    = -5,   /* low-order peer key, or ids mismatch */
    NODE_SESSION_ERR_CONFIRM = -6,   /* confirm tag mismatch — no shared key */
    NODE_SESSION_EXHAUSTED   = -7    /* seq space used up, rekey required   */
} node_session_status_t;

/*
 * Send-side nonce counter. The only sanctioned source of a `seq`.
 *
 * Same principle as tg_nonce_guard_t on the uplink: the policy layer decides
 * *when* to rekey, but cannot produce a duplicate nonce even if it decides
 * badly.
 */
typedef struct {
    uint32_t key_epoch;
    uint64_t next_seq;
    int      exhausted;
} node_nonce_guard_t;

/*
 * Load the persisted epoch, INCREMENT it, and commit before returning.
 *
 * Ordering is the whole point: committing first means a crash mid-boot can
 * only skip an epoch, never reuse one. Skipping is free; reusing is fatal.
 */
node_session_status_t node_nonce_boot(node_nonce_guard_t *g);

/* Claim the next seq. Returns NODE_SESSION_EXHAUSTED once the epoch is spent;
 * the caller must rekey rather than continue. */
node_session_status_t node_nonce_next(node_nonce_guard_t *g, uint64_t *seq_out);

/* Bump to a fresh epoch mid-run (rekey). Persists before returning. */
node_session_status_t node_nonce_rekey(node_nonce_guard_t *g);

/* ── handshake ───────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  session_key[NODE_SESSION_KEY_LEN];
    uint8_t  transcript[32];
    uint16_t endpoint_id;
    uint32_t key_epoch;
    int      established;
} node_session_t;

/* Ephemeral state held only between HELLO and HELLO_ACK. Wipe after use. */
typedef struct {
    uint8_t leaf_sk[NODE_PUBKEY_LEN];
    uint8_t hello[NODE_HELLO_LEN];
} node_handshake_ctx_t;

/*
 * Leaf step 1: build HELLO. Generates the ephemeral keypair and a fresh
 * handshake nonce, and retains what step 2 needs in `ctx`.
 */
node_session_status_t node_handshake_start(node_handshake_ctx_t *ctx,
                                           uint16_t endpoint_id,
                                           uint32_t key_epoch,
                                           uint8_t out[NODE_HELLO_LEN]);

/*
 * Leaf step 2: consume HELLO_ACK, derive the session key, emit CONFIRM.
 * Wipes `ctx` on both success and failure — the ephemeral private key must
 * not outlive this call, or forward secrecy is lost.
 */
node_session_status_t node_handshake_finish(node_handshake_ctx_t *ctx,
                                            const uint8_t psk[NODE_PSK_LEN],
                                            const uint8_t ack[NODE_HELLO_ACK_LEN],
                                            node_session_t *session,
                                            uint8_t out[NODE_CONFIRM_LEN]);

/*
 * Gateway side, both steps in one call: consume HELLO, emit HELLO_ACK, derive
 * the same session key. The gateway has no long-lived DH key either — its
 * keypair is ephemeral per handshake.
 *
 * Implemented in C so the loopback test can exercise both roles. Phase D ports
 * this role to Python and pins it with a cross-language KAT.
 */
node_session_status_t node_handshake_respond(const uint8_t psk[NODE_PSK_LEN],
                                             const uint8_t hello[NODE_HELLO_LEN],
                                             node_session_t *session,
                                             uint8_t out[NODE_HELLO_ACK_LEN]);

/* Gateway: verify the leaf's CONFIRM against the derived key. */
node_session_status_t node_handshake_verify_confirm(
        const node_session_t *session,
        const uint8_t confirm[NODE_CONFIRM_LEN]);

/*
 * Deterministic core of the derivation, exposed for cross-language pinning.
 *
 * A live handshake generates ephemeral keys and nonces, so it cannot be a
 * known-answer test. This takes the two transcript messages, the DH output and
 * the PSK as fixed inputs and performs exactly the derivation the handshake
 * does, which CAN be pinned byte-for-byte against the Python gateway.
 *
 * Not part of the runtime API. The handshake functions call the same internal
 * path, so a passing KAT here covers the real one.
 */
node_session_status_t node_session_derive_for_test(
        const uint8_t hello[NODE_HELLO_LEN],
        const uint8_t ack[NODE_HELLO_ACK_LEN],
        const uint8_t dh[32],
        const uint8_t psk[NODE_PSK_LEN],
        node_session_t *session);

/* Confirm tag for a derived session. Exposed alongside the above. */
void node_session_confirm_tag_for_test(const node_session_t *session,
                                       uint8_t tag[16]);

/* Wipe a session's key material. */
void node_session_wipe(node_session_t *session);

#endif /* NODE_SESSION_H */
