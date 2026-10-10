/*
 * posture_frame.h — sealed server->gateway control frame.
 *
 * Wraps a 32-byte tg_control_t in AES-256-GCM under the `gw-ctrl` session
 * key, which the RXCR-KMAC-KDF derives separately from the `gw-telemetry`
 * key (the KDF's customisation string keeps them apart). Separate key means
 * separate nonce space, so telemetry and control counters can never collide.
 *
 * Wire layout, 64 bytes fixed:
 *
 *     off  len  field
 *      0    1   version        TG_PROTO_VERSION
 *      1    1   type           TG_CTRL_FRAME_TYPE
 *      2    2   reserved       must be 0
 *      4   12   nonce          ctrl_epoch(4 BE) || ctrl_seq(8 BE)
 *     16   32   ciphertext     encrypted tg_control_t
 *     48   16   tag            GCM tag
 *
 *     AAD = bytes [0 .. 15]  (everything before the ciphertext)
 *
 * Encrypted, not merely authenticated
 * -----------------------------------
 * The obvious cheaper design is AAD-only authentication: the posture is
 * already visible in the telemetry header, so why hide it? Because
 * `node_mask` is in here. A passive observer reading it learns precisely
 * which nodes the LSTM has flagged -- that is, the attacker learns they have
 * been detected, and on which nodes, in time to move. Thirty-two bytes of
 * encryption is a trivial price for not broadcasting that.
 *
 * Nonce uniqueness
 * ----------------
 * The nonce is `ctrl_epoch || ctrl_seq`, both of which the SERVER owns. Same
 * discipline as telemetry: ctrl_epoch is persisted and bumped on every
 * control-key install and every server restart, ctrl_seq is monotonic within
 * an epoch. A restart therefore cannot replay a (key, nonce) pair even if the
 * same `gw-ctrl` key is reloaded.
 *
 * Putting the nonce in the clear is deliberate and safe: GCM nonces are not
 * secret, and the gateway needs ctrl_seq to run its replay check BEFORE
 * spending a decryption on a frame that may be a replay.
 */
#ifndef TG_POSTURE_FRAME_H
#define TG_POSTURE_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#define TG_CTRL_FRAME_LEN   64
#define TG_CTRL_FRAME_TYPE  0x01
#define TG_CTRL_AAD_LEN     16
#define TG_CTRL_KEY_LEN     32

typedef enum {
    TG_FRAME_OK            =  0,
    TG_FRAME_ERR_PARAM     = -1,
    TG_FRAME_ERR_FORMAT    = -2,   /* bad version/type/reserved          */
    TG_FRAME_ERR_AUTH      = -3,   /* GCM tag failed — forged or corrupt */
    TG_FRAME_ERR_BACKEND   = -4,   /* AEAD backend failure               */
    TG_FRAME_ERR_MISMATCH  = -5    /* ctrl_seq in nonce != in payload    */
} tg_frame_status_t;

/*
 * Seal a control message. `ctrl->ctrl_seq` supplies the nonce's counter half,
 * so the caller must have advanced it before calling.
 */
tg_frame_status_t tg_ctrl_seal(const uint8_t key[TG_CTRL_KEY_LEN],
                               uint32_t ctrl_epoch,
                               const tg_control_t *ctrl,
                               uint8_t out[TG_CTRL_FRAME_LEN]);

/*
 * Open and verify a control frame.
 *
 * On TG_FRAME_OK, *ctrl holds the authenticated message and *ctrl_epoch_out
 * the epoch from the nonce. Any other return leaves *ctrl zeroed.
 *
 * Cryptographic verification only — this does NOT apply the message. Feed the
 * result to tg_posture_apply(), which enforces freshness and ordering.
 */
tg_frame_status_t tg_ctrl_open(const uint8_t key[TG_CTRL_KEY_LEN],
                               const uint8_t in[TG_CTRL_FRAME_LEN],
                               tg_control_t *ctrl,
                               uint32_t *ctrl_epoch_out);

/*
 * Read ctrl_seq straight out of the cleartext nonce, without decrypting.
 *
 * Lets the gateway drop an obvious replay before paying for a GCM open. The
 * value is UNAUTHENTICATED at this point: use it only to skip work, never to
 * accept anything. tg_ctrl_open() re-checks it against the authenticated
 * payload and returns TG_FRAME_ERR_MISMATCH if they disagree.
 */
tg_frame_status_t tg_ctrl_peek_seq(const uint8_t in[TG_CTRL_FRAME_LEN],
                                   uint64_t *ctrl_seq_out);

#endif /* TG_POSTURE_FRAME_H */
