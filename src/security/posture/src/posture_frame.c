/*
 * posture_frame.c — seal/open for the server->gateway control frame.
 * See posture_frame.h for the wire layout and design notes.
 */
#include "posture_frame.h"
#include "aead_iface.h"

#include <string.h>

#define OFF_VERSION  0
#define OFF_TYPE     1
#define OFF_RESERVED 2
#define OFF_NONCE    4
#define OFF_CT       16
#define OFF_TAG      48

static void put_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void put_u64be(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint32_t get_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint64_t get_u64be(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

tg_frame_status_t tg_ctrl_seal(const uint8_t key[TG_CTRL_KEY_LEN],
                               uint32_t ctrl_epoch,
                               const tg_control_t *ctrl,
                               uint8_t out[TG_CTRL_FRAME_LEN])
{
    uint8_t plain[TG_CONTROL_LEN];
    uint8_t nonce[AEAD_NONCE_LEN];
    aead_status_t rc;

    if (key == NULL || ctrl == NULL || out == NULL)
        return TG_FRAME_ERR_PARAM;

    /* Header + nonce. These 16 bytes are the AAD. */
    memset(out, 0, TG_CTRL_FRAME_LEN);
    out[OFF_VERSION] = TG_PROTO_VERSION;
    out[OFF_TYPE]    = TG_CTRL_FRAME_TYPE;
    /* reserved stays 0 */

    put_u32be(nonce,     ctrl_epoch);
    put_u64be(nonce + 4, ctrl->ctrl_seq);
    memcpy(out + OFF_NONCE, nonce, AEAD_NONCE_LEN);

    tg_control_serialize(ctrl, plain);

    rc = aead_encrypt(key, nonce,
                      out, TG_CTRL_AAD_LEN,
                      plain, TG_CONTROL_LEN,
                      out + OFF_CT, out + OFF_TAG);

    /* Do not leave a cleartext control message on the stack. */
    memset(plain, 0, sizeof(plain));

    if (rc != AEAD_OK)
        return TG_FRAME_ERR_BACKEND;

    return TG_FRAME_OK;
}

tg_frame_status_t tg_ctrl_peek_seq(const uint8_t in[TG_CTRL_FRAME_LEN],
                                   uint64_t *ctrl_seq_out)
{
    if (in == NULL || ctrl_seq_out == NULL)
        return TG_FRAME_ERR_PARAM;
    if (in[OFF_VERSION] != TG_PROTO_VERSION) return TG_FRAME_ERR_FORMAT;
    if (in[OFF_TYPE]    != TG_CTRL_FRAME_TYPE) return TG_FRAME_ERR_FORMAT;

    *ctrl_seq_out = get_u64be(in + OFF_NONCE + 4);
    return TG_FRAME_OK;
}

tg_frame_status_t tg_ctrl_open(const uint8_t key[TG_CTRL_KEY_LEN],
                               const uint8_t in[TG_CTRL_FRAME_LEN],
                               tg_control_t *ctrl,
                               uint32_t *ctrl_epoch_out)
{
    uint8_t plain[TG_CONTROL_LEN];
    uint8_t nonce[AEAD_NONCE_LEN];
    aead_status_t rc;
    uint64_t nonce_seq;

    if (key == NULL || in == NULL || ctrl == NULL)
        return TG_FRAME_ERR_PARAM;

    memset(ctrl, 0, sizeof(*ctrl));

    if (in[OFF_VERSION]  != TG_PROTO_VERSION)   return TG_FRAME_ERR_FORMAT;
    if (in[OFF_TYPE]     != TG_CTRL_FRAME_TYPE) return TG_FRAME_ERR_FORMAT;
    if (in[OFF_RESERVED] != 0 || in[OFF_RESERVED + 1] != 0)
        return TG_FRAME_ERR_FORMAT;

    memcpy(nonce, in + OFF_NONCE, AEAD_NONCE_LEN);

    rc = aead_decrypt(key, nonce,
                      in, TG_CTRL_AAD_LEN,
                      in + OFF_CT, TG_CONTROL_LEN,
                      in + OFF_TAG,
                      plain);

    if (rc == AEAD_ERR_AUTH_FAILED) return TG_FRAME_ERR_AUTH;
    if (rc != AEAD_OK)              return TG_FRAME_ERR_BACKEND;

    if (tg_control_parse(plain, ctrl) != 0) {
        memset(plain, 0, sizeof(plain));
        memset(ctrl, 0, sizeof(*ctrl));
        return TG_FRAME_ERR_FORMAT;
    }
    memset(plain, 0, sizeof(plain));

    /*
     * The nonce carried ctrl_seq in the clear so the receiver could
     * replay-check cheaply. Confirm it matches the authenticated copy: if an
     * attacker rewrote the cleartext half to slip past the replay guard, the
     * GCM tag would already have failed (the nonce is AAD), but checking
     * explicitly means the two can never silently diverge and turns any such
     * attempt into a distinct, loggable error.
     */
    nonce_seq = get_u64be(in + OFF_NONCE + 4);
    if (nonce_seq != ctrl->ctrl_seq) {
        memset(ctrl, 0, sizeof(*ctrl));
        return TG_FRAME_ERR_MISMATCH;
    }

    if (ctrl_epoch_out != NULL)
        *ctrl_epoch_out = get_u32be(in + OFF_NONCE);

    return TG_FRAME_OK;
}
