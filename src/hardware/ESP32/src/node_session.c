/*
 * node_session.c — leaf nonce discipline and PSK+DHE handshake.
 * See node_session.h for the protocol and its rationale.
 */
#include "node_session.h"
#include "node_storage.h"

#include "iiot_ecdhe.h"
#include "hal_port.h"
#include "kmac.h"
#include "rxcr_kmac_kdf.h"

#include <string.h>

static const uint8_t KDF_INFO[]     = "leaf-session/v1";
static const uint8_t KDF_ALGO[]     = "AES-GCM";
static const uint8_t CONFIRM_CTX[]  = "leaf-confirm/v1";

#define KDF_INFO_LEN    (sizeof(KDF_INFO) - 1)
#define KDF_ALGO_LEN    (sizeof(KDF_ALGO) - 1)
#define CONFIRM_CTX_LEN (sizeof(CONFIRM_CTX) - 1)

/* ── nonce guard ─────────────────────────────────────────────────────────── */

node_session_status_t node_nonce_boot(node_nonce_guard_t *g)
{
    uint32_t epoch = 0;
    storage_status_t rc;

    if (g == NULL) return NODE_SESSION_ERR_PARAM;

    rc = node_storage_get_u32(NODE_EPOCH_KEY, &epoch);
    if (rc == STORAGE_NOT_FOUND) {
        epoch = 0;                 /* first ever boot */
    } else if (rc != STORAGE_OK) {
        return NODE_SESSION_ERR_STORAGE;
    }

    epoch++;

    /*
     * Commit BEFORE handing the epoch out. If power drops between the store
     * and the first encryption, the next boot resumes from the committed
     * value and simply skips an epoch. The reverse order would let a crash
     * hand out an epoch that was never persisted, and the next boot would
     * reissue it — reusing every nonce under it.
     */
    if (node_storage_set_u32(NODE_EPOCH_KEY, epoch) != STORAGE_OK)
        return NODE_SESSION_ERR_STORAGE;

    g->key_epoch = epoch;
    g->next_seq  = 0;
    g->exhausted = 0;
    return NODE_SESSION_OK;
}

node_session_status_t node_nonce_next(node_nonce_guard_t *g, uint64_t *seq_out)
{
    if (g == NULL || seq_out == NULL) return NODE_SESSION_ERR_PARAM;

    if (g->exhausted || g->next_seq >= NODE_SEQ_MAX) {
        g->exhausted = 1;
        return NODE_SESSION_EXHAUSTED;
    }

    *seq_out = g->next_seq++;
    if (g->next_seq >= NODE_SEQ_MAX) g->exhausted = 1;
    return NODE_SESSION_OK;
}

node_session_status_t node_nonce_rekey(node_nonce_guard_t *g)
{
    return node_nonce_boot(g);   /* same discipline: bump, commit, reset seq */
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/*
 * Derive the session key from the two handshake messages.
 *
 * transcript = SHA3-256(HELLO || HELLO_ACK) — both fixed length, so plain
 * concatenation is unambiguous.
 * ikm = dh || psk  — DH first, so the PSK cannot dominate if the DH is weak.
 */
static node_session_status_t derive_session(const uint8_t *hello,
                                            const uint8_t *ack,
                                            const uint8_t dh[32],
                                            const uint8_t psk[NODE_PSK_LEN],
                                            uint16_t endpoint_id,
                                            node_session_t *session)
{
    uint8_t tr_input[NODE_HELLO_LEN + NODE_HELLO_ACK_LEN];
    uint8_t transcript[32];
    uint8_t ikm[64];
    uint8_t node_id[2];
    node_session_status_t st = NODE_SESSION_OK;

    memcpy(tr_input, hello, NODE_HELLO_LEN);
    memcpy(tr_input + NODE_HELLO_LEN, ack, NODE_HELLO_ACK_LEN);
    sha3_256(tr_input, sizeof(tr_input), transcript);

    memcpy(ikm, dh, 32);
    memcpy(ikm + 32, psk, NODE_PSK_LEN);

    put_u16(node_id, endpoint_id);

    if (rxcr_kdf_derive(ikm, sizeof(ikm),
                        transcript, sizeof(transcript),
                        KDF_INFO, KDF_INFO_LEN,
                        node_id, sizeof(node_id),
                        KDF_ALGO, KDF_ALGO_LEN,
                        0,
                        session->session_key, NODE_SESSION_KEY_LEN) != RXCR_KDF_OK) {
        st = NODE_SESSION_ERR_CRYPTO;
        goto done;
    }

    memcpy(session->transcript, transcript, sizeof(transcript));
    session->endpoint_id = endpoint_id;
    session->key_epoch   = get_u32(hello + 4);
    session->established = 1;

done:
    hal_secure_wipe(ikm, sizeof(ikm));
    hal_secure_wipe(tr_input, sizeof(tr_input));
    return st;
}

static void confirm_tag(const node_session_t *session, uint8_t tag[16])
{
    kmacxof256(session->session_key, NODE_SESSION_KEY_LEN,
               session->transcript, sizeof(session->transcript),
               CONFIRM_CTX, CONFIRM_CTX_LEN,
               tag, 16);
}

/* Constant-time equality. The tag is a MAC, so an early-exit memcmp would
 * leak how many bytes matched and let it be forged a byte at a time. */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t  i;

    for (i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ── leaf role ───────────────────────────────────────────────────────────── */

node_session_status_t node_handshake_start(node_handshake_ctx_t *ctx,
                                           uint16_t endpoint_id,
                                           uint32_t key_epoch,
                                           uint8_t out[NODE_HELLO_LEN])
{
    uint8_t leaf_pub[NODE_PUBKEY_LEN];

    if (ctx == NULL || out == NULL) return NODE_SESSION_ERR_PARAM;

    iiot_ecdhe_generate_keypair(leaf_pub, ctx->leaf_sk);

    out[0] = 0x01;                       /* LEAF_PROTO_VERSION */
    out[1] = NODE_MSG_HELLO;
    put_u16(out + 2, endpoint_id);
    put_u32(out + 4, key_epoch);
    memcpy(out + 8, leaf_pub, NODE_PUBKEY_LEN);

    /* A fresh nonce per handshake, so a replayed HELLO cannot reproduce an
     * earlier transcript and therefore cannot reproduce an earlier key. */
    hal_trng_fill(out + 40, NODE_HS_NONCE_LEN);

    memcpy(ctx->hello, out, NODE_HELLO_LEN);
    return NODE_SESSION_OK;
}

node_session_status_t node_handshake_finish(node_handshake_ctx_t *ctx,
                                            const uint8_t psk[NODE_PSK_LEN],
                                            const uint8_t ack[NODE_HELLO_ACK_LEN],
                                            node_session_t *session,
                                            uint8_t out[NODE_CONFIRM_LEN])
{
    uint8_t dh[32];
    uint8_t tag[16];
    node_session_status_t st;

    if (ctx == NULL || psk == NULL || ack == NULL ||
        session == NULL || out == NULL)
        return NODE_SESSION_ERR_PARAM;

    if (ack[0] != 0x01 || ack[1] != NODE_MSG_HELLO_ACK) {
        st = NODE_SESSION_ERR_FORMAT;
        goto done;
    }

    /* The gateway must be answering the handshake we actually started. */
    if (get_u16(ack + 2) != get_u16(ctx->hello + 2)) {
        st = NODE_SESSION_ERR_PEER;
        goto done;
    }

    if (iiot_ecdhe_compute_shared_secret(dh, ctx->leaf_sk, ack + 8) != IIOT_ECDHE_OK) {
        /* Low-order gateway public key: the DH output carries no secret and
         * the peer knows it. Abort rather than derive from it. */
        st = NODE_SESSION_ERR_PEER;
        goto done;
    }

    st = derive_session(ctx->hello, ack, dh, psk, get_u16(ctx->hello + 2), session);
    if (st != NODE_SESSION_OK) goto done;

    confirm_tag(session, tag);
    out[0] = 0x01;
    out[1] = NODE_MSG_CONFIRM;
    put_u16(out + 2, session->endpoint_id);
    put_u32(out + 4, 0);
    memcpy(out + 8, tag, 16);

done:
    /*
     * The ephemeral private key must not survive this call on any path.
     * Keeping it would make every past session decryptable by whoever later
     * reads the node's memory, which is exactly the forward secrecy the
     * ephemeral keypair exists to provide.
     */
    hal_secure_wipe(dh, sizeof(dh));
    hal_secure_wipe(ctx->leaf_sk, sizeof(ctx->leaf_sk));
    return st;
}

/* ── gateway role ────────────────────────────────────────────────────────── */

node_session_status_t node_handshake_respond(const uint8_t psk[NODE_PSK_LEN],
                                             const uint8_t hello[NODE_HELLO_LEN],
                                             node_session_t *session,
                                             uint8_t out[NODE_HELLO_ACK_LEN])
{
    uint8_t gw_pub[NODE_PUBKEY_LEN], gw_sk[NODE_PUBKEY_LEN];
    uint8_t dh[32];
    node_session_status_t st;

    if (psk == NULL || hello == NULL || session == NULL || out == NULL)
        return NODE_SESSION_ERR_PARAM;

    if (hello[0] != 0x01 || hello[1] != NODE_MSG_HELLO)
        return NODE_SESSION_ERR_FORMAT;

    iiot_ecdhe_generate_keypair(gw_pub, gw_sk);

    out[0] = 0x01;
    out[1] = NODE_MSG_HELLO_ACK;
    put_u16(out + 2, get_u16(hello + 2));   /* echo the endpoint id */
    put_u32(out + 4, 0);
    memcpy(out + 8, gw_pub, NODE_PUBKEY_LEN);
    hal_trng_fill(out + 40, NODE_HS_NONCE_LEN);

    if (iiot_ecdhe_compute_shared_secret(dh, gw_sk, hello + 8) != IIOT_ECDHE_OK) {
        st = NODE_SESSION_ERR_PEER;
        goto done;
    }

    st = derive_session(hello, out, dh, psk, get_u16(hello + 2), session);

done:
    hal_secure_wipe(dh, sizeof(dh));
    hal_secure_wipe(gw_sk, sizeof(gw_sk));
    return st;
}

node_session_status_t node_handshake_verify_confirm(
        const node_session_t *session,
        const uint8_t confirm[NODE_CONFIRM_LEN])
{
    uint8_t expect[16];

    if (session == NULL || confirm == NULL) return NODE_SESSION_ERR_PARAM;
    if (!session->established)              return NODE_SESSION_ERR_PARAM;

    if (confirm[0] != 0x01 || confirm[1] != NODE_MSG_CONFIRM)
        return NODE_SESSION_ERR_FORMAT;
    if (get_u16(confirm + 2) != session->endpoint_id)
        return NODE_SESSION_ERR_PEER;

    confirm_tag(session, expect);
    if (!ct_equal(expect, confirm + 8, 16))
        return NODE_SESSION_ERR_CONFIRM;

    return NODE_SESSION_OK;
}

node_session_status_t node_session_derive_for_test(
        const uint8_t hello[NODE_HELLO_LEN],
        const uint8_t ack[NODE_HELLO_ACK_LEN],
        const uint8_t dh[32],
        const uint8_t psk[NODE_PSK_LEN],
        node_session_t *session)
{
    if (hello == NULL || ack == NULL || dh == NULL ||
        psk == NULL || session == NULL)
        return NODE_SESSION_ERR_PARAM;

    return derive_session(hello, ack, dh, psk, get_u16(hello + 2), session);
}

void node_session_confirm_tag_for_test(const node_session_t *session,
                                       uint8_t tag[16])
{
    confirm_tag(session, tag);
}

void node_session_wipe(node_session_t *session)
{
    if (session == NULL) return;
    hal_secure_wipe(session->session_key, sizeof(session->session_key));
    hal_secure_wipe(session->transcript, sizeof(session->transcript));
    session->established = 0;
}
