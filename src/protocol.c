/*
 * protocol.c — frame serialisation, nonce derivation, and the send/receive
 * guards described in include/protocol.h.
 *
 * All multi-byte fields are big-endian on the wire so the C gateway and the
 * Python server agree without either side depending on host byte order. (The
 * previous chaos context used memcpy() over a native uint32/uint64, which was
 * silently little-endian-only.)
 */
#include "protocol.h"
#include <string.h>

/* ── big-endian helpers ──────────────────────────────────────────────────── */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/* ── telemetry header ────────────────────────────────────────────────────── */

void tg_header_serialize(const tg_header_t *h, uint8_t out[TG_HEADER_LEN])
{
    out[0] = h->version;
    out[1] = h->posture;
    put_u16(out + 2,  h->node_id);
    put_u32(out + 4,  h->key_epoch);
    put_u64(out + 8,  h->seq);
    put_u64(out + 16, h->timestamp_ms);
}

int tg_header_parse(const uint8_t in[TG_HEADER_LEN], tg_header_t *h)
{
    h->version      = in[0];
    h->posture      = in[1];
    h->node_id      = get_u16(in + 2);
    h->key_epoch    = get_u32(in + 4);
    h->seq          = get_u64(in + 8);
    h->timestamp_ms = get_u64(in + 16);

    if (h->version != TG_PROTO_VERSION)      return -1;
    if (h->posture >= TG_POSTURE__COUNT)     return -1;
    return 0;
}

void tg_nonce_derive(const tg_header_t *h, uint8_t nonce[TG_NONCE_LEN])
{
    put_u32(nonce,     h->key_epoch);
    put_u64(nonce + 4, h->seq);
}

/* ── send-side nonce guard ───────────────────────────────────────────────── */

void tg_nonce_guard_init(tg_nonce_guard_t *g, uint32_t key_epoch)
{
    g->key_epoch = key_epoch;
    g->next_seq  = 0;
    g->exhausted = 0;
}

int tg_nonce_next(tg_nonce_guard_t *g, uint64_t *seq_out)
{
    if (g->exhausted || g->next_seq >= TG_SEQ_MAX) {
        g->exhausted = 1;
        return -1;
    }
    *seq_out = g->next_seq++;
    if (g->next_seq >= TG_SEQ_MAX)
        g->exhausted = 1;
    return 0;
}

/* ── receive-side replay guard ───────────────────────────────────────────── */

void tg_replay_guard_init(tg_replay_guard_t *g)
{
    g->key_epoch = 0;
    g->last_seq  = 0;
    g->seen      = 0;
}

int tg_replay_check(tg_replay_guard_t *g, const tg_header_t *h)
{
    if (!g->seen) {
        g->key_epoch = h->key_epoch;
        g->last_seq  = h->seq;
        g->seen      = 1;
        return 0;
    }

    if (h->key_epoch < g->key_epoch)
        return -1;                       /* epoch regression — rolled back */

    if (h->key_epoch > g->key_epoch) {   /* legitimate rekey: seq restarts */
        g->key_epoch = h->key_epoch;
        g->last_seq  = h->seq;
        return 0;
    }

    if (h->seq <= g->last_seq)
        return -1;                       /* replay or reorder */

    g->last_seq = h->seq;
    return 0;
}

/* ── posture control message ─────────────────────────────────────────────── */

void tg_control_serialize(const tg_control_t *c, uint8_t out[TG_CONTROL_LEN])
{
    out[0] = c->version;
    out[1] = c->posture;
    out[2] = c->directive;
    out[3] = c->reserved;
    put_u32(out + 4,  c->node_mask);
    put_u32(out + 8,  c->lease_ms);
    put_u32(out + 12, c->min_hold_ms);
    put_u64(out + 16, c->ctrl_seq);
    put_u64(out + 24, c->issued_ms);
}

int tg_control_parse(const uint8_t in[TG_CONTROL_LEN], tg_control_t *c)
{
    c->version     = in[0];
    c->posture     = in[1];
    c->directive   = in[2];
    c->reserved    = in[3];
    c->node_mask   = get_u32(in + 4);
    c->lease_ms    = get_u32(in + 8);
    c->min_hold_ms = get_u32(in + 12);
    c->ctrl_seq    = get_u64(in + 16);
    c->issued_ms   = get_u64(in + 24);

    if (c->version != TG_PROTO_VERSION)      return -1;
    if (c->posture >= TG_POSTURE__COUNT)     return -1;
    if (c->directive >= TG_DIRECTIVE__COUNT) return -1;

    /* Reject a non-zero reserved byte rather than ignoring it. A future
     * version may give it meaning, and silently accepting it now would let an
     * old gateway apply a message whose semantics it does not understand. */
    if (c->reserved != 0)                    return -1;
    return 0;
}

/* ── gateway-side posture state machine ──────────────────────────────────── */

void tg_posture_init(tg_posture_state_t *s, uint64_t now_ms)
{
    s->posture          = TG_POSTURE_NORMAL;
    s->directive_floor  = TG_POSTURE_NORMAL;
    s->advised_posture  = TG_POSTURE_NORMAL;
    s->seen_ctrl        = 0;
    s->node_mask        = 0;
    s->lease_ms         = 0;
    s->min_hold_ms      = 0;
    s->lease_expires_ms = 0;
    s->posture_since_ms = now_ms;
    s->last_ctrl_seq    = 0;
}

void tg_posture_grace(tg_posture_state_t *s, uint32_t grace_ms, uint64_t now_ms)
{
    s->lease_ms         = grace_ms;
    s->lease_expires_ms = now_ms + grace_ms;
}

static void set_posture(tg_posture_state_t *s, uint8_t posture, uint64_t now_ms)
{
    if (s->posture != posture) {
        s->posture          = posture;
        s->posture_since_ms = now_ms;
    }
}

tg_ctrl_status_t tg_posture_apply(tg_posture_state_t *s,
                                  const tg_control_t *c,
                                  uint64_t now_ms,
                                  uint64_t max_skew_ms)
{
    uint64_t skew;

    if (c->version != TG_PROTO_VERSION)      return TG_CTRL_ERR_PARSE;
    if (c->posture >= TG_POSTURE__COUNT)     return TG_CTRL_ERR_PARSE;
    if (c->directive >= TG_DIRECTIVE__COUNT) return TG_CTRL_ERR_PARSE;

    /*
     * Strictly increasing. Equality is a replay, not a duplicate to tolerate:
     * the server never reuses a ctrl_seq, so a repeat means someone else sent
     * it. This is what stops a captured NORMAL suppressing a live response.
     */
    if (s->seen_ctrl && c->ctrl_seq <= s->last_ctrl_seq)
        return TG_CTRL_ERR_REPLAY;

    skew = (now_ms > c->issued_ms) ? (now_ms - c->issued_ms)
                                   : (c->issued_ms - now_ms);
    if (skew > max_skew_ms)
        return TG_CTRL_ERR_STALE;

    s->last_ctrl_seq = c->ctrl_seq;
    s->seen_ctrl     = 1;

    /* Renew the lease. Every valid message does this, whatever its directive
     * -- the lease proves the server is alive and reachable, independently of
     * what it is asking for. */
    s->lease_ms         = c->lease_ms;
    s->lease_expires_ms = now_ms + c->lease_ms;
    s->min_hold_ms      = c->min_hold_ms;

    switch (c->directive) {
    case TG_DIRECTIVE_ADVISE:
        /* Observation only. Recorded for the agent's state vector; posture is
         * left to policy via tg_posture_request(). */
        s->advised_posture = c->posture;
        break;

    case TG_DIRECTIVE_ENFORCE:
        /* A floor, applied immediately if we are currently below it. The
         * agent may still escalate further, never below. */
        s->directive_floor = c->posture;
        s->advised_posture = c->posture;
        if (s->posture < c->posture)
            set_posture(s, c->posture, now_ms);
        break;

    case TG_DIRECTIVE_QUARANTINE:
        /*
         * Mandatory. Accumulate rather than replace the mask: two overlapping
         * detections must not clear each other's nodes. Release is explicit,
         * via tg_posture_release() after triage.
         */
        s->node_mask      |= c->node_mask;
        s->directive_floor = TG_POSTURE_ANOMALY;
        s->advised_posture = TG_POSTURE_ANOMALY;
        set_posture(s, TG_POSTURE_ANOMALY, now_ms);
        break;

    default:
        return TG_CTRL_ERR_PARSE;
    }

    return TG_CTRL_OK;
}

int tg_posture_tick(tg_posture_state_t *s, uint64_t now_ms)
{
    uint8_t next;

    if (s->lease_expires_ms == 0 || now_ms < s->lease_expires_ms)
        return 0;

    /*
     * Lease lapsed. Escalate one level and re-arm for another lease_ms, so a
     * dead control channel walks NORMAL -> SUSPICIOUS -> ANOMALY over two
     * lease periods rather than slamming to ANOMALY on a single lost packet.
     *
     * Deliberately does NOT touch node_mask: auto-quarantine on lease expiry
     * would turn "jam the control channel" into a remote denial of service.
     */
    if (s->posture >= TG_POSTURE_ANOMALY) {
        s->lease_expires_ms = now_ms + s->lease_ms;   /* already at the top */
        return 0;
    }

    next = (uint8_t)(s->posture + 1);
    set_posture(s, next, now_ms);

    /* Re-arm. If lease_ms is 0 (no lease was ever granted) fall back to a
     * single escalation and then stop, rather than spinning every tick. */
    s->lease_expires_ms = (s->lease_ms != 0) ? (now_ms + s->lease_ms) : 0;
    return 1;
}

uint8_t tg_posture_request(tg_posture_state_t *s, uint8_t desired, uint64_t now_ms)
{
    if (desired >= TG_POSTURE__COUNT)
        return s->posture;                 /* ignore nonsense from policy */

    /* Escalation is always allowed and always immediate. */
    if (desired > s->posture) {
        set_posture(s, desired, now_ms);
        return s->posture;
    }

    if (desired == s->posture)
        return s->posture;

    /* ── de-escalation, the direction that needs guarding ── */

    /* Never below an ENFORCE floor. */
    if (desired < s->directive_floor)
        desired = s->directive_floor;

    /* Not before min_hold_ms has elapsed. Bounds how fast an attacker who can
     * drop control messages is able to flap the system, and stops a policy
     * that has learned to oscillate. */
    if (now_ms - s->posture_since_ms < (uint64_t)s->min_hold_ms)
        return s->posture;

    if (desired < s->posture)
        set_posture(s, desired, now_ms);

    return s->posture;
}

uint8_t tg_posture_effective(const tg_posture_state_t *s)
{
    return s->posture;
}

int tg_posture_is_quarantined(const tg_posture_state_t *s, uint16_t node_id)
{
    if (node_id >= 32) return 0;           /* mask covers 32 nodes */
    return (s->node_mask & (1u << node_id)) != 0;
}

void tg_posture_release(tg_posture_state_t *s, uint16_t node_id)
{
    if (node_id >= 32) return;
    s->node_mask &= ~(1u << node_id);
}
