/*
 * posture_kat_dump.c — emit sealed control frames and a posture state trace.
 *
 * Paired with test_posture.py. Two things are pinned:
 *
 *   1. Frame bytes. The nonce is derived, not random, so tg_ctrl_seal() is
 *      deterministic and C and Python output can be compared byte for byte.
 *   2. State machine behaviour. The same scenarios run on both sides and the
 *      traces must match, so the lease/shield semantics cannot drift between
 *      the gateway (C) and anything reimplemented in Python.
 *
 * Build: see tools/build_tests.bat
 */
#include <stdio.h>
#include <string.h>

#include "posture_frame.h"
#include "protocol.h"
#include "aead_iface.h"

static void put_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    printf("%s ", label);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static uint8_t g_key[TG_CTRL_KEY_LEN];

static tg_control_t mk(uint8_t posture, uint8_t directive, uint32_t node_mask,
                       uint32_t lease_ms, uint32_t min_hold_ms,
                       uint64_t ctrl_seq, uint64_t issued_ms)
{
    tg_control_t c;
    memset(&c, 0, sizeof(c));
    c.version     = TG_PROTO_VERSION;
    c.posture     = posture;
    c.directive   = directive;
    c.reserved    = 0;
    c.node_mask   = node_mask;
    c.lease_ms    = lease_ms;
    c.min_hold_ms = min_hold_ms;
    c.ctrl_seq    = ctrl_seq;
    c.issued_ms   = issued_ms;
    return c;
}

static void dump_frame(const char *label, uint32_t epoch, tg_control_t c)
{
    uint8_t frame[TG_CTRL_FRAME_LEN];
    if (tg_ctrl_seal(g_key, epoch, &c, frame) != TG_FRAME_OK) {
        printf("%s SEAL_FAILED\n", label);
        return;
    }
    put_hex(label, frame, TG_CTRL_FRAME_LEN);
}

/* One line of posture state, so the Python side can diff the whole trace. */
static void trace(const char *tag, const tg_posture_state_t *s, uint64_t now)
{
    printf("trace %-22s t=%-6llu posture=%u floor=%u advised=%u mask=%08x lease_exp=%llu\n",
           tag, (unsigned long long)now,
           (unsigned)s->posture, (unsigned)s->directive_floor,
           (unsigned)s->advised_posture, s->node_mask,
           (unsigned long long)s->lease_expires_ms);
}

int main(void)
{
    size_t i;
    for (i = 0; i < sizeof(g_key); i++) g_key[i] = (uint8_t)(i * 13 + 7);

    aead_init();

    /* ── sealed frame vectors ──────────────────────────────────────────── */
    dump_frame("frame_advise",
               1, mk(TG_POSTURE_SUSPICIOUS, TG_DIRECTIVE_ADVISE,
                     0x00000000u, 3000, 5000, 1, 1757664000000ULL));
    dump_frame("frame_enforce",
               1, mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_ENFORCE,
                     0x00000000u, 3000, 5000, 2, 1757664001000ULL));
    dump_frame("frame_quarantine",
               1, mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_QUARANTINE,
                     0x00000028u, 3000, 5000, 3, 1757664002000ULL));
    dump_frame("frame_epoch7",
               7, mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE,
                     0x00000000u, 1000, 0, 99, 1757664003000ULL));

    /* ── scenario A: lease lapse escalates one level at a time ─────────── */
    {
        tg_posture_state_t s;
        uint64_t t = 10000;
        tg_control_t c = mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE,
                            0, 3000, 0, 1, t);

        tg_posture_init(&s, t);
        trace("A.init", &s, t);

        tg_posture_apply(&s, &c, t, 60000);
        trace("A.renewed", &s, t);

        t = 12000; tg_posture_tick(&s, t);
        trace("A.before_expiry", &s, t);

        t = 13000; tg_posture_tick(&s, t);
        trace("A.expiry1", &s, t);

        t = 16000; tg_posture_tick(&s, t);
        trace("A.expiry2", &s, t);

        t = 19000; tg_posture_tick(&s, t);
        trace("A.expiry3_capped", &s, t);
    }

    /* ── scenario B: ENFORCE floor blocks de-escalation ────────────────── */
    {
        tg_posture_state_t s;
        uint64_t t = 20000;
        tg_control_t c = mk(TG_POSTURE_SUSPICIOUS, TG_DIRECTIVE_ENFORCE,
                            0, 5000, 0, 1, t);

        tg_posture_init(&s, t);
        tg_posture_apply(&s, &c, t, 60000);
        trace("B.enforced", &s, t);

        /* The agent asks to stand down; the floor refuses. */
        tg_posture_request(&s, TG_POSTURE_NORMAL, t);
        trace("B.denied_normal", &s, t);

        /* The agent may still escalate above the floor. */
        tg_posture_request(&s, TG_POSTURE_ANOMALY, t);
        trace("B.escalated", &s, t);

        /* And back down to the floor, but no further. */
        tg_posture_request(&s, TG_POSTURE_NORMAL, t);
        trace("B.back_to_floor", &s, t);
    }

    /* ── scenario C: min_hold blocks rapid de-escalation ───────────────── */
    {
        tg_posture_state_t s;
        uint64_t t = 30000;
        tg_control_t c = mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE,
                            0, 10000, 5000, 1, t);

        tg_posture_init(&s, t);
        tg_posture_apply(&s, &c, t, 60000);

        tg_posture_request(&s, TG_POSTURE_ANOMALY, t);
        trace("C.escalated", &s, t);

        t = 32000;
        tg_posture_request(&s, TG_POSTURE_NORMAL, t);
        trace("C.too_soon", &s, t);

        t = 36000;
        tg_posture_request(&s, TG_POSTURE_NORMAL, t);
        trace("C.min_hold_elapsed", &s, t);
    }

    /* ── scenario D: quarantine accumulates, release is explicit ───────── */
    {
        tg_posture_state_t s;
        uint64_t t = 40000;
        tg_control_t q1 = mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_QUARANTINE,
                             (1u << 3), 5000, 0, 1, t);
        tg_control_t q2 = mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_QUARANTINE,
                             (1u << 5), 5000, 0, 2, t);

        tg_posture_init(&s, t);
        tg_posture_apply(&s, &q1, t, 60000);
        trace("D.quarantine_3", &s, t);

        tg_posture_apply(&s, &q2, t, 60000);
        trace("D.quarantine_3_5", &s, t);

        printf("check D.node3_quarantined=%d\n", tg_posture_is_quarantined(&s, 3));
        printf("check D.node4_quarantined=%d\n", tg_posture_is_quarantined(&s, 4));
        printf("check D.node5_quarantined=%d\n", tg_posture_is_quarantined(&s, 5));

        tg_posture_release(&s, 3);
        trace("D.released_3", &s, t);
    }

    /* ── scenario E: replay and staleness rejected ─────────────────────── */
    {
        tg_posture_state_t s;
        uint64_t t = 50000;
        tg_control_t c1 = mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE, 0, 3000, 0, 10, t);
        tg_control_t old = mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE, 0, 3000, 0, 9, t);
        tg_control_t same = mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_ENFORCE, 0, 3000, 0, 10, t);
        tg_control_t stale = mk(TG_POSTURE_NORMAL, TG_DIRECTIVE_ADVISE, 0, 3000, 0, 11, 1);

        tg_posture_init(&s, t);
        printf("check E.first=%d\n",  (int)tg_posture_apply(&s, &c1, t, 60000));
        printf("check E.older=%d\n",  (int)tg_posture_apply(&s, &old, t, 60000));
        printf("check E.equal=%d\n",  (int)tg_posture_apply(&s, &same, t, 60000));
        printf("check E.stale=%d\n",  (int)tg_posture_apply(&s, &stale, t, 60000));
        trace("E.final", &s, t);
    }

    /* ── scenario F: round trip through seal/open ──────────────────────── */
    {
        uint8_t frame[TG_CTRL_FRAME_LEN];
        tg_control_t out;
        uint32_t epoch = 0;
        uint64_t peeked = 0;
        tg_control_t c = mk(TG_POSTURE_ANOMALY, TG_DIRECTIVE_QUARANTINE,
                            0x0000002Au, 4000, 250, 4242, 1757664009000ULL);

        tg_ctrl_seal(g_key, 5, &c, frame);
        printf("check F.peek=%d\n", (int)tg_ctrl_peek_seq(frame, &peeked));
        printf("check F.peek_seq=%llu\n", (unsigned long long)peeked);
        printf("check F.open=%d\n", (int)tg_ctrl_open(g_key, frame, &out, &epoch));
        printf("check F.epoch=%u\n", epoch);
        printf("check F.mask=%08x\n", out.node_mask);
        printf("check F.seq=%llu\n", (unsigned long long)out.ctrl_seq);

        /* Flip one ciphertext bit: must fail authentication. */
        frame[20] ^= 0x01;
        printf("check F.tampered=%d\n", (int)tg_ctrl_open(g_key, frame, &out, &epoch));
        frame[20] ^= 0x01;

        /* Flip a bit in the cleartext nonce: the nonce is AAD, so this must
         * also fail rather than letting an attacker shift the replay window. */
        frame[10] ^= 0x01;
        printf("check F.nonce_tampered=%d\n", (int)tg_ctrl_open(g_key, frame, &out, &epoch));
    }

    return 0;
}
