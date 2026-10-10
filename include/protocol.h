/*
 * protocol.h — wire frame for the gateway -> main-server telemetry link.
 *
 * Layer order on this link (confirmed design): ACCM sits OUTSIDE AES-GCM.
 *
 *     plaintext
 *       -> AES-256-GCM (key = session key, nonce = derived below,
 *                       AAD  = the serialised 24-byte header)
 *       -> ct || tag
 *       -> ACCM chaotic mask (XOR keystream)
 *       -> wire:  header(24, cleartext) || masked(ct || tag)
 *
 * Why the header travels in the clear
 * -----------------------------------
 * The receiver must reproduce the ACCM keystream before it can unmask, so
 * every parameter that selects that keystream has to be readable first. The
 * header is therefore cleartext but NOT unauthenticated: it is fed to
 * AES-GCM as additional authenticated data, so a single flipped bit in
 * `posture`, `key_epoch`, `seq` or `timestamp_ms` fails the GCM tag check.
 *
 * This is the fix for the old design, where the anomaly flag was implicit
 * shared state. Previously, sender and receiver disagreeing about epsilon
 * produced a *silent* garbage plaintext: GCM was applied underneath the mask,
 * so its tag still verified against whatever the unmask produced, and the
 * server had no signal that it had just decoded noise -- during an attack,
 * which is exactly when the flag flips. Now the posture is explicit and
 * authenticated, and a mismatch is a hard, loud GCM failure.
 *
 * The tradeoff is honest and deliberate: the posture transition IS visible on
 * the wire. An observer can see that the system changed state. What they
 * cannot do is forge it, replay it, or predict the resulting keystream. The
 * defensible claim is unpredictability and unforgeability, not steganography.
 *
 * Nonce construction
 * ------------------
 *     nonce[12] = key_epoch (4 bytes BE) || seq (8 bytes BE)
 *
 * Deterministic rather than random, so GCM nonce uniqueness is a structural
 * property instead of an assumption about an RNG or about what the DQN policy
 * decides to do. `key_epoch` increments on every session-key install AND on
 * every gateway boot (it is persisted), so a reboot can never replay a
 * (key, nonce) pair even if the same session key is reloaded from storage.
 * `tg_nonce_guard_t` enforces strict monotonicity of `seq` within an epoch
 * and refuses to emit past TG_SEQ_MAX.
 */
#ifndef TG_PROTOCOL_H
#define TG_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define TG_PROTO_VERSION   0x02

#define TG_HEADER_LEN      24
#define TG_NONCE_LEN       12
#define TG_GCM_TAG_LEN     16
#define TG_TAIL_LEN         8    /* ACCM inter-packet chaining bytes */

/*
 * Security posture. Mirrors the three terminal states of the workflow
 * diagram (NORMAL / SUSPICIOUS / ANOMALY) and selects the ACCM coupling
 * strength epsilon. Set by the gateway, driven by an authenticated control
 * message from the server's LSTM (see tg_control_t).
 */
typedef enum {
    TG_POSTURE_NORMAL     = 0,
    TG_POSTURE_SUSPICIOUS = 1,
    TG_POSTURE_ANOMALY    = 2,
    TG_POSTURE__COUNT
} tg_posture_t;

/* Hard ceiling on packets per (key_epoch). Far below the 2^32 GCM limit for
 * a 96-bit deterministic nonce; the guard forces a rekey well before any
 * birthday concern. At 10 Hz this is ~3.4 years of continuous telemetry. */
#define TG_SEQ_MAX  ((uint64_t)1 << 30)

typedef struct {
    uint8_t  version;        /* TG_PROTO_VERSION                          */
    uint8_t  posture;        /* tg_posture_t                              */
    uint16_t node_id;        /* logical source node                       */
    uint32_t key_epoch;      /* session-key generation; bumped on rekey   */
    uint64_t seq;            /* packet counter, unique within key_epoch   */
    uint64_t timestamp_ms;   /* sender clock; freshness + stream entropy  */
} tg_header_t;

/* Serialise to 24 bytes, big-endian. This exact byte string is both the
 * AES-GCM AAD and part of the ACCM keystream derivation input. */
void tg_header_serialize(const tg_header_t *h, uint8_t out[TG_HEADER_LEN]);

/* Parse and validate. Returns 0 on success, -1 if the version is unknown or
 * the posture is out of range. */
int  tg_header_parse(const uint8_t in[TG_HEADER_LEN], tg_header_t *h);

/* nonce = key_epoch(4 BE) || seq(8 BE) */
void tg_nonce_derive(const tg_header_t *h, uint8_t nonce[TG_NONCE_LEN]);

/*
 * Send-side nonce guard. One per (session key, key_epoch).
 *
 * The invariant "never reuse (key, nonce)" must not be something the DQN can
 * learn its way out of, so it is enforced here, below the policy layer: the
 * agent may choose *when* to rotate, but it cannot choose to emit a duplicate
 * nonce. tg_nonce_next() is the only sanctioned way to obtain a seq.
 */
typedef struct {
    uint32_t key_epoch;
    uint64_t next_seq;
    int      exhausted;      /* set once TG_SEQ_MAX is hit; rekey required */
} tg_nonce_guard_t;

void tg_nonce_guard_init(tg_nonce_guard_t *g, uint32_t key_epoch);

/*
 * Claim the next sequence number. Returns 0 and writes *seq_out on success.
 * Returns -1 when the epoch is exhausted -- the caller MUST rekey (install a
 * new session key, bump key_epoch) rather than continue.
 */
int  tg_nonce_next(tg_nonce_guard_t *g, uint64_t *seq_out);

/*
 * Receive-side replay guard. Rejects any (key_epoch, seq) not strictly ahead
 * of what has already been accepted, and rejects epoch regression.
 * Returns 0 if the header is acceptable, -1 otherwise.
 *
 * This is a strict-ordering window suitable for the TCP gateway->server link.
 * It would need a sliding bitmap window if this link ever moves to UDP/DTLS.
 */
typedef struct {
    uint32_t key_epoch;
    uint64_t last_seq;
    int      seen;
} tg_replay_guard_t;

void tg_replay_guard_init(tg_replay_guard_t *g);
int  tg_replay_check(tg_replay_guard_t *g, const tg_header_t *h);

/* ═══════════════════════════════════════════════════════════════════════════
 * Server -> gateway posture control
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The problem this solves
 * -----------------------
 * The LSTM runs on the server; the posture it decides has to reach the
 * gateway. You cannot guarantee delivery of an alert over a network an
 * attacker may control: if neutralisation depends on a message arriving, an
 * attacker who drops it wins, and retries only make suppression noisier.
 *
 * So the control plane is inverted into a LEASE. The server continuously
 * issues authenticated "posture is X, valid for lease_ms" tokens. The gateway
 * holds its posture only while the lease is unexpired; when it lapses, the
 * gateway escalates on its own.
 *
 *      alert arrives          -> immediate escalation (push, fast)
 *      alert dropped          -> lease expires -> escalate anyway
 *      server DDoSed / killed -> lease expires -> escalate anyway
 *      channel jammed         -> lease expires -> escalate anyway
 *
 * Blocking the channel now CAUSES escalation instead of suppressing it. Push
 * gives speed; the lease gives the guarantee. That matters directly for the
 * Ukraine case study, whose phase 5 was a DDoS to blind the operators.
 *
 * Renewals piggyback on the telemetry response, so the cadence follows the
 * aggregation window with no extra timer or connection, and a server that
 * stops *responding* decays the lease exactly like one that stops *renewing*.
 *
 * Lease expiry escalates posture but NEVER auto-quarantines. Otherwise
 * jamming the control channel would become a remote denial of service --
 * precisely the attack being defended against. Escalation is nearly free
 * (epsilon changes, maybe a rekey) and telemetry keeps flowing; quarantine
 * stops data, so it requires an explicit authenticated command.
 *
 * Confidentiality
 * ---------------
 * The control message is ENCRYPTED, not merely authenticated. `node_mask`
 * would otherwise tell a passive observer exactly which nodes the LSTM has
 * flagged -- i.e. tell the attacker they have been detected, and where.
 *
 * `ctrl_seq` is strictly monotonic and replay-checked. That is what stops a
 * captured "posture = NORMAL" being replayed to suppress a live response, and
 * a captured "posture = ANOMALY" being replayed as a rekey-storm DoS.
 */

/*
 * How much authority a control message carries.
 *
 * The server detects; the DQN decides. This ladder keeps the agent in charge
 * of the ordinary cost/benefit tradeoff while leaving the SOC a hard override
 * for a live intrusion.
 */
typedef enum {
    /* An observation. Feeds the agent's state; the agent chooses the
     * response. The posture field is advisory only. */
    TG_DIRECTIVE_ADVISE     = 0,

    /* A floor. The agent may escalate above `posture` but never below it. */
    TG_DIRECTIVE_ENFORCE    = 1,

    /* Mandatory. Quarantines every node in `node_mask` and forces ANOMALY.
     * Bypasses agent policy entirely. */
    TG_DIRECTIVE_QUARANTINE = 2,

    TG_DIRECTIVE__COUNT
} tg_directive_t;

#define TG_CONTROL_LEN 32

typedef struct {
    uint8_t  version;        /* TG_PROTO_VERSION                          */
    uint8_t  posture;        /* tg_posture_t — requested, floor, or advice */
    uint8_t  directive;      /* tg_directive_t                            */
    uint8_t  reserved;       /* must be 0; rejected otherwise             */
    uint32_t node_mask;      /* bitmap of implicated nodes (up to 32)     */
    uint32_t lease_ms;       /* validity; gateway escalates on expiry      */
    uint32_t min_hold_ms;    /* de-escalation floor, bounds posture flap  */
    uint64_t ctrl_seq;       /* monotonic, replay-checked                 */
    uint64_t issued_ms;      /* server clock                              */
} tg_control_t;

void tg_control_serialize(const tg_control_t *c, uint8_t out[TG_CONTROL_LEN]);
int  tg_control_parse(const uint8_t in[TG_CONTROL_LEN], tg_control_t *c);

/* ── gateway-side posture state machine ──────────────────────────────────── */

typedef enum {
    TG_CTRL_OK          =  0,
    TG_CTRL_ERR_PARSE   = -1,   /* malformed or unknown version/enum     */
    TG_CTRL_ERR_REPLAY  = -2,   /* ctrl_seq not strictly increasing      */
    TG_CTRL_ERR_STALE   = -3    /* issued_ms outside the accepted window */
} tg_ctrl_status_t;

/*
 * Everything the gateway knows about its current security posture.
 *
 * Treat as opaque; drive it with the four functions below. The DQN reads it
 * (lease_expires_ms, node_mask, directive_floor are all state features) but
 * must not write it directly -- tg_posture_request() is the only way policy
 * influences posture, and it is where the shielding lives.
 */
typedef struct {
    uint8_t  posture;             /* current effective posture            */
    uint8_t  directive_floor;     /* minimum posture, from ENFORCE        */
    uint8_t  advised_posture;     /* latest ADVISE, for agent state only  */
    uint8_t  seen_ctrl;           /* any control message accepted yet     */
    uint32_t node_mask;           /* currently quarantined nodes          */
    uint32_t lease_ms;            /* last granted lease duration          */
    uint32_t min_hold_ms;         /* de-escalation floor                  */
    uint64_t lease_expires_ms;    /* 0 = no lease held                    */
    uint64_t posture_since_ms;    /* when the current posture was entered */
    uint64_t last_ctrl_seq;
} tg_posture_state_t;

/*
 * Start with no lease held. `now_ms` seeds posture_since_ms.
 *
 * A freshly booted gateway holds no lease, so the very first tg_posture_tick()
 * would escalate it. Call tg_posture_grace() to allow a startup window before
 * the server's first renewal arrives.
 */
void tg_posture_init(tg_posture_state_t *s, uint64_t now_ms);

/* Grant an initial lease window at startup, before the first control message. */
void tg_posture_grace(tg_posture_state_t *s, uint32_t grace_ms, uint64_t now_ms);

/*
 * Apply a control message that has ALREADY been decrypted and authenticated.
 *
 * This function does not verify anything cryptographic -- do that first (see
 * src/security/posture). It enforces freshness and ordering, then applies the
 * directive. Renews the lease on success.
 */
tg_ctrl_status_t tg_posture_apply(tg_posture_state_t *s,
                                  const tg_control_t *c,
                                  uint64_t now_ms,
                                  uint64_t max_skew_ms);

/*
 * Advance time. Call every loop iteration.
 *
 * If the lease has expired, escalates ONE level (NORMAL -> SUSPICIOUS ->
 * ANOMALY) and re-arms for another lease_ms, so loss of the control channel
 * degrades gracefully instead of slamming straight to ANOMALY on one dropped
 * packet. Returns 1 if the posture changed, 0 otherwise.
 */
int tg_posture_tick(tg_posture_state_t *s, uint64_t now_ms);

/*
 * The DQN proposes a posture; this grants or clamps it. THE SHIELD.
 *
 * Refuses to go below `directive_floor`, and refuses to de-escalate before
 * `min_hold_ms` has elapsed in the current posture. Escalation is always
 * permitted and always immediate.
 *
 * Returns the posture actually in force afterwards, which may differ from
 * what was asked. The agent is not told "no" -- it observes the result, which
 * is the correct signal for a policy to learn from.
 */
uint8_t tg_posture_request(tg_posture_state_t *s, uint8_t desired, uint64_t now_ms);

/* Current effective posture, for stamping into a telemetry frame header. */
uint8_t tg_posture_effective(const tg_posture_state_t *s);

/* Is this node currently quarantined? Quarantine is a TRUST state, not a
 * crypto state: the node keeps a valid session key and keeps being ingested,
 * but its data is marked untrusted and isolated for triage. */
int tg_posture_is_quarantined(const tg_posture_state_t *s, uint16_t node_id);

/* Clear quarantine for a node once triage has cleared it. */
void tg_posture_release(tg_posture_state_t *s, uint16_t node_id);

#endif /* TG_PROTOCOL_H */
