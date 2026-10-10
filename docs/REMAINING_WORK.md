# Remaining Work — Specs and Sequencing

Draft 1 · 2026-09-12 · companion to [PROJECT_STATUS.md](PROJECT_STATUS.md)
(what exists) and [DQN_SPEC.md](DQN_SPEC.md) (Phase A in full).

Every remaining component, with enough interface detail to build against.
Items marked **[DECIDE]** need your answer first.

---

## 0. Where things stand

The **cryptographic layer is essentially complete and tested** — six suites,
all green: AES-256-GCM (400 checks), ECDHE (23), KMAC C↔Python (10/10), ACCM
cross-language, posture control plane (13/13), PQC root-key transfer.

What is missing is not more crypto. It is:

1. **The application layer.** No process reads a sensor, holds a session pool,
   or opens a socket. Every module works standalone and none are wired
   together. This is the single largest gap.
2. **The two ML components** (DQN, LSTM), neither started.
3. **Leaf firmware**, not started.

```
         ┌──────────────────────── what exists ────────────────────────┐
         │  AES-GCM   ECDHE   RXCR-KDF   ACCM   protocol   posture     │
         │  PQC root-key transfer                                      │
         └──────────────────────────┬──────────────────────────────────┘
                                    │ all standalone, nothing calls them
    ┌───────────────────────────────┴───────────────────────────────┐
    │                     what has to be built                      │
    │                                                               │
    │   C: ESP32 firmware ──UART──▶ D: Gateway daemon ──TCP──▶ E: Server  │
    │                                     │  ▲                  │  │     │
    │                                 A: DQN  └──── lease ──────┘  │     │
    │                                                          B: LSTM   │
    └───────────────────────────────────────────────────────────────┘
```

---

## 0b. Topology and terminology

Three tiers, confirmed for the prototype. "Node" was used loosely earlier;
pinned here because it determines what quarantine actually does.

| Tier | What | Prototype | Industry | Owns a session key? |
|---|---|---|---|---|
| 1 | **Measurement channel** (sensor) | **5** | n | no |
| 2 | **Crypto endpoint** (ESP32) | **1** | m | **yes** — key, nonce guard, ECDHE identity |
| 3 | **Gateway** (RPi) | **1** | 1 per substation | yes — ROOT_KEY + the derived pool |
|   | Main server (laptop) | 1 | 1 | yes — issues ROOT_KEY, holds gw-ctrl |

```
  5 sensors ──▶ 1 ESP32 ──UART──▶ 1 RPi gateway ──TCP──▶ 1 laptop
  (channels)    (crypto          (ROOT_KEY, pool,        (LSTM, lease,
                 endpoint)        posture, DQN)           root-key issuer)
```

### What node_mask indexes: channels, not endpoints

`tg_control_t.node_mask` is a bitmap over **measurement channels** (up to 32).

An earlier draft of this document said it indexed crypto endpoints. That is
wrong for this topology and would have made quarantine useless: with one
ESP32, quarantining "the endpoint" stops all telemetry, which is
indistinguishable from shutting the system down. Channel granularity is what
makes quarantine a meaningful action.

On the gateway -> server link the sender is always the gateway, so
`tg_header_t.node_id` identifies the **gateway**, not a leaf. Per-channel
readings travel inside the encrypted payload.

### How quarantine works across the tiers

```
LSTM flags channel 2 (say ACS712 current)
  -> server sets node_mask bit 2, directive QUARANTINE
  -> gateway isolates channel 2's series into the untrusted buffer
  -> channels 0,1,3,4 keep flowing in the normal aggregate
  -> gateway maps channel 2 -> its owning ESP32 -> recycles that session key
  -> on confirmed anomaly, the untrusted buffer is dropped
```

Two granularities, deliberately:

- **isolation** is per channel — the suspect series is quarantined
- **key recycling** is per endpoint — the key belongs to the ESP32

With one ESP32 the recycle affects every channel on it, which is correct: the
key is shared, so a suspect channel means a possibly-compromised endpoint. The
other four channels keep reporting under the *new* key.

This also means a second ESP32 is **not** needed to demonstrate quarantine, as
an earlier draft suggested. Isolating one of five channels while four continue
is a clear demo on the hardware you already have.

### Scaling to industry

The protocol already carries this: 32 channels in `node_mask`, 65,536 endpoint
ids in `node_id`, 32 nodes per KDF pool. For m endpoints the gateway holds m
session keys and m nonce guards, and channel -> endpoint becomes a real lookup
rather than the constant it is in the prototype.

### Consequence for the DQN

Several state features are per-endpoint (`worst_node_budget_util`,
`node_silence_count`). With one endpoint they degenerate to constants, which
teaches the agent nothing about multi-endpoint behaviour.

So the environment simulates **6-12 endpoints** while the prototype runs 1.
That is a normal sim-to-real setup: the policy generalises to industry scale,
and the prototype is a valid degenerate instance of it. State-vector shape is
unchanged either way, so no retraining is needed to move between them.

---

## 0c. C or Python for the daemons? Measured

The concern was latency. Measured on this machine, per operation:

| Operation | Python | C | Ratio |
|---|---|---|---|
| AES-256-GCM, 1 KB | **0.003 ms** | ~0.03 ms | **Python 10x faster** |
| ACCM mask, 256 B | 10.33 ms | 0.149 ms | C 69x faster |
| ACCM mask, 1 KB | 23.57 ms | 0.441 ms | C 53x faster |
| RXCR-KDF, 2-key pool | 17.13 ms | (not ported) | — |
| Control frame seal/open | 0.006 / 0.014 ms | — | — |

**Gateway budget, 1 s window, 6 channels at 10 Hz with a 1 KB batch:**

```
leaf decrypts    60/s        ~  3.60 ms
ACCM mask        1 x 1 KB    ~ 23.57 ms
control + misc               ~  2.00 ms
                             -----------
total                        ~ 29.17 ms   = 2.9% of the window
```

**Python is fast enough by roughly 34x.** Even 50-70x slower on the chaos
layer, it consumes 3% of the budget. Key rotation costs 17 ms and is
occasional.

Note the inversion on the first row: Python's AES-GCM goes through
`cryptography` -> OpenSSL -> **AES-NI hardware instructions**, while the C
build uses table-based tiny-AES in software. Python is not only faster there,
it is also **more side-channel resistant** — table-driven AES has known
cache-timing weaknesses that AES-NI does not.

### Does the switch weaken security?

| Property | Verdict |
|---|---|
| Algorithm correctness | **Identical.** The cross-language KATs prove byte-for-byte equality. Language cannot change the algorithm. |
| AES side channels | **Python better** — AES-NI vs table-based software AES |
| Key hygiene in memory | **C better, and this is a real gap** |

The one genuine loss is key hygiene. Python `bytes` are immutable, so key
material cannot be reliably zeroed; the GC may retain copies from intermediate
operations; and there is no `mlock()` to stop keys being swapped to disk. The C
side has `hal_secure_wipe()` with a volatile pointer precisely for this.

Mitigations, in increasing order of effort:

1. Hold long-lived secrets (ROOT_KEY, session keys) in `bytearray` and zero
   them explicitly on rotation. Weaker than C — intermediates may still leak —
   but much better than `bytes`.
2. `mlock` the process (`ctypes` -> `mlockall`) so keys never reach swap.
3. Keep ROOT_KEY handling in a small C extension, Python for everything else.

For a research prototype, (1) plus a documented limitation is proportionate.
Note it in the paper's threat model rather than claiming production-grade key
hygiene.

### Verdict

Python for the gateway and server daemons. C stays the ESP32 path and the
validated mirror. Revisit only if the aggregation window shrinks below ~100 ms
or ACCM payloads grow past ~30 KB, neither of which is on the roadmap.

---

## 1. Sequencing

**Dependency truths:**

- A (DQN) needs only the *simulator*, not the daemons → can start immediately
- B (LSTM) needs *data*, from MSU/ORNL or the rig → can start immediately
- C (firmware) is independent → can start immediately
- D and E (daemons) need nothing new, but everything else plugs into them
- F (integration) needs all of the above

**Two viable orders:**

| Order | First | Argument |
|---|---|---|
| **Research-first** | A ∥ B ∥ C, then D+E, then F | Both ML results land sooner; the paper's novel content is de-risked early |
| **Pipe-first** | D+E with a dummy policy, then A ∥ B ∥ C | An end-to-end demo exists from week one; every later component slots into something real |

**Recommendation: pipe-first, narrowly.** Build D and E with a *stub* policy
(fixed-interval rotation) and a *stub* detector (threshold on variance). That
is maybe 2–3 days, and it buys you:

- a working demo immediately, which de-risks the deliverable
- a real integration target, so A and B are written against live interfaces
  instead of assumed ones
- `fixed-interval` and `threshold` are two of the five DQN baselines you need
  anyway — building them as stubs means they are not extra work later

Then A, B, C in parallel.

---

## 1b. Is there a circular dependency between the LSTM and the DQN?

No, and it is worth writing down because the question recurs.

**The apparent circle:** the LSTM needs telemetry to train on; telemetry needs
a running system; a running system needs the DQN; the DQN's state vector
includes `lstm_score`.

**Why it does not close:** the LSTM runs on the server, *after* AES-GCM
decryption. Its input is voltage, current, temperature and relay state. Those
numbers are identical whether the DQN is running a trained policy, rotating
keys on a fixed timer, or the link has no encryption at all. Key rotation does
not change what a ZMPT101B reads.

**The LSTM never observes the security layer.** So collecting its training
data needs the *pipe* (Phases C, D, E) with a stub policy — roughly ten lines
of "rotate every N seconds" — and nothing from Phase A.

Meanwhile the DQN does not need the real LSTM either. It needs *a* detector
signal with known statistical properties, which the `Beta(fpr, fnr, delay)`
surrogate supplies. So it trains entirely in simulation.

```
  C+D+E (pipe, stub policy) ──▶ telemetry logs ──▶ LSTM training ──┐
                                                                    │
  simulator + detector surrogate ──▶ DQN training ──────────────────┤
                                                                    │
                                                      Phase F integration
```

Two parallel branches. Neither is upstream of the other. This is the strongest
argument for pipe-first: it unblocks LSTM data collection, and the DQN is
already unblocked.

**Two real couplings, both milder than a circular dependency:**

1. *Policy transfer.* A DQN trained against a surrogate may not transfer
   cleanly to the real LSTM. Mitigated by training across a distribution of
   `(fpr, fnr, delay)` rather than one setting — the robustness curve is the
   mitigation, not just a figure.

2. *Distribution shift.* If the DQN quarantines a node, that node leaves the
   aggregate, so the stream the LSTM sees does change. Handled by two-stage
   training: LSTM on normal data collected under the fixed stub policy, then
   the DQN against the calibrated LSTM. Sequential, not circular.

**And the LSTM can start today regardless.** MSU/ORNL needs nothing from this
system — 37 scenarios, 28 attack types, already labelled. Rig data is for
domain match and is additive, not a prerequisite.

---

## 2. Phase A — DQN

**Full spec: [DQN_SPEC.md](DQN_SPEC.md).** Summary of the build:

| Deliverable | Location | Notes |
|---|---|---|
| Gym-style environment | `src/ML/dqn/env.py` | Imports the *real* `PostureState` / `NonceGuard`, does not reimplement |
| Detector surrogate | `src/ML/dqn/detector.py` | `Beta(fpr, fnr, delay)` — swapped for the real LSTM later |
| Telemetry replay | `src/ML/dqn/telemetry.py` | MSU/ORNL traces resampled to 1 s |
| Cost model | `src/ML/dqn/costs.py` | Measured numbers from `benchmark.py` |
| Shield wrapper | `src/ML/dqn/shield.py` | Four of eight rules already exist in C/Python |
| Agent | `src/ML/dqn/agent.py` | Double DQN + dueling |
| Baselines | `src/ML/dqn/baselines.py` | never / fixed / threshold / always-max / oracle |
| Training + eval | `src/ML/dqn/train.py`, `evaluate.py` | |

**Acceptance:** beats `threshold-on-score` on mean episode return; zero
nonce-exhaustion events; blocked-unsafe-action count reported; robustness
curve across `(fpr, fnr, delay)`.

---

## 3. Phase B — LSTM anomaly detection

### 3.1 Purpose and contract

Runs on the **main server**, consumes decrypted aggregated telemetry, emits an
anomaly score that drives posture decisions.

The contract matters more than the architecture, because the DQN is being
trained against a *surrogate* detector. Match this and the swap is clean:

```python
class Detector(Protocol):
    def score(self, window: np.ndarray) -> float:
        """window: (T, F) float32. Returns calibrated anomaly score in [0, 1]."""

    def attribute(self, window: np.ndarray) -> int:
        """Returns a node_mask bitmap of the nodes most responsible.
           Feeds tg_control_t.node_mask for quarantine targeting."""

    @property
    def latency_ms(self) -> float:
        """Measured inference time. Must stay well under the 1 s window."""
```

`attribute()` is not optional. Quarantine needs to know *which* node, and
`tg_control_t.node_mask` already carries it — a detector that only says
"something is wrong" cannot drive it.

### 3.2 Architecture: LSTM autoencoder

**Recommended: reconstruction-error autoencoder, not a supervised classifier.**

Reason: it trains on **normal data only**, which is the data you will actually
have from the rig. A supervised classifier needs labelled attacks, and a
healthy rig produces none. The autoencoder also gives node attribution for
free — per-feature reconstruction error maps directly onto nodes.

```
input   (T=60, F)               60 s window at 1 Hz, F = 5 channels x features
        ↓
encoder LSTM(64) → LSTM(32)
        ↓
latent  Dense(16)
        ↓
decoder RepeatVector(60) → LSTM(32) → LSTM(64)
        ↓
output  TimeDistributed(Dense(F))   reconstruct the window
```

Features: one or more per channel (voltage, current, temperature, relay
state, and the fifth channel once confirmed). Plus derived:
rate-of-change, rolling std. Normalise per-feature using training-set
statistics, and **persist those statistics** — a detector that renormalises at
inference time will drift.

### 3.3 Score calibration — the part that makes the surrogate swap work

Raw reconstruction error is unbounded and scale-dependent. Convert it to a
calibrated score:

```
score = empirical CDF of reconstruction error, fitted on held-out NORMAL data
```

So `score = 0.99` means "worse than 99% of normal windows". This gives a
genuine `[0, 1]` with a probabilistic reading, and it means the `(fpr, fnr)`
the DQN trained against map onto real thresholds instead of arbitrary units.

### 3.4 Training data

| Source | Use |
|---|---|
| **MSU/ORNL Power System Attack Datasets** | 37 scenarios: 1 normal, 8 natural disturbances, 28 attacks. Train the AE on normal, evaluate detection on attacks |
| Rig-collected normal | Domain adaptation — your sensors, your noise floor |
| Rig-injected attacks | Relay trips, command injection, data injection are all reproducible on the ESP32/RPi setup |

The 8 **natural disturbances** are the important ones. They are the
false-positive source that makes this non-trivial — a detector that flags
every fault as an attack is useless, and the DQN's false-positive cost only
means something if the detector actually produces them.

### 3.5 Evaluation

Report **precision-recall, not just ROC/AUC.** Attacks are rare, so AUC will
look impressive and mean little under class imbalance. Also report:

- detection delay (steps from compromise onset to score crossing threshold) —
  this is exactly the `delay` parameter in the DQN surrogate
- per-scenario breakdown across the 28 attack types
- attribution accuracy: does `attribute()` name the right node?

### 3.6 Deployment

TorchScript or ONNX, loaded once at server start. Budget: inference must
finish inside the 1 s aggregation window with room for the crypto. Measure and
record it in `latency_ms` — the DQN reads it as a resource feature.

**[DECIDE]** Autoencoder only, or AE for deployment plus a supervised
classifier for the paper's detection numbers? The second is more work but
gives stronger evaluation.

---

## 4. Phase C — Leaf firmware (ESP32) and telemetry conversion

**Status: PHASE C COMPLETE on the host. 114 checks, 0 failures.**
Pin drivers written but not yet run on a board.

| Piece | State |
|---|---|
| Channel abstraction + config table | done - `channel.h`, `channel_config.c` |
| Scaling, plausibility band, quality flags | done - `channel.c` |
| COBS framing | done - `cobs.c` |
| Frame seal/open (AES-GCM, AAD=header, derived nonce) | done - `node_frame.c` |
| Host sensor HAL (synthetic signals) | done - `sensor_hal_host.c` |
| Persisted key_epoch (NVS / file) | done - `node_storage.c` |
| Nonce guard, epoch bumped before first encrypt | done - `node_session.c` |
| PSK + ephemeral X25519 handshake | done - `node_session.c` |
| ESP-IDF pin drivers (MCP3008 SPI, GPIO, DHT22) | written, **unvalidated on hardware** |
| Firmware main loop + UART transport | written, **unvalidated on hardware** |
| ESP-IDF component CMakeLists | done |

Everything except the last three is host-tested. First bring-up should check,
in order: MCP3008 channel mapping against `channel_config.c` (watch for
`CH_QUALITY_RANGE` on boot), then DHT22 bit-bang timing.

### Leaf handshake: PSK + ephemeral X25519

Raw ECDHE is unauthenticated, so the leaf is provisioned at manufacture with a
32-byte device PSK and the session key comes from both:

    ikm = X25519(leaf_sk, gw_pub) || device_psk

This is the PSK-DHE shape from TLS-PSK-with-DHE. It authenticates (only the
real gateway holds this node's PSK) and stays forward secret (the DH keys are
ephemeral and wiped). If the PSK leaks, an attacker can MITM *future*
handshakes for that node; past traffic stays safe, and re-provisioning one
ESP32 is the cheapest recovery in the system.

No signatures on the leaf, which matters: ML-DSA verification is ~13 ms against
a 100 ms sampling budget.

The MITM case is tested explicitly - an attacker who relays the public keys but
lacks the PSK derives a different session key, and the CONFIRM tag makes that
visible at handshake time rather than at the first telemetry frame.

**Phase D must mirror the gateway role in Python** (`node_handshake_respond`)
and pin it with a cross-language KAT, exactly as ACCM and the posture plane are
pinned.

### 4.1 Scope

`src/hardware/ESP32/`. Sensor acquisition, session establishment, encryption,
UART transport.

### 4.2 Boot sequence

```
1. init NVS, load persisted key_epoch, INCREMENT it, persist  ← before any encryption
2. bring up RF          (ESP32 TRNG needs it — see hal_port.c)
3. ECDHE handshake with the gateway → raw shared secret
4. raw secret → RXCR-KMAC-KDF → session key
5. wipe the ECDHE private key
6. enter the sample loop
```

Step 1 before step 6 is not optional: it is what makes GCM nonce reuse across
a reboot impossible. Step 2 before step 3 is also not optional — the ESP32
hardware RNG is only fully entropic while RF is active, so generating a
keypair before WiFi is up produces low-entropy secret keys.

### 4.3 Sampling

```c
typedef struct {
    uint16_t node_id;
    uint64_t seq;
    uint64_t timestamp_ms;
    float    voltage;       /* ZMPT101B via MCP3008 CH0, SPI */
    float    current;       /* ACS712   via MCP3008 CH1, SPI */
    float    temperature;   /* DHT22, 1-wire GPIO            */
    uint8_t  relay_state;   /* GPIO read                     */
} sensor_payload_t;
```

10 Hz. Encrypt with `aead_encrypt()`, nonce from the same
`key_epoch || seq` discipline as the gateway link.

### 4.4 UART framing - SETTLED: COBS

The deck (slide 13) describes serialising to JSON over UART. That does not
survive contact with AES-GCM: ciphertext and tag are arbitrary binary, and
UART is a byte stream with no message boundaries.

**COBS was chosen and is implemented.** One byte of overhead per frame, and
0x00 appears only as the delimiter - so a receiver that loses sync recovers at
the very next frame boundary with no ambiguity. On a substation line where
electrical noise is expected rather than exceptional, that automatic resync is
the difference between a dropped packet and a dead link. A length prefix would
have been one byte smaller and desynchronised until restart.

Measured on the prototype's 5 channels: **81 bytes per frame plus a delimiter,
820 B/s at 10 Hz** - about 7% of a 115200-baud line. Ample room for more
channels.

### 4.5 Telemetry converter

For real SCADA deployments the data already exists in DNP3 / IEC 61850, so the
ESP32 path is replaced by a mapping layer:

```
DNP3 / IEC-61850 point  →  (node_id, measurand, value, unit, quality, timestamp)
                        →  sensor_payload_t
```

Needs: point-to-node mapping table, unit normalisation, timestamp alignment to
the 1 s grid, and quality-flag handling (a bad-quality point must not look like
an anomaly to the LSTM).

For the prototype this is a thin shim — the ESP32 is the source. Build it as a
separate module anyway so the SCADA claim in the paper is backed by an actual
interface rather than an assertion.

---

## 5. Phase D — Gateway daemon

**Status: PHASE D COMPLETE. 30/30 end-to-end checks.**

| Piece | State |
|---|---|
| Python COBS + leaf frame open | done - `leaf_link.py`, cross-language KAT |
| Python handshake responder (gateway role) | done - cross-language KAT |
| `GatewayState` - ROOT_KEY, pool, epochs, leaf links | done - `gateway_state.py` |
| `Aggregator` - 1 s window, quarantine isolation | done - `aggregator.py` |
| `Uplink` - GCM + ACCM + TCP, piggybacked lease | done - `uplink.py` |
| `Policy` + `Shield` + 4 baselines | done - `policy.py` |
| `GatewayDaemon` - asyncio orchestration | done - `daemon.py` |
| End-to-end test (simulated leaf + server) | done - `test_gateway.py` |

The tests run the **real** daemon against a simulated ESP32 and a simulated
server over in-memory asyncio pipes. Only the two peers are simulated;
the handshake, AES-GCM, ACCM mask, posture state machine and shield are all
production code. That is what lets the whole pipeline be verified before any
hardware exists.

Verified end to end: handshake agreement, 10 telemetry frames accepted, replay
rejected, tampered frame counted as an auth failure, batch sealed and opened by
the server, lease renewed by the response, quarantine isolating one channel
while four keep flowing, lease expiry walking NORMAL -> SUSPICIOUS -> ANOMALY
without auto-quarantining, and all five shield rules firing.

### What the DQN plugs into

`policy.py` is the seam. `Observation` mirrors the DQN state vector (with
`to_vector()` for the agent), `Action` is the eight-action set, and `Shield`
enforces the safety envelope. Swapping `ThresholdPolicy` for a trained agent is
one constructor argument.

Four baselines ship already - `never`, `fixed-interval`, `threshold`,
`always-max` - which is four of the five the DQN must beat. Only the oracle
baseline is left, and that needs the simulator's ground truth.

### 5.1 Responsibilities

| Component | Job |
|---|---|
| `UartReader` | COBS deframe, AES-GCM decrypt per leaf, replay check |
| `Aggregator` | 1 s window, per-node buffering, quarantine isolation |
| `TelemetryTx` | build header, GCM encrypt (AAD=header), ACCM mask, send |
| `ControlRx` | open sealed control frames, `PostureState.apply()` |
| `PolicyLoop` | 1 Hz: build the observation, run the DQN, apply through the shield |
| `KeyManager` | ROOT_KEY, RXCR-KDF pool, nonce guards, epoch persistence |

### 5.2 State it owns

```python
ROOT_KEY            : bytes            # from the PQC transfer
session_pool        : dict[bytes, bytes]   # per-node, from RXCR-KMAC-KDF
nonce_guards        : dict[int, NonceGuard]
replay_guards       : dict[int, ReplayGuard]
posture             : PostureState     # already built and tested
accm_chain          : bytes            # prev_tail, per peer
```

### 5.3 Quarantine handling

Confirmed semantics: **isolate and continue as untrusted; dump on confirmed
major anomaly.** So quarantine is a *trust* state, not a crypto state —

- the node keeps a valid session key and keeps being ingested
- its data goes to a separate buffer, tagged untrusted
- it is **excluded from the aggregate** sent to the server as normal telemetry
- it is forwarded separately, flagged, for triage
- on confirmation, the buffer is dropped and the node's session key is recycled

`tg_posture_is_quarantined()` and `tg_posture_release()` already exist.

### 5.4 Concurrency

**[DECIDE]** asyncio or threads? asyncio suits the I/O-bound mix (UART, TCP,
timers) and avoids locking the key material. Threads are easier if the DQN
inference blocks. Recommendation: asyncio with the DQN forward pass in a
thread executor.

### 5.5 Acceptance

Survives a 1-hour soak at 10 Hz × 6 nodes with zero nonce reuse, zero
unhandled GCM failures, and correct posture echo in every frame header.

---

## 6. Phase E — Server daemon

`server/`. Counterpart to D.

### 6.1 Receive path

```
TCP frame
  → parse 24-byte header
  → tg_replay_check()                    reject replay/reorder
  → ACCM unmask (header + prev_tail)
  → AES-GCM decrypt, AAD = header        ← posture/epoch authenticated here
  → accm_chain_update()
  → append to the LSTM window
```

### 6.2 Response path — the piggybacked lease

Every telemetry batch gets a response, and that response **is** the lease
renewal. No separate timer, no second connection, and a server that stops
responding decays the lease exactly like one that stops renewing.

```
→ LSTM score + attribution
→ posture decision (ADVISE / ENFORCE / QUARANTINE)
→ tg_ctrl_seal() under the gw-ctrl key
→ send as the telemetry response
```

Lease 3 s, renewal 1 s — two lost renewals tolerated before escalation.

### 6.3 Posture echo verification

The gateway's compliance is already observable: `posture` is in every
telemetry header and authenticated as GCM AAD. So:

```
after issuing ENFORCE/QUARANTINE at ctrl_seq = N:
    the next K frames must report the commanded posture
    if not  → gateway unreachable or compromised
            → drop the link, alert the SOC, stop trusting its data
```

**[DECIDE]** What is K? 5 frames (5 s) is a reasonable default.

### 6.4 Also owned by the server

- ROOT_KEY issuance (`transfer_root_key`, already built) with the persisted
  epoch counter
- `ctrl_epoch` / `ctrl_seq` persistence — same discipline, bumped on restart
- SOC alert output (log, syslog, or a webhook)

---

## 7. Phase F — Integration and demo

Four scenarios, in increasing order of how good they look in a viva:

1. **Normal operation** — sensors → ESP32 → RPi → laptop, telemetry decoding
   cleanly, posture NORMAL, lease renewing at 1 Hz.
2. **Injected attack** — replay an MSU/ORNL attack scenario or trip a relay.
   LSTM scores, server issues ENFORCE, gateway escalates, ACCM ε shifts, DQN
   rotates keys. Show the posture echo closing the loop.
3. **Control channel cut** — unplug the Ethernet. Lease expires, gateway
   escalates NORMAL → SUSPICIOUS → ANOMALY on its own, telemetry keeps
   flowing. **This is the best demo moment you have**: the system defends
   itself when the server is silenced, which is precisely the Ukraine phase-5
   scenario.
4. **Quarantine and release** — flag a node, show its data isolated and tagged,
   triage, release.

Instrument all four so they produce the figures the paper needs, rather than
being run once for the demo and then re-created later.

---

## 8. Phase G — Evaluation and paper artefacts

| Artefact | Source | Status |
|---|---|---|
| PQC benchmark table | `benchmark.py` | **done** |
| ACCM keystream statistics | `accm_stats.py` | **done** |
| ACCM v1 failure evidence | PROJECT_STATUS §4.2 | **done** — publishable as a negative result |
| DQN vs 5 baselines | Phase A | pending |
| DQN robustness curve | Phase A | pending |
| LSTM PR curves + detection delay | Phase B | pending |
| End-to-end latency budget | Phase F | pending |
| Per-node timing under adaptive selection | slides 20–24 | partially done |
| NIST STS on ACCM (≥55 sequences) | `accm_stream_gen` + STS | pending |
| NIST STS on RXCR **with varying IKM** | see P5 | pending |

---

## 9. Residual security hardening

Carried from PROJECT_STATUS §6, with what each actually needs:

| ID | Item | Work |
|---|---|---|
| **P3** | Gateway KEM public key trusted implicitly | Gateway signs its own KEM pk with its ML-DSA key; server holds a trusted `gateway_dsa_pk.bin`. The gateway DSA keypair already exists and is unused — this is what it is for. Half a day. |
| **P4** | No forward secrecy on the root-key transfer | Rotate the gateway ML-KEM keypair per epoch; server re-fetches the public key over the authenticated channel from P3. Depends on P3. |
| **P5** | STS run does not test RXCR-Extract | `generate_sts_input.py` holds IKM and salt fixed, so the same PRK is produced for all 1,000,000 blocks — it measures KMACXOF256, not the extractor. Vary IKM per block, concatenate PRKs, and use ≥55 sequences. Half a day. |
| **P6** | RXCR finalizer concatenation ambiguity | Length-prefix the fields in `SHA3-256(state ‖ ikm ‖ salt)`. One line, but it changes KDF output — do it together with P5 so the corpus is regenerated once. |
| **P7** | RXCR novelty framing | Reframe as "hardening pre-mix with a SHA3-256 security floor"; back it with ESP32 cycle counts vs HMAC-SHA256. Writing, not code. |
| **P8** | `rxcr.c` / `rxcr_kmac_kdf.c` empty | Port from `python/rxcr.py`, validate with the same KAT pattern used for `kmac.c`. Mechanical, one day. **Blocks a pure-C gateway** — not needed if the gateway is Python. |
| **P9** | ACCM chaining is transport-fragile | Fine over TCP. If the link ever becomes UDP/DTLS, drop `prev_tail` chaining and give `tg_replay_guard_t` a sliding bitmap window. |
| **P10** | ML-KEM-512 / ML-DSA-44 are level 1/2 | Deliberate for now. Revisit before deployment, not before the demo. |
| — | ESP32 S3/C3 backends are stubs | Fail at compile time with guidance. Implement only if those boards are actually used. |
| — | AES-GCM comments destroyed | Re-documented from scratch. If an unstripped original turns up, diff it. |

---

## 10. Effort summary

Rough, assuming familiarity with the codebase:

| Phase | Effort | Can start now? |
|---|---|---|
| D + E with stub policy/detector | 2–3 days | **yes** |
| A — DQN | 1–2 weeks | **yes** (needs §11 answers) |
| B — LSTM | 1–2 weeks | **yes** (needs data) |
| C — ESP32 firmware | 1 week | **yes** |
| F — integration | 3–5 days | after A–E |
| G — evaluation | 1 week | rolling |
| P3–P6 hardening | 2–3 days | **yes**, any time |

---

## 11. Open [DECIDE] items, collected

From [DQN_SPEC.md](DQN_SPEC.md) §11:

1. Node count for the prototype (6?)
2. Where the agent runs — Python on RPi calling C, or Python daemon with C as a library
3. `w_miss / w_fp` ratio (suggested 20:3)
4. Detector surrogate: sweep `(fpr, fnr)` or fit from MSU/ORNL first
5. PyTorch or NumPy-only

From this document:

6. LSTM: autoencoder only, or AE + supervised classifier for the paper (§3.6)
7. ~~UART framing~~ **Settled: COBS**, implemented and tested (§4.4)
8. Gateway concurrency: asyncio or threads (§5.4)
9. Posture echo window K (§6.3, suggested 5)

Items 1, 2 and 5 block Phase A. Item 7 blocks Phase C. The rest have
defensible defaults and can be settled later.
