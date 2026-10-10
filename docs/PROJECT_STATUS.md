# Project Status

**An AI-Enhanced Post-Quantum Key Exchange with Chaotic Stream Encryption for Secure Power Grid IIoT Telemetry**

Last updated: 2026-09-12

This document covers **what exists and what state it is in**. It is the
handover document for the project; keep it current.

| Document | Covers |
|---|---|
| **PROJECT_STATUS.md** (this file) | What exists, what changed and why, open issues |
| [REMAINING_WORK.md](REMAINING_WORK.md) | Everything left to build, with specs and sequencing |
| [DQN_SPEC.md](DQN_SPEC.md) | The DQN in full — MDP, reward, shield, simulator, evaluation |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Milestones, order, acceptance criteria, risks, decision gates |

---

## 1. Architecture as built

Three tiers, confirmed against the workflow and architecture slides:

```
LEAF                        GATEWAY (RPi 4B)                 MAIN SERVER (laptop/cloud)
────                        ────────────────                 ─────────────────────────
sensors → ESP32             ROOT_KEY holder                  ROOT_KEY origin
  ZMPT101B  (voltage)       RXCR-KMAC-KDF → session pool     ML-KEM-512 encaps
  ACS712    (current)       telemetry aggregation            ML-DSA-44 sign
  DHT22     (temperature)   DQN: key lifecycle + scheduling  LSTM anomaly detection
  relay, MCP3008 ADC        ACCM masking                     posture decisions

  AES-GCM over UART              AES-GCM + ACCM over TCP
leaf ──────────────────→ gateway ────────────────────────→ server
     session key via ECDHE       session key via RXCR-KMAC-KDF
                                 posture control ←──────────
```

**Layer order on the gateway→server link** (this is the load-bearing detail):

```
plaintext
  → AES-256-GCM   key = session key, nonce = derived, AAD = frame header
  → ct || tag
  → ACCM mask     XOR keystream, applied OUTSIDE the AEAD
  → wire:  header(24, cleartext but authenticated) || masked(ct || tag)
```

Leaf nodes get their session keys via **ECDHE** (`src/security/ECDHE`, built on
monocypher), not from the ROOT_KEY hierarchy. That closes the leaf bootstrap
question but means the leaf tier is *not* post-quantum — see §6.

---

## 2. Component inventory

| Component | Location | State |
|---|---|---|
| RXCR-KMAC-KDF (Python) | `temp_codes/RXCR-KMAC-KDF/python/` | Working. `rxcr.py` extract, `kmac.py` KMACXOF256, `kdf.py` pipeline |
| RXCR-KMAC-KDF (C) | `temp_codes/RXCR-KMAC-KDF/c/` | **Complete.** kmac + rxcr + kdf, **17/17 vectors match Python**. Closes P8 |
| PQC root-key transfer | `temp_codes/pqcrypto_project/` | Working. ML-KEM-512 + ML-DSA-44 + AES-256-GCM. **Hardened this pass** |
| PQC benchmark | `temp_codes/pqcrypto_project/pqcrypto_project/benchmark.py` | Working, 1000/1000 stress pass |
| ACCM v1 | `temp_codes/Chaos/Chaos/chaos_custom.C` | **Superseded** — kept for reference; see §4.2 for why it cannot ship |
| ACCM v2 | `src/security/ACCM/` | **New this pass.** C + Python, cross-language KAT, statistics |
| Wire protocol | `include/protocol.h`, `src/protocol.c` | **New this pass.** Was an empty stub |
| Posture control plane | `src/security/posture/` | **New.** Sealed control frame + lease state machine, C + Python, 13/13 cross-language |
| AES-256-GCM (software) | `temp_codes/AES-256-GCM/` | Working. **400 checks / 0 failures**, incl. 8 NIST vectors. Was silently AES-128 — see §3.5.1 |
| AES-256-GCM (esp32_hw) | `.../backends/esp32_hw.c` | Correct (mbedTLS, 256-bit). Recommended ESP32 backend. Guard conflict resolved |
| AES-256-GCM (esp32 regs) | `.../backends/esp32_hw_registers.c` | Builds, **never validated on hardware**. Own guard `AEAD_BACKEND_ESP32_REGS` now. Timeout bug fixed |
| AES-256-GCM (S3 / C3) | `.../backends/esp32s3_hw.c`, `esp32c3_hw.c` | Stubs — now fail at **compile** time with an explanatory `#error` instead of at link time |
| ECDHE (leaf) | `src/security/ECDHE/` | Working. **23 checks / 0 failures**, incl. RFC 7748 vector. Had never compiled — see §3.5.3 |
| LSTM anomaly detection | `server/LSTM/` | **Empty.** Not started |
| DQN environment | `src/ML/dqn/` | Env + surrogate + costs + 5 baselines. **27/27** |
| DQN agent | `src/ML/dqn/agent.py` | Double DQN + duelling, PyTorch train / NumPy deploy. **23/23**, export matches to 9e-08 |
| DQN train / evaluate | `src/ML/dqn/train.py`, `evaluate.py` | Domain-randomised training, 5-baseline table, 27-point robustness sweep |
| Leaf firmware | `src/hardware/ESP32/` | **Phase C complete.** Channels, COBS, frames, persisted nonce guard, PSK+DHE handshake. **114 checks / 0 failures** |
| Leaf pin drivers + main | `.../sensor_hal_esp32.c`, `node_main.c` | Written, **not yet run on hardware** - MCP3008 SPI, DHT22 1-wire, boot ordering |
| Leaf link (Python) | `src/hardware/Gateway/python/` | **New.** COBS, frame open, handshake responder. **Cross-language KAT passes** |
| Gateway daemon | `src/hardware/Gateway/python/` | **Phase D complete.** asyncio daemon: leaf reader, aggregator, uplink, posture, policy + shield. **30/30 end-to-end** |
| Server daemon | `server/python/` | **Phase E complete.** TCP listener, frame opening, lease issuance, posture echo. **33/33 full-pipe** |
| Detector interface | `server/python/detector.py` | Protocol + `StubDetector`. The LSTM slots in here |
| Root-key provisioning | `server/python/provisioning.py` | **New.** Both ends derive the transcript from the packet — closes a gap where it came from nowhere |

Note: every `README.md` under `src/` is 0 bytes, and all working code currently
lives under `temp_codes/`. Consolidating is worth doing before the tree grows.

---

## 3. What changed in this pass

Four defects were fixed. Three were found by inspection; the fourth was found by
measurement and was the most serious.

### 3.1 The anomaly flag had no synchronisation channel

**Problem.** ε was selected by a boolean `anomaly_flag` held as implicit state
on each side. The LSTM runs on the *server* but the mask is applied at the
*gateway*, so the two ends had no agreed mechanism for switching on the same
packet boundary. Because ACCM sits outside AES-GCM, a mismatch was *silent*:
the server would unmask with the wrong ε, hand garbage to GCM, and GCM would
fail — but the demo (`main_custom.C`) papered over this by having the receiver
hand-copy the sender's context, which no real link can do.

**Fix.** The posture is now an explicit field in a 24-byte frame header that is
cleartext on the wire but passed to AES-GCM as **AAD**. A flipped posture bit
fails the GCM tag. `tg_posture_t` has three states matching the workflow
diagram's terminal states (NORMAL / SUSPICIOUS / ANOMALY), mapping to ε of
0.10 / 0.25 / 0.40.

**Honest consequence for the paper.** Slide 16 claims "no metadata change
indicating anything happened". That claim has to go — it is *unachievable*, not
merely unimplemented. If the receiver must reproduce the keystream, every
parameter selecting that keystream must be readable before unmasking. The
defensible claim is **unforgeability and unpredictability**, not invisibility:
an observer sees that the posture changed, but cannot forge it, replay it, or
predict the resulting keystream without the session key.

The server→gateway control path is specified as `tg_control_t`: its own AES-GCM
envelope under a separate derived key (`gw-ctrl`, kept distinct from
`gw-telemetry` by the KDF's customisation string), with a monotonic `ctrl_seq`.
That is what stops a captured "NORMAL" being replayed to suppress a live
response, or a captured "ANOMALY" being replayed as a rekey-storm DoS. A
`min_hold_ms` de-escalation floor bounds posture flapping. **Built and tested**
in C and Python (13/13 cross-language), including the lease state machine -
see `src/security/posture/`.

### 3.2 Only 64 bits of the session key reached the chaos layer

**Problem.** In `lorenz_derive_seeds`, `combined[8]` took `session_key[0..7]`,
but only `combined[0..5]` became the Lorenz seed — bytes 6–7 were computed and
discarded. `r1`/`r2` came from `session_key[8]` and `[9]`. Bytes 10–31 were
never read. Total: 48 + 16 = **64 bits** of secret entropy in the entire
masking layer.

**Fix.** Every ACCM parameter is now derived with KMACXOF256 keyed on all 32
bytes. The KAT asserts this directly: two keys differing only in
`session_key[31]` — a byte v1 never read — must produce different keystreams.

### 3.3 AES-GCM nonce reuse was reachable

**Problem.** Nonce management was unspecified. With the DQN owning key
lifecycle, a session key surviving a gateway reboot while a counter reset would
produce catastrophic GCM nonce reuse (forgery *and* plaintext recovery).

**Fix.** `nonce = key_epoch(4B BE) || seq(8B BE)`, deterministic. `key_epoch`
increments on every session-key install **and every gateway boot** (persisted),
so a reboot cannot replay a `(key, nonce)` pair. `tg_nonce_guard_t` is the only
sanctioned source of a `seq`; it enforces strict monotonicity and refuses past
`TG_SEQ_MAX` (2³⁰ — roughly 3.4 years at 10 Hz).

**The design principle here matters more than the mechanism:** the invariant
"never reuse (key, nonce)" lives *below* the policy layer. The DQN chooses
*when* to rotate; it cannot choose to emit a duplicate nonce. Safety
constraints must be structural, not learned.

### 3.4 Root-key packets replayed forever

**Problem.** The v1 signature covered `kem_ct || ct || nonce || tag`. Nothing
said who the packet was for or when it was issued, so a captured packet
verified indefinitely — an attacker could roll the gateway back onto an old
ROOT_KEY and every session key beneath it.

**Fix.** The signed payload now covers a protocol tag, recipient `gateway_id`,
monotonic `root_epoch`, and `issued_ms`, each length-prefixed (`wire.lv()`).
The same context is bound into the AES-GCM AAD *and* into the transport-key
derivation. The gateway persists the highest accepted epoch and rejects
anything not strictly newer. Verified: `python server.py` shows a successful
transfer followed by `replay : rejected`, and the 1000-iteration stress test
passes with enforcement on.

**KDF inputs, now specified** (`keyschedule.py`) — this answers "what should
RXCR take as IKM":

```
IKM  = ROOT_KEY || transcript_hash
salt = lv(protocol_tag) || lv(node_id) || u32(key_epoch)
info = b"rxcr-kmac-kdf/v2|pq-iot-telemetry"

transcript_hash = SHA3-256 over protocol tag, gateway_id, root_epoch,
                  kem_ciphertext, gateway_kem_pk, server_dsa_pk
```

ROOT_KEY stays first because the extractor's security rests on it; the
transcript is public context. Binding the transcript means session keys from
different handshakes are unrelated, so a re-injected root key cannot resurrect
old session keys. `key_epoch` appears in the salt, in the frame header, *and*
in the nonce — so "new key" and "new nonce space" are one indivisible step.

---

### 3.5 Security audit — second pass

Run before starting DQN work, to establish what can actually be integrated.

### 3.5.1 The AES-256-GCM module was AES-128-GCM (FIXED)

**Severity: critical.** The software backend failed **all 8** NIST known-answer
vectors — ciphertext *and* tag mismatched on every one. Meanwhile 363 of 385
other checks passed: round-trip, tamper detection, parameter validation all
worked. That combination is the signature of a cipher that is internally
self-consistent but not the algorithm it claims to be.

Cause: `src/backends/tiny_aes/aes.h` had `#define AES128 1` hardcoded and
unconditional. `AES_init_ctx()` does not validate key length — it reads the
first `AES_KEYLEN` (16) bytes and builds an AES-128 schedule. So
`software.c`'s 32-byte key was **silently truncated to 16 bytes**.

This was almost certainly collateral from the comment-stripping in §3.5.2: the
upstream file has `//#define AES192 1` / `//#define AES256 1` on the following
lines, and those became blank.

Consequences had it shipped:
- effective strength 128-bit, upper half of every session key discarded;
- the gateway would **not interoperate** with the Python server, which uses
  real AES-256-GCM via `cryptography`;
- every "AES-256" claim in the deck would have been false for this code path.

Fixed by defaulting to `AES256` when no size is specified, overridable from
the build. **393 checks, 0 failures.** The vectors themselves were verified
independently against `cryptography`'s AES-GCM (8/8 valid), so this also
establishes C↔Python interop transitively.

*Lesson worth keeping: the round-trip and tamper tests all passed. Self-
consistency tests cannot detect "correct-looking but wrong algorithm" — only
known-answer vectors against an independent implementation can.*

### 3.5.2 All comments stripped from the AES-GCM module

Every one of the 10 non-vendored `.c`/`.h` files in `temp_codes/AES-256-GCM/`
has zero comments remaining, with the comment text replaced by runs of spaces
(confirmed by hexdump — literal 0x20 padding where `/* ... */` blocks were).
The code still compiles; the documentation is gone, and in one case
(§3.5.1) a semantically load-bearing commented-out line went with it.

`temp_codes/` is **entirely untracked in git**, so there is no history to
recover from. If an original copy exists elsewhere, restore it.

### 3.5.3 ECDHE had never compiled (FIXED)

Four independent breakages, of which the last is the one that mattered:

1. `src/ECDHE.c` included `"iiot_ecdhe.h"`; the file was `include/ECDHE.h`.
2. `CMakeLists.txt` listed `src/iiot_ecdhe.c`; the file was `src/ECDHE.c`.
3. ESP-IDF-only: `hal_port.c` included `esp_random.h` / `esp_timer.h`
   unconditionally, so nothing could build or test it off-target — despite
   `iiot_ecdhe.h` promising it "must compile for ANY target".
4. **It called a Monocypher 3.x API that the vendored 4.0.2 does not have.**
   `crypto_x25519_public()` does not exist in 4.x (it is
   `crypto_x25519_public_key()`), and `crypto_x25519()` returns `void`, not
   `int` — so `int result = crypto_x25519(...)` is not valid C.

Point 4 means this module had **never been compiled at all**, by anyone. The
filename mismatches are what you notice first; the API mismatch is what proves
nothing ever built it.

It also matters for security, not just for the build. Monocypher 4.x dropped
the return value deliberately and moved the all-zero-output check to the
caller. Code written against 3.x that is ported by fixing the compile error —
rather than by reading why the signature changed — silently loses its
low-order-point rejection while still *looking* like it validates the peer
key. The check is now explicit, using constant-time `crypto_verify32()`
against a zero buffer.

**Fixed:**

- Renamed to `iiot_ecdhe.{c,h}`, matching the include guard, the `@file` tags,
  the `iiot_ecdhe_*` prefix and the CMakeLists — five pieces of evidence for
  that name against one for the other.
- `hal_port.c` now has three backends chosen automatically: ESP-IDF (leaf),
  POSIX (the RPi gateway — a production path, not just a test convenience),
  and Windows (dev/test). An unknown platform is a hard `#error`, never a
  fallback to `rand()`.
- Ported to the Monocypher 4.x API with an explicit zero check.
- `iiot_ecdhe_compute_shared_secret()` now returns `iiot_ecdhe_status_t`.

The old void signature handled a low-order peer key by wiping the output and
then spinning in `while (1) {}` under `!NDEBUG` — a hang an attacker triggers
by sending one degenerate public key. In release builds it was worse: it
returned silently with an all-zero buffer, and a caller that did not
separately check for all-zero would derive session keys from a value the
attacker also knows. The header had flagged the void signature as a known
compromise; it is now just fixed.

**Verification** (`src/security/ECDHE/tests/test_ecdhe.c`, 23 checks, 0
failures — all first-time, since nothing here could previously run):

- RFC 7748 §6.1 known-answer vector, both directions
- generated keypairs agree, and differ from each other
- **5 low-order points rejected** (orders 1, 2, 4, 8) with the output wiped
- NULL-parameter handling and `hal_secure_wipe()`

### 3.5.4 ESP32 backend selection is broken

- `esp32s3_hw.c` and `esp32c3_hw.c` define only `aead_backend_name()` and
  `aead_backend_is_hardware()`. Selecting either gives **undefined references**
  to `aead_init`/`aead_encrypt`/`aead_decrypt`/`aead_deinit`. The ESP32-S3 is a
  likely target board, so this matters.
- `esp32_hw.c` (mbedTLS) and `esp32_hw_registers.c` (bare-metal register
  driver) are both guarded by `AEAD_BACKEND_ESP32_HW` and both define the same
  five symbols → **duplicate symbol link error** if both are compiled. They are
  mutually exclusive alternatives and need distinct guards.
- `esp32_hw.c` rejects `plaintext == NULL` even when `pt_len == 0`, which the
  software backend accepts. Harmless for telemetry (never empty) but an
  interop inconsistency between backends.

### 3.5.5 Fixes applied in the documentation pass

The AES-GCM module was re-documented from scratch (its comments had been
destroyed — §3.5.2). Five correctness changes went in alongside the prose.

**96-bit nonce is now enforced, not assumed.** `gcm_core.c` builds the
pre-counter block as `J0 = IV || 0^31 || 1`, which SP 800-38D defines *only*
for a 96-bit IV; any other length requires `J0 = GHASH(H, {}, IV)`, which this
file does not implement. Widening `AEAD_NONCE_LEN` would therefore keep
compiling, keep round-tripping against itself, and silently stop being GCM.
A static assertion now makes that edit a build failure:

    gcm_core.c(62): error C2338: static_assert failed: 'nonce_must_be_96_bits'

Matching assertions pin the 256-bit key and 128-bit tag. `test_aead.c` also
checks at runtime that the last nonce byte changes both keystream and tag, so
a backend that quietly reads fewer than 12 bytes is caught too.

*Verified by actually editing the constant to 16 and confirming the build
fails.* The project nonce (`key_epoch:32 || seq:64`) is exactly 96 bits, so
there is no pressure to widen it.

**Backend selection is guarded.** `esp32_hw.c` and `esp32_hw_registers.c`
both defined the same five symbols under the same macro; the register backend
moved to `AEAD_BACKEND_ESP32_REGS`. Selecting two backends, or either S3/C3
stub, now fails at compile time with a message saying what to use instead.
All four guards were negative-tested by trying to build them.

While writing that header I introduced — and had to fix — a textbook instance
of the same bug class this module keeps hitting:

    #define COUNT (defined(A) + defined(B))   /* undefined behaviour */
    #if COUNT > 1

`defined` reaching `#if` through macro expansion is UB. GCC does what you
meant; MSVC evaluates it to 0, so the guard silently passes and never fires.
Each flag is now resolved in its own `#if` first. The lesson generalises: a
guard that has not been observed to fire is not a guard.

**Hardware timeout no longer ignored.** `aes_hw_raw_block()` spun waiting for
the AES peripheral to report idle, then read the output registers and returned
success *regardless of whether the wait timed out*. A wedged peripheral would
have produced silent garbage ciphertext. It now returns `-1`, propagating to
`AEAD_ERR_BACKEND`.

**Backend behaviour aligned.** `esp32_hw.c` rejected a NULL plaintext even at
`pt_len == 0`, which the software backend accepts — that is AAD-only
authentication, which the posture control channel needs.

**Off-by-one in the GCM length limit.** The payload bound was
`0xFFFFFFFF * 16`; the correct limit for a 96-bit IV is `(2^32 - 2) * 16`.
Now also computed in `uint64_t`, since on a 32-bit ESP32 the old expression
overflowed `size_t` and the check was vacuous. Theoretical at 64 GiB per
message, but free to get right.

---

## 4. The measured finding: ACCM v1 did not produce a usable keystream

This was not visible by inspection. It came out of generating a real corpus.

### 4.1 What was measured

`accm_stream_gen.exe` emits the keystream the way the link actually uses it —
re-derived per frame from an advancing `(seq, timestamp, prev_tail)`, not one
long run of a single map. `accm_stats.py` then measures it.

**ACCM v1 extraction (`byte = (x>>24) ^ (y>>24)`), 4 MB corpus:**

| Posture | Entropy | Max byte frequency | Lag-1 corr |
|---|---|---|---|
| NORMAL (ε=0.1) | 7.68 bits/byte | 1.0% | +0.211 |
| ANOMALY (ε=0.4) | **3.26 bits/byte** | **35.9%** | +0.024 |

The anomaly posture — the case that matters most — degraded the mask to almost
nothing. One byte value took 36% of all output.

### 4.2 Root cause: two independent failures

**(a) Synchronisation.** As ε → 0.5 the coupled states converge. Measured mean
|x−y| falls from 0.330 at ε=0.05 to 0.0046 at ε=0.40 to exactly 0 at ε=0.50.
v1 XORed the *same* bit-slice of x and y, so convergence collapsed the output
toward zero. At ε=0.5 the keystream is identically zero.

**(b) The map is not a CSPRNG, at any precision.** Fraction of random
key-derived parameter draws whose keystream fell below 7.99 bits/byte:

| Mitigation tried | Failure rate |
|---|---|
| v1 extraction (top byte of each, XORed) | **100%** |
| Fold all fraction bytes at different offsets | 20–60% |
| + restrict r to Lyapunov-verified chaotic values | 20–60% |
| + widen state to Q64 (rules out fixed-point cycle shortening) | 20–60% |

For reference, 10.3% of the r range [3.57, 4.0) is not chaotic at all
(periodic windows, e.g. the period-3 window near r≈3.83). But filtering those
out did not help, and Q32 cycle lengths were usually >10⁶ — long enough that
cycle shortening was not the cause either. **No parameter tuning makes a
coupled logistic map produce a uniform keystream.** This is consistent with
why chaos-based stream ciphers are repeatedly broken in the literature.

### 4.3 The fix, and the claim it supports

ACCM v2 XORs the chaotic byte over a **KMACXOF256 base stream**:

```
base      = KMACXOF256(session_key, expand || be32(chunk), "ACCM-v2/stream", n)
stream[i] = base[i] XOR fold(x_i, y_i)
```

XORing a uniform stream with anything independent of it stays uniform, so the
floor of this layer is **exactly KMACXOF256, whatever the map does**. The
chaotic component can only add. The same "can only add, never subtract"
discipline applies to the Lorenz stage, whose orbit is folded back through
KMAC rather than used directly.

Result, 4 MB per posture:

| Posture | Entropy | χ² (df=255) | p | Monobit p | Lag-1 corr |
|---|---|---|---|---|---|
| NORMAL | 7.999951 | 274.1 | 0.197 | 0.178 | −0.00008 |
| SUSPICIOUS | 7.999958 | 232.2 | 0.844 | 0.029 | +0.00027 |
| ANOMALY | 7.999954 | 255.6 | 0.478 | 0.357 | −0.00041 |

**What to claim in the paper.** ACCM is a *posture-adaptive chaotic mixing
layer with a provable security floor*, applied over an already-complete
AES-256-GCM ciphertext. It is defence in depth and traffic-shape obfuscation.
Do **not** claim the chaos carries confidentiality — §4.2 is the evidence
against that, and a reviewer who runs the same measurement will find it.

Framed honestly this is a *stronger* contribution than the original claim:
"we measured the naive construction, showed it fails in 100% of draws, and
built one with a provable floor" is a real result. The negative result in §4.2
is publishable on its own.

### 4.4 Determinism

ACCM v2 is integer-only — Q32 for the coupled logistic pair, Q16 for Lorenz.
The gateway is C on ARM and the server is CPython on x86-64; a chaotic map
amplifies a one-ULP difference exponentially, so with IEEE-754 doubles any
divergence in FMA contraction, x87 excess precision, or `-ffast-math` would
desynchronise the keystream within a few dozen iterations and silently corrupt
telemetry. Integer arithmetic makes the two ends bit-identical *by
construction*, not by compiler-flag discipline.

`test_accm_kat.py` pins this with 12 vectors, including a 512-byte stream that
spans a chunk boundary. It is the gate that keeps the link working — run it in
CI.

One residual assumption: arithmetic right shift of a negative `int64_t` is
implementation-defined in ISO C, though every targeted compiler (MSVC, GCC,
Clang, xtensa GCC) floors it, matching Python. The KAT fails loudly if that
ever stops holding.

---

## 5. How to build and run

```bash
# C test binaries (needs Visual Studio 2022 Community; edit VCVARS if elsewhere)
tools\build_tests.bat

# 0. Subsystem suites (AES-GCM: NIST vectors/tamper/nonce; ECDHE: RFC 7748/low-order)
%TEMP%\accm_build\test_aead.exe
%TEMP%\accm_build\test_ecdhe.exe
%TEMP%\accm_build\test_node.exe

# 1. KMACXOF256 / SHA3-256: C vs Python  (also checks SHA3 against hashlib)
cd temp_codes\RXCR-KMAC-KDF && python c/tests/compare_kat.py %TEMP%\accm_build\kat_dump.exe

# 2. ACCM v2: C vs Python, plus security properties
python src/security/ACCM/tests/test_accm_kat.py %TEMP%\accm_build\accm_kat.exe

# 3. ACCM keystream statistics
%TEMP%\accm_build\accm_stream_gen.exe %TEMP%\accm_normal.bin 4000000 64 0
python src/security/ACCM/tests/accm_stats.py %TEMP%\accm_normal.bin

# 4. PQC root-key transfer + replay rejection
cd temp_codes\pqcrypto_project\pqcrypto_project && python server.py
python benchmark.py
```

Python deps: `cryptography`, `dilithium-py`, `kyber-py`.

Measured on this machine (ML-DSA-44 sign dominates): ML-KEM encaps 5.0 ms,
decaps 6.7 ms, ML-DSA sign 56 ms, verify 12.7 ms, end-to-end root-key
transfer 91 ms. Root-key transfer is a rare operation, so this is fine — but
it is a reason not to let the DQN rotate the *root* key aggressively.

---

## 6. Open issues, in priority order

**P1 — Post-quantum protection is tiered by link, deliberately.** Leaf
session keys come from X25519 ECDHE, not ML-KEM. This is a decision, not an
oversight, and should be stated in the paper as a risk-based migration
argument rather than defended as "quantum is not a concern here" — which
invites the obvious harvest-now-decrypt-later rebuttal.

The substance:

| | Leaf -> Gateway | Gateway -> Server |
|---|---|---|
| Carries | raw sensor readings | ROOT_KEY + aggregated telemetry |
| Secret lifetime | ephemeral, per session | ROOT_KEY unlocks every derived session key |
| Value in 2040 | a 2026 voltage reading is operationally worthless | key material may still be live |
| Forward secrecy | **yes** (ephemeral X25519) | **no** (static ML-KEM keypair, see P4) |

Note the last row: the leaf tier is actually *stronger* in one dimension. Say
so — it shows the tiering was reasoned, not just cheap.

Residual risk to state honestly rather than let a reviewer find it: a future
quantum adversary who breaks a leaf X25519 exchange can **forge telemetry**,
which on a grid is a safety problem, not only a confidentiality one. The
answer is that forging requires an active attack at that future time, by which
point the leaf tier migrates — the ESP32 is the cheapest component in the
system to replace. Measure ML-KEM-512 on the ESP32 against the per-packet
budgets on slides 20-23 before committing to a date.

**P2 — Posture control plane: DONE.** `tg_control_t` extended to 32 bytes
(directive / node_mask / lease_ms), sealed in AES-256-GCM under the `gw-ctrl`
key, lease state machine with graduated fail-secure escalation, replay guard,
and the `tg_posture_request()` shield. C and Python, 13/13 cross-language
checks — sealed frames byte-identical, 32 state-trace lines identical.

The design point worth carrying into the paper: delivery of an alert cannot be
guaranteed over a network an attacker may control, so the channel is inverted
into a **lease**. The gateway holds its posture only while the lease is
unexpired, which means jamming the control channel *causes* escalation instead
of suppressing it. Lease expiry escalates one level per period and never
auto-quarantines, so the fail-secure path cannot itself be turned into a
denial of service.

**P3 — Gateway KEM public key is trusted implicitly.** The server reads
`gateway_kem_pk.bin` off local disk. In deployment the gateway must sign its
own KEM public key with its ML-DSA key, and the server must hold a trusted copy
of `gateway_dsa_pk.bin`. The gateway ML-DSA keypair is already generated and
currently unused — this is what it is for.

**P4 — No forward secrecy.** The gateway ML-KEM keypair is long-term and on
disk. An attacker who later recovers `gateway_kem_sk.bin` can decapsulate
recorded transfers and recover past ROOT_KEYs. Fix: rotate the gateway KEM
keypair per epoch, with the server re-fetching the public key over an
authenticated channel.

**P5 — The NIST STS run does not test RXCR-Extract.** In
`generate_sts_input.py`, IKM, salt, and info are fixed while only `node_id`
varies. So `rxcr_extract(ikm, salt)` returns the **same PRK for all 1,000,000
blocks** — the corpus measures KMACXOF256's output diversity, which would pass
regardless of what RXCR does. To actually test the extractor, vary the IKM per
block and concatenate the PRKs. Also: 10 sequences is below the ≥55 that SP
800-22 needs for a meaningful proportion column.

**P6 — RXCR-Extract finalizer has a concatenation ambiguity.**
`SHA3-256(state || ikm || salt)` has no length prefixes, so
`(ikm=A‖B, salt=C)` and `(ikm=A, salt=B‖C)` can be confused. Fix is one line —
length-prefix the fields, as `wire.lv()` already does elsewhere. Deferred here
because it changes KDF output and invalidates the existing STS corpus; do it
together with P5.

**P7 — Framing the RXCR novelty claim.** `PRK = SHA3-256(state || ikm || salt)`
feeds ikm and salt *directly* into the finalizer, so the output is already at
least as strong as `SHA3-256(ikm‖salt)` regardless of what RXCR did. That is a
good fail-safe property, but it means the custom extractor contributes nothing
*provable*. Also, the README's claim that HMAC-Extract is "optimized for
DH-style secrets" will not survive review — HKDF is used on KEM secrets
throughout TLS 1.3 hybrid and the ML-KEM specs. Recommended framing: "RXCR is a
hardening pre-mix with a SHA3-256 security floor", backed by ESP32 cycle counts
versus HMAC-SHA256 rather than by a security claim.

**~~P8~~ — RXCR C port: DONE.** `rxcr.c` and `rxcr_kmac_kdf.c` are written and
KAT-verified against the Python reference (17/17 vectors, first try). The leaf
handshake derives its session key through them, and a pure-C gateway is now
possible if that is ever wanted.

**P9 — ACCM inter-frame chaining is transport-fragile.** `prev_tail` chains
each frame to the last, so a dropped frame makes every subsequent frame
undecodable. Fine over TCP, which is what this link uses. It must be dropped if
the transport ever becomes UDP/DTLS, and `tg_replay_guard_t` would need a
sliding bitmap window instead of strict ordering.

**P10 — Parameter set.** ML-KEM-512 / ML-DSA-44 are NIST level 1/2. Deliberate
for now (lightweight, per decision on 2026-09-12); level 3 (768/65) is the
usual recommendation for 20-year grid assets. Revisit before deployment, not
before the demo.

---

## 7. DQN training data

> Superseded in detail by [DQN_SPEC.md](DQN_SPEC.md), which specifies the full
> MDP, reward, shield and evaluation. This section is kept for the dataset
> survey and the reasoning about why no key-rotation dataset exists.

**There is no dataset for this, and that is not a gap — it is a category
error.** Key-rotation policy is not a supervised-learning problem with labelled
examples. A DQN learns from an **environment**, not a corpus. What public data
provides is a realistic *observation stream* to drive that environment.

### 7.1 What to build

A Gym-style environment wrapping the gateway key lifecycle:

- **State** — key age (packets and wall-clock since install), fraction of
  `TG_SEQ_MAX` consumed, current posture, LSTM anomaly score, per-node
  encryption-time headroom (the metrics already on slides 20–23), queue depth,
  time since last root-key transfer.
- **Actions** — hold; rotate session key (bump `key_epoch`); refresh the whole
  pool; request a new ROOT_KEY; escalate/de-escalate posture; quarantine a node.
- **Reward** — negative cost for exposure (key-age × traffic volume), negative
  cost for rotation (the measured 91 ms root transfer, 5–7 ms KEM ops, missed
  telemetry deadlines), large negative for a safety violation.
- **Shielding** — the agent proposes, the guard disposes. `tg_nonce_guard_t`
  already makes nonce reuse unreachable; add hard floors and ceilings on
  rotation interval so exploration cannot produce an unsafe or DoS-ing policy
  on a live system.

Watch the reward design: with anomalies rare, a naive "minimise rotations
subject to no anomaly" reward teaches the agent to never rotate. Give exposure
a continuous cost so holding is never free.

### 7.2 Datasets to drive the observation stream

| Dataset | Why | Access |
|---|---|---|
| **MSU / ORNL Power System Attack Datasets** (Morris et al.) | The canonical match for this case study: two-line three-bus system, 4 PMUs, 128 features, 37 scenarios — 1 normal, 8 natural disturbances, 28 attacks including relay setting change, remote tripping command injection, and data injection. Binary / three-class / multiclass splits in CSV and ARFF | Public; also mirrored via IMPACT |
| **MSU SCADA gas pipeline / water tower** (Turnipseed, 2015) | Raw SCADA network traffic rather than synchrophasor measurements — useful for the protocol-level side | Public via MSU Scholars Junction |
| **SWaT / WADI** (iTrust, SUTD) | Larger industrial testbeds, well-curated, widely cited baselines | Free but requires a signed request form — start this early, it takes time |
| **Electra / ICS-Flow** | ICS network flow data, useful for gateway-tier traffic modelling | Public |

Practical sequencing: the MSU/ORNL set is the one to start with — it matches
the case study directly, the 28 attack scenarios give the LSTM its positive
class, and the same traces can drive DQN episodes. Note the published splits
are sampled at 1%, so for RL episode generation you want the full sets.

### 7.3 On the LSTM data plan

Gathering telemetry after the DQN is running (the stated plan) works for the
*normal* class but will produce almost no attack examples — a rig running
normally generates only negatives. Two ways to get a positive class: label
against MSU/ORNL attack scenarios, or inject the attacks yourself on the rig
(relay trips, command injection, data injection are all reproducible on the
ESP32/RPi setup). Doing both gives a real evaluation. Either way, an LSTM
autoencoder on reconstruction error is the safer first model — it trains on
normal data only, which is the data you will actually have.

Sources:
- [MSU/ORNL Power System Attack Datasets — IMPACT](https://impactcybertrust.org/dataset_view?idDataset=1290)
- [A New SCADA Dataset for Intrusion Detection System Research (Turnipseed, 2015)](https://scholarsjunction.msstate.edu/td/209/)
- [Power System Dataset README](http://www.ece.uah.edu/~thm0009/icsdatasets/PowerSystem_Dataset_README.pdf)

---

## 8. What is left

The cryptographic layer is essentially complete: six suites, all green. What
remains is the **application layer** (no process yet reads a sensor, holds a
session pool, or opens a socket), the **two ML components**, and the **leaf
firmware**.

| Phase | Component | Status | Spec |
|---|---|---|---|
| A | DQN key lifecycle | **done** - fully trained (5000 eps); +1175 vs threshold, 15/15 seeds, 27/27 robustness, DQN_SPEC 12.14 | [DQN_SPEC.md](DQN_SPEC.md) |
| B | LSTM anomaly detection | **built**, 61/61 tests; recall 0.96-0.98, 2.5 ms; **fails on natural disturbances (98-100% false alarms)** - see `server/LSTM/README.md` | [REMAINING_WORK.md](REMAINING_WORK.md) §3 |
| C | ESP32 firmware + telemetry converter | **code complete**, 114/0 on host; ESP32 bring-up deferred to M2 | §4 |
| D | Gateway daemon | **done** - 30/30 | §5 |
| E | Server daemon | **done** - 33/33 | §6 |
| F | Integration and demo | **software path done** - 24/24, real LSTM + real DQN over a loopback socket; p95 42 ms/cycle. Hardware scenarios blocked on M2 | §7 |
| G | Evaluation and paper artefacts | partially done | §8 |

Recommended order is **pipe-first**: build D and E with a stub policy and stub
detector (2–3 days) so an end-to-end demo exists immediately and later
components are written against live interfaces. The two stubs double as two of
the five DQN baselines, so they are not throwaway work. Then A, B and C in
parallel.

See [REMAINING_WORK.md](REMAINING_WORK.md) for the full specs, the residual
security hardening items (P3–P10), effort estimates, and the collected list of
decisions still needed.

---

## 9. Slide corrections needed

| Slide | Issue |
|---|---|
| 16 (ACCM) | "no metadata change indicating anything happened" is unachievable — the posture must be readable before unmasking. Reframe as unforgeable and unpredictable. |
| 16 (ACCM) | "ε shifts from 0.1 to 0.4 … restructuring the attractor" — true, but in v1 that *destroyed* the keystream (3.26 bits/byte). Present the v2 construction and the measurement. |
| 9 (Proposed Solution) | "Kyber for key exchange" is stated system-wide; the leaf tier uses ECDHE. Reframe as tiered PQ migration by link value/lifetime — see P1 for the table to use. |
| 17 (RXCR) | "HKDF-Extract is HMAC-based and optimized for DH-style secrets" will not survive review. See P7. |
| 14 (mapping) | Lists HKDF; the KDF is RXCR-Extract + KMACXOF256, not HKDF. |

## 10. NIST SP 800-22 — what was actually tested

Run with `tools/sts_corpus.py`, which replaces
`temp_codes/RXCR-KMAC-KDF/python/tests/sts/generate_sts_input.py`.

### 10.1 The old corpus tested the wrong thing (P5, fixed)

The previous generator held `IKM`, `salt` and `info` fixed and varied only
`node_id`. `rxcr_extract(ikm, salt)` therefore returned **the same PRK for all
one million blocks**, and every byte of the corpus came out of KMACXOF256's
expand step. The suite measured SHA-3's output diversity — it would have passed
with RXCR replaced by a constant. It also used 10 sequences, below the 55 that
SP 800-22 needs for a meaningful proportion column.

The new generator varies the IKM per block and concatenates the **PRKs**, so
the bits under test are the extractor's own output, and runs 55 sequences.

### 10.2 A control corpus is run every time, and it changed the answer

`os.urandom` is tested alongside, and any test the control fails is excluded
from the verdict.

This is not ceremony. At 100,000 bits this library fails **six of twelve tests
on cryptographically secure random input**: Approximate Entropy, Discrete
Fourier Transform, Serial, Random Excursion, Random Excursion Variant and
Non-Overlapping Template Matching. Several of those need ~10^6 bits to be
meaningful, and 10^6-bit sequences do not finish in usable time in a
pure-Python implementation.

**Without the control the headline would have been "RXCR fails half the NIST
battery", which is false.**

### 10.3 Result: RXCR-Extract


55 sequences x 100,000 bits, 1% significance, minimum proportion 0.950.

| test | `os.urandom` control | RXCR-Extract |
|---|---|---|
| Monobit | 54/55 | **55/55** |
| Runs | 55/55 | **55/55** |
| Binary Matrix Rank | 55/55 | **55/55** |
| Cumulative Sums | 55/55 | **55/55** |
| Frequency Within Block | 54/55 | **54/55** |
| Longest Run of Ones in a Block | 54/55 | **54/55** |

**PASS on all six control-validated tests.**

The stronger observation is in the excluded six: RXCR-Extract tracks the
control almost exactly there too — Serial 0/55 both, Approximate Entropy 0/55
both, DFT 0/55 both, Random Excursion Variant 32/55 both, template matching 38
vs 36. It behaves like `os.urandom` on every test in the battery, passing and
failing the same ones. That correspondence is what establishes the exclusions
as artefacts of the tool rather than weaknesses in the extractor.

### 10.5 Result: ACCM keystream

The corpus is generated **frame by frame**, as `uplink.py` emits it: 64-byte
frames, each re-deriving its parameters from `(session_key, header,
prev_tail)`, chained by tail with sequence number and timestamp advancing.

Pulling one long stream from a single context would have been easier and would
have measured something the system never emits. The two arrangements fail in
opposite directions: a chaotic map that degenerates after a few thousand
iterations looks terrible as one long stream and never arises in per-frame use,
while a re-derivation that depends only weakly on `seq` looks fine as one long
stream and is fatal in deployment. Only the second arrangement tests ACCM as
built.

**Three independent corpora** (different session keys), 55 sequences x 100,000
bits each:

| test | key 0 | key 1 | key 2 | pooled (165) |
|---|---|---|---|---|
| Monobit | 55/55 | 54/55 | 55/55 | **164/165** |
| Runs | 54/55 | 53/55 | 55/55 | **162/165** |
| Binary Matrix Rank | 55/55 | 54/55 | 55/55 | **164/165** |
| Cumulative Sums | 55/55 | 55/55 | 55/55 | **165/165** |
| Frequency Within Block | **52/55** | 55/55 | 55/55 | **162/165** |
| Longest Run of Ones | 55/55 | 55/55 | 55/55 | **165/165** |

Minimum proportion at 1% significance is 0.950. Every pooled figure is 0.982
or better. **PASS.**

#### The one result that needed a second look

Frequency Within Block came out at 52/55 = 0.945 on the first corpus, just
under the 0.950 threshold — 53 would have passed, so a single sequence decided
it. Two possibilities fit: a small real bias, or noise. Under a genuinely
uniform source the chance of 52 or fewer passes is about 1.8%, which is neither
damning nor dismissible.

Two further corpora under different session keys both returned 55/55, and the
pooled figure is 0.982. The honest reading is a sampling fluctuation, and the
reason to state it rather than quietly report the passing runs is that the
opposite outcome — a bias reproducing across keys — would have been a genuine
finding about the construction.

It is also a caution about the threshold itself: at 55 sequences one episode
flips the verdict. Anyone re-running this should expect occasional marginal
failures and should re-test rather than either accepting or reporting them on
a single run.

#### What this does not say

ACCM was already shown to be the *wrong* thing to rely on alone: PROJECT_STATUS
§4 records that ACCM v1's chaos-only keystream failed badly (100% of parameter
draws below 7.99 bits/byte), which is why the deployed construction XORs the
chaotic byte over a KMACXOF256 base stream. These statistics are therefore
substantially a measurement of that base stream, exactly as intended — the
chaotic layer supplies posture-dependent structure, not entropy. A pass here is
evidence that the masking layer does not *damage* the stream it sits on. It is
not evidence that the chaotic map is itself a secure generator, and the paper
must not imply that it is.

### 10.4 What this does and does not license

SP 800-22 is a **necessary condition, not a sufficient one**. A counter
encrypted under AES passes every test in it. The correct claim is "no
detectable statistical structure at this sample size", and nothing stronger.

In particular it says nothing about P7: `PRK = SHA3-256(state || ikm || salt)`
feeds `ikm` and `salt` directly into the finalizer, so the output is at least
as strong as `SHA3-256(ikm‖salt)` whatever RXCR did. That is a good fail-safe
property and it is also why a statistical pass cannot be evidence that the
custom pre-mix contributes anything. Those are separate claims and the paper
should keep them separate.
