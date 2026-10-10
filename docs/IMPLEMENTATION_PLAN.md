# Implementation Plan

2026-09-24 · companion to [PROJECT_STATUS.md](PROJECT_STATUS.md) (what exists),
[REMAINING_WORK.md](REMAINING_WORK.md) (component specs) and
[DQN_SPEC.md](DQN_SPEC.md) (Phase A in detail).

Those three say *what*. This says *in what order, with what acceptance test,
and what has to be decided first.*

---

## 0. Where we are

**Every software phase is built and green. Only hardware work remains.**

| Phase | State |
|---|---|
| A — DQN key lifecycle | **done**, fully trained (5000 eps), 15/15 seeds, 27/27 robustness |
| B — LSTM anomaly detection | **built**; one acceptance criterion genuinely fails (M4) |
| C — ESP32 firmware | **code complete**, host-tested; board bring-up is M2 |
| D — Gateway daemon | **done** |
| E — Server daemon | **done** |
| F — Integration | **done** in software, 24/24; hardware scenarios are M2 |
| G — Evaluation | **done** — every artefact produced, including both NIST randomness runs |

### Suites

| Suite | Result | Last run |
|---|---|---|
| AES-256-GCM | 400 checks, 0 failures | unchanged since M1 |
| ECDHE (X25519) | 23 checks, 0 failures | unchanged since M1 |
| Leaf node (C) | 114 checks, 0 failures | unchanged since M1 |
| Leaf link C↔Python | all pass | unchanged since M1 |
| KMAC + RXCR C↔Python | 17/17 vectors | unchanged since M1 |
| ACCM cross-language | all pass | current |
| Posture control plane | **8/8** | current (the previously recorded 13/13 did not match the file) |
| PQC root-key transfer | round trip + replay rejected | unchanged since M1 |
| Gateway daemon E2E | 30/30 | current |
| **Server daemon E2E** | **33/33** | current |
| **LSTM detector** | **61/61** | current |
| **DQN environment** | **28/28** | current |
| **DQN agent** | **33/33** | current |
| **M5 integration** | **24/24** | current |

**The C suites have not been re-run since M1.** No C file has been touched since
then — every change since has been Python — so the results should still hold, but
they are carried forward rather than re-verified. Rebuild with
`tools/build_tests.bat` (needs an MSVC environment) before quoting them in the
paper.

### Headline results

```
DQN vs threshold   +1175.1  (95% CI +600.8 .. +1749.3), wins 15/15 seeds
                   74% fewer compromised steps (19.3 vs 75.6)
                   using 76% fewer key rotations (12.9 vs 53.9)
robustness         27/27 detector settings, 9/9 under benign disturbances
LSTM               recall 0.96-0.98, detection delay 0.03 s, 2.5 ms inference
                   BUT 98-100% false alarms on natural disturbances
randomness         RXCR-Extract and ACCM both pass NIST SP 800-22
                   (55+ sequences, against an os.urandom control)
end-to-end         p95 41 ms per 1 s cycle, 24/24 integration checks
```

**Everything not blocked by hardware is complete.** The optional hardening in
§3 (P3, P4, P6, P7, P10) is deployment-grade work, not demo-grade, and none of
it blocks the paper.

### The three things a reader must be told

1. **The LSTM flags 98-100% of natural disturbances as attacks.** A genuine
   failure, honestly measured, and the reason this is described as a
   *disturbance* detector whose output a policy weighs rather than an attack
   detector. `server/LSTM/README.md`.
2. **Every DQN result before the M5 recalibration is superseded.** They were
   measured against a benign score distribution that did not match the real
   detector. DQN_SPEC 12.11 and 12.13.
3. **The shipped policy is not the highest-scoring seed.** Seed 21 scored
   better on the trained objective; seed 22 ships because it uses 2.6x fewer
   key rotations for a statistically indistinguishable result, and holds
   NORMAL on calm data where seed 21 parks at SUSPICIOUS. DQN_SPEC 12.15.

### What is actually left

| Work | Blocked on | Effort |
|---|---|---|
| M2 hardware bring-up | the boards | 3–5 days |
| Hardware demo scenarios + ESP32 latency | M2 | folded into M2 |

---

## 1. The two critical paths

They are genuinely separate, and conflating them is the main scheduling risk.

```
DEMO PATH        M1 server ──▶ M2 hardware ──▶ M5 integration ──▶ working demo
                     │                              ▲
                     └──────────────────────────────┤
PAPER PATH       M3 DQN ────────────────────────────┤
                 M4 LSTM ───────────────────────────┘ ──▶ M6 results
```

- **Demo path** produces something that runs on the bench. Low risk, mostly
  known work, and it is what a viva actually sees.
- **Paper path** produces the novel results. Higher risk, and the part a
  reviewer judges.

M3 and M4 depend on **nothing** from M2. The DQN trains against a simulator and
the LSTM trains against MSU/ORNL. If the hardware fights you, the research
results are not blocked — and vice versa.

**If you have teammates, split along that line.** One person on M1+M2, one on
M3, one on M4. They only rejoin at M5.

---

## 2. Milestones

### M1 — Close the pipe (Phase E, server daemon) — **DONE**

**Result: 33/33 full-pipe checks.** Real gateway daemon against real server
daemon over a loopback socket, simulated ESP32 feeding the gateway. Verified:
5-batch round trip, posture command reaching the gateway and echoing back,
quarantine isolating one channel while four keep flowing, a non-compliant
gateway detected and alerted, replayed frames rejected, key rotation followed
across the link, a silent server escalating the gateway on its own, and a
60-tick soak with zero rejects and exactly 60 sequence numbers consumed.

Two real bugs were found by these tests, neither visible from either side alone:

  * **A persistently non-compliant gateway was never detected.** The server
    re-issues a command while the condition holds, and each re-issue restarted
    the echo window — so the counter reset faster than it could expire. The
    window now measures "how long have I been asking", not "when did I last
    ask".
  * **The ACCM chain desynchronised on key rotation.** The server reset
    `prev_tail` when adopting a new `key_epoch`; the gateway carried its chain
    over. The first frame under a new key unmasked to garbage and failed the
    GCM tag. The reset now lives in `Uplink`, which owns the chain and sees the
    epoch on every send, so it holds however the rotation was triggered.

Original scope follows, for reference.

**Why first:** it is the last piece of the transport, it is cheap, it unblocks
rig data collection for M4, and everything downstream plugs into it.

**Build:**

| File | Contents |
|---|---|
| `server/python/server_state.py` | per-gateway state, `ctrl_epoch`/`ctrl_seq` persistence, replay guard, posture-echo tracking |
| `server/python/telemetry_rx.py` | replay check → ACCM unmask → GCM decrypt (AAD = header) → batch decode |
| `server/python/lease.py` | lease issuance, the ADVISE/ENFORCE/QUARANTINE ladder, `min_hold_ms` |
| `server/python/detector.py` | `Detector` protocol + `StubDetector` (rolling-variance threshold) |
| `server/python/daemon.py` | asyncio TCP listener, one task per gateway |
| `server/tests/test_server.py` | end-to-end against the **real** gateway daemon over a loopback socket |

**Acceptance:**
- real gateway daemon ↔ real server daemon, 60 s soak at 1 Hz, zero errors
- lease renews on every batch; cutting the link escalates NORMAL→SUSPICIOUS→ANOMALY
- an ENFORCE command round-trips and the **posture echo** is verified in the
  next frames
- a replayed control frame is rejected; a replayed telemetry frame is rejected
- zero nonce reuse across a simulated restart of both ends

**Blockers:** none. **Effort:** 2–3 days.

---

### M2 — Hardware bring-up (finish Phase C)

**Build:** nothing new — flash `src/hardware/ESP32/` and make it work.

**Order matters here, because the failures look alike:**

1. **Provision the PSK.** Write the 32-byte `device_psk` blob into NVS
   namespace `iiot_node`. Without it the node refuses to run, which is the
   intended behaviour and the first thing you will hit.
2. **MCP3008 first, DHT22 second.** SPI is deterministic; the 1-wire bit-bang
   is not. Debug them separately or you will not know which is failing.
3. **Check channel mapping against `channel_config.c`.** A swapped
   voltage/current pair produces plausible-looking data that is silently wrong.
   Watch for `CH_QUALITY_RANGE` on first boot — that is what the plausibility
   bands are for.
4. **Calibrate** `scale`/`offset` against a reference meter. The current values
   are deliberately round placeholders so an uncalibrated build is obvious.
5. **Then** connect the real leaf to the real gateway.

**Acceptance:**
- five channels reporting plausible engineering units, `CH_QUALITY_GOOD`
- handshake completes against the gateway daemon; CONFIRM verifies
- 1 hour at 10 Hz with zero auth failures and zero replay rejects
- measured per-frame latency on the ESP32, recorded for the paper

**Blockers:** none. **Effort:** 3–5 days, mostly debugging, mostly DHT22.

**Contingency:** if DHT22 timing proves unreliable, swap in esp-idf-lib's `dht`
component rather than tuning delays. It is not where the project's value is.
If that also fails, drop to 4 channels and say so — the architecture does not
care, and a wrong reading is worse than a missing one.

---

### M3 — DQN (Phase A) — **DONE**

**Full spec: [DQN_SPEC.md](DQN_SPEC.md).** Build order matters — each step is
testable before the next.

| Step | File | Test before moving on |
|---|---|---|
| 1 | `src/ML/dqn/costs.py` | action costs match `benchmark.py` measurements |
| 2 | `src/ML/dqn/detector.py` | surrogate produces the requested fpr/fnr over 10⁵ samples |
| 3 | `src/ML/dqn/telemetry.py` | MSU/ORNL traces resample to 1 s without gaps |
| 4 | `src/ML/dqn/env.py` | imports the **real** `PostureState`/`NonceGuard`, not copies |
| 5 | `src/ML/dqn/shield.py` | wraps the real `policy.Shield`; unsafe actions unreachable |
| 6 | `src/ML/dqn/baselines.py` | the 4 existing policies + oracle |
| 7 | `src/ML/dqn/agent.py` | Double DQN + dueling |
| 8 | `train.py`, `evaluate.py` | |

**Do step 4 by importing, not reimplementing.** The environment must use the
same `PostureState` the gateway runs, or the policy learns against a model of
the system rather than the system.

**Acceptance - all five met** (fully trained, DQN_SPEC 12.14)**:**

| Criterion | Result |
|---|---|
| beats `threshold` on mean episode return | **yes** -- `+1175.1`, 95% CI `+600.8 .. +1749.3`, wins **15/15** seeds |
| **zero** nonce-exhaustion events | **yes**, non-vacuously -- tested at 1800 steps where the guard rail is reachable |
| blocked-unsafe-action count non-zero | **3.5 per episode**. The *forcing* path never fired, so it is untested by this run -- DQN_SPEC 12.9 |
| robustness curve across `(fpr, fnr, delay)` | **yes** -- **27/27**, plus **9/9** in the disturbance regime |
| 5-baseline comparison table | **yes** -- DQN_SPEC 12.14 |

**The claim: 74% fewer compromised steps than `threshold` (19.3 vs 75.6) using
76% fewer key rotations (12.9 vs 53.9).** Cheaper and safer at once, on the
cost an operator actually pays.

Deployed: `src/ML/dqn/runs/final_seed22/`. 5000 episodes, 748,000 gradient
steps. **Not** the highest-scoring seed — DQN_SPEC 12.15 gives the reasoning,
which is operational rather than statistical.

**Effort:** actual -- completed in resumable chunks after `--resume` was added;
a single run exceeds the harness background-command limit.

**Contingency:** if the DQN does not beat `threshold`, that is a *result*, not
a failure — report it honestly with the robustness curve showing where each
wins. A negative result with good methodology is publishable; a fabricated
positive is not. Budget a week for this possibility rather than panicking.

---

### M4 — LSTM (Phase B) — **BUILT; one acceptance criterion failed**

**Start with MSU/ORNL. It needs nothing from this system.**

| Step | File | Note |
|---|---|---|
| 1 | `server/LSTM/data.py` | MSU/ORNL loader; 37 scenarios, 128 features |
| 2 | `server/LSTM/model.py` | LSTM autoencoder, 60 s window |
| 3 | `server/LSTM/train.py` | trains on **normal only** — the data you will actually have |
| 4 | `server/LSTM/calibrate.py` | ECDF over held-out normal → calibrated `[0,1]` score |
| 5 | `server/LSTM/detector.py` | implements the `Detector` protocol incl. `attribute()` |
| 6 | `server/LSTM/evaluate.py` | PR curves, detection delay, attribution accuracy |

**`attribute()` is not optional.** Quarantine needs to know *which* channel,
and `node_mask` already carries it. Per-feature reconstruction error gives it
for free — another reason for the autoencoder over a classifier.

**Acceptance - four of five met, the fifth measured and FAILED:**

| Criterion | Result |
|---|---|
| PR curve, not just ROC | **yes** — and reported two ways. Operational (faults count as false alarms) **AP 0.964**; attacks-vs-calm-grid 0.999. The second is the flattering one and must not be headlined |
| per-scenario breakdown, 28 attack types | **yes** — median recall 1.000. Weakest are #40 (0.46) and #39 (0.77), both "maintenance with relays disabled": the attacks disguised as routine work |
| detection delay distribution | **yes** — median 3–4 rows = **0.03 s**, p90 17 rows |
| inference latency inside the 1 s window | **yes** — **2.5 ms**, 0.25% of budget |
| the 8 natural disturbances handled as the false-positive source | **NO.** Measured at **98–100% false alarms**, at every operating point. Retraining with faults as benign did not help (the apparent gain was a test-set artifact — see `server/LSTM/README.md`) |

**This is a negative result with a clean methodology, and it is reportable.**
A reconstruction autoencoder measures *unusual*, and a fault is extremely
unusual; the mechanism that catches attacks is the one that fires on storms.
The honest framing is that this is a **disturbance detector** and the
discrimination comes from the DQN's handling of uncertain evidence — the score
is calibrated input to a policy, not a verdict, and the posture ladder is
"isolate and continue as untrusted", not instant quarantine.

**Blocks an M5 claim until addressed:** M3's surrogate has a single `fpr`, but
the real detector has two — about 0.05 on a calm grid and about 1.0 during a
fault. The 27-point sweep only reaches fpr 0.15. **Extend the sweep before any
end-to-end claim.**

**Dataset:** recovered from the Internet Archive — the original UAH host
(`ece.uah.edu/~thm0009/`) is dead. Files and the scenario-grouping
verification are in `data/msu_ornl/`, loader in `server/LSTM/data.py`.

**Effort:** actual — one session. Training 80 s (calm-grid) / 375 s (benign).



---

### M5 — Integration (Phase F) — **software path DONE; 24/24**

`server/tests/test_integration.py` runs the real gateway and server daemons
over a loopback socket with **every stub removed**: the trained LSTM behind the
`Detector` protocol, and the trained DQN through its deployable NumPy path.
Hardware scenarios wait on M2; nothing else does.

Figures land in `server/tests/integration_figures.json`.

| Scenario | Result |
|---|---|
| 1. normal operation | 132/132 batches, 0 rejected, lease renewing, posture holds NORMAL |
| 2. injected attack | score 0.512 → 1.000, posture NORMAL → ANOMALY, 0 echo violations |
| 3. control channel cut | gateway escalates unaided NORMAL → SUSPICIOUS → ANOMALY, telemetry still collected, **no auto-quarantine** |
| 4. quarantine and release | real detector isolates channel 2, four keep flowing, channel recovers while isolated, triage releases, stays released |
| 5. latency budget | **p95 42 ms per full cycle**, detector 2.2–3.4 ms — 4% of the 1 s window |

**Connecting the two trained models found four defects that neither found
alone.** Every one of them produced a working-looking system.

1. **The gateway's detector slot was never filled.** `_observe` reads a
   gateway-local detector (DQN_SPEC 3.4); only the server had one. The policy
   therefore saw `lstm_score = 0.0` on every tick — the single input it most
   depends on, permanently absent, with no error anywhere.

2. **The calibration contract and the DQN surrogate disagreed about what a
   normal score looks like.** This is the big one; see DQN_SPEC 12.11.

3. **Every score threshold in `lease.py` was set for a detector that reads
   near zero when nothing is wrong.** Under ECDF calibration the score is
   uniform on normal data, so a threshold *is* its false-alarm rate:
   `quarantine_score = 0.9` meant quarantining a healthy channel on 10% of
   windows. Re-derived: 0.95 / 0.99 / 0.999 for suspicious / anomaly /
   quarantine.

4. **Quarantine was permanent in practice.** The detector read
   `batch.trusted` only, so an isolated channel's last bad value was carried
   forward for ever, kept scoring as anomalous, and was re-quarantined the
   moment triage released it. It now ingests untrusted samples too — safe,
   because this is a detector and not a control path, and a hostile input can
   only push reconstruction error *up*.

**Retraining against the corrected surrogate fixed the last failure.** Proposed
actions on calm data, before and after, measured in the live loop:

| | before | after |
|---|---|---|
| HOLD | 5% | **92.3%** |
| ROTATE_SESSION_KEY | 42% | **0%** |
| final posture | ANOMALY | **NORMAL** |

The policy was never broken; it was reading a score whose meaning had shifted
under it. Re-fitting the surrogate to the measured distribution was the whole
repair.

**Caveat on the deployed weights.** `runs/cal_seed12` is the best of three
seeds but reached only **1900 of 5000 episodes** — the retraining run was cut
short by a platform background-time limit, not by convergence. It passes every
integration check and beats the baselines, but it is under-trained relative to
the ~5000-episode plateau measured in DQN_SPEC 12.10. That section also found
the remaining gain from more episodes to be small (about +110, against +338
from fixing checkpoint selection), so this is a known and bounded shortfall
rather than an unknown one. Re-run to 5000 when there is an uninterrupted
window.

**What already holds regardless:** scenarios 2–5 pass with a mis-specified
policy in the loop. That is the safety envelope doing exactly its job — the
shield bounded the damage, the posture ladder never auto-quarantined, and no
frame was ever rejected or replayed. A system that only behaves when its policy
is correct would not have survived this.

**Effort:** actual — one session for the software path. Hardware scenarios
remain blocked on M2.

---

### M6 — Evaluation (Phase G)

| Artefact | Source | Status |
|---|---|---|
| PQC benchmark table | `benchmark.py` | **done** |
| ACCM keystream statistics | `accm_stats.py` | **done** |
| ACCM v1 failure evidence | PROJECT_STATUS §4.2 | **done** — publishable alone |
| Leaf per-frame latency | `test_node.exe` | **done** (host); redo on ESP32 at M2 |
| DQN vs 5 baselines | M3 | **done** -- DQN_SPEC 12.13, re-run against the corrected surrogate |
| DQN robustness curve | M3 | **done** -- **27/27** plus **9/9** disturbance, DQN_SPEC 12.13 |
| LSTM PR + detection delay | M4 | **done** -- operational AP 0.964, delay 0.03 s; false alarms on natural disturbances 98-100% (`server/LSTM/README.md`) |
| End-to-end latency budget | M5 | **done** -- p95 42 ms per cycle, 4% of the 1 s window (`server/tests/integration_figures.json`) |
| NIST STS on ACCM (≥55 sequences) | `tools/sts_corpus.py --only accm` | **done** — 3 corpora x 55 seqs, pooled 162/165 or better on every control-validated test. PROJECT_STATUS §10.5 |
| NIST STS on RXCR **with varying IKM** | `tools/sts_corpus.py` | **done** — 55 seqs x 100k bits, PASS on all 6 control-validated tests; indistinguishable from `os.urandom` across the whole battery. PROJECT_STATUS §10 |

**Effort:** 1 week, rolling.

---

## 3. Parallel track — residual hardening

None of these block a milestone. Do them in gaps; each is small.

| ID | Item | Effort |
|---|---|---|
| **P5** | STS corpus did not exercise RXCR-Extract (fixed IKM ⇒ same PRK every block) — **fixed**: `tools/sts_corpus.py` varies the IKM per block and tests the PRKs directly, with 55 sequences and an `os.urandom` control | done |
| **P6** | RXCR finalizer concatenation ambiguity — length-prefix it | 1 hour, **do with P5** since it changes every derived key |
| **P3** | Gateway KEM public key trusted implicitly — sign it with the (already generated, unused) gateway ML-DSA key | half day |
| **P4** | No forward secrecy on the root-key transfer — rotate the gateway KEM keypair per epoch | 1 day, depends on P3 |
| **P7** | RXCR novelty framing — reframe as "hardening pre-mix with a SHA3-256 floor", back with ESP32 cycle counts | writing only |
| **P10** | ML-KEM-512 / ML-DSA-44 are level 1/2 — revisit before deployment, not before the demo | — |
| **P11** | ~~Three modules named `detector.py`~~ — **done**: renamed to `lstm_detector.py` and `surrogate_detector.py`; the `sys.modules`-swapping workaround in `test_integration.py` is deleted | done |
| **P12** | ~~Re-run DQN training to 5000 episodes~~ — **done**: all three seeds reached 5000 episodes via `train.py --resume`; `final_seed22` ships (DQN_SPEC 12.14) | done |

**P11 is the one most likely to bite someone else**: it produces an
`ImportError` about a name that plainly exists in the file being imported,
and the cause is invisible at the call site.

**P5+P6 are the highest value for the paper**, because the current STS result does not
measure what the paper claims it measures. A reviewer who reads
`generate_sts_input.py` will notice.

---

## 4. Decision gates

| # | Decision | Blocks | Default if unanswered |
|---|---|---|---|
| D1 | `w_miss / w_fp` ratio | M3 reward | 20:3 |
| D2 | Detector surrogate: sweep `(fpr,fnr)` or fit from MSU/ORNL | M3 | sweep — gives the robustness curve for free |
| D3 | **PyTorch or NumPy-only** | **M3 start** | PyTorch |
| D4 | LSTM: autoencoder only, or AE + supervised classifier | M4 scope | AE only; add the classifier if time allows |
| D5 | Posture-echo window K | M1 | 5 frames |

**D3 is the only hard blocker.** D1 is a genuine judgement call about how much
worse a missed intrusion is than a false alarm — that one is yours, not mine.

---

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| DHT22 bit-bang timing unreliable | **high** | low | swap to esp-idf-lib `dht`; or drop to 4 channels |
| MCP3008 register/channel mapping wrong | medium | medium | plausibility bands flag it on first boot |
| DQN does not beat `threshold` | **medium** | medium | report honestly with the robustness curve — it is a result |
| MSU/ORNL feature space ≠ rig feature space | **high** | medium | expected; train on MSU/ORNL for the paper, fine-tune on rig data for the demo |
| Surrogate-trained policy transfers poorly to the real LSTM | medium | medium | train across a *distribution* of `(fpr,fnr,delay)`, not one setting |
| ESP32 register backend never validated | low | low | already fails at compile time; use the mbedTLS backend |
| Time runs out | — | — | §6 |

---

## 6. Minimum viable outcome

If time runs short, this is the smallest set that still gives a working demo
**and** a defensible paper:

**Must have:**
- M1 (server) + M2 (hardware) + demo scenarios 1 and 3
- the existing nine test suites
- the PQC benchmark table
- **the ACCM v1 negative result** — measured, publishable on its own
- the leaf latency numbers

**Should have:**
- M4 (LSTM) on MSU/ORNL only, simulation results

**Nice to have:**
- M3 (DQN) with the baseline comparison
- rig-collected LSTM data

Note what that implies: **the security contribution is already complete and
evidenced.** The ML components strengthen the paper but the crypto work,
including the negative result on chaotic keystreams, stands without them.

---

## 7. Suggested order from here

Solo:

```
M1 (2-3d) → D3 answered → M3 (1-2w) ∥ M2 (3-5d) → M4 (1-2w) → M5 (3-5d) → M6 (1w)
```

With teammates, split at §1's dotted line: one on M1→M2, one on M3, one on M4,
rejoin at M5. P5+P6 fit in any gap.

**Immediate next action:** M1, the server daemon. It blocks rig data collection
and it is the last piece of transport. Two to three days, no open decisions.
