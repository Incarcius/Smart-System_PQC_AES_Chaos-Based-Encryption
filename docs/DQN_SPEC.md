# DQN Specification — Adaptive Key Lifecycle and Threat Response

Draft 1 · 2026-09-12 · companion to [PROJECT_STATUS.md](PROJECT_STATUS.md)

This is the design to build against. Sections marked **[DECIDE]** need your
answer before implementation starts.

---

## 1. Scope: what is actually an RL problem

The single biggest risk to this contribution is a reviewer asking *"why
reinforcement learning instead of a rule?"* and the answer being weak. So the
scope is drawn deliberately narrow.

| Decision | RL? | Why |
|---|---|---|
| Rotation interval under normal load | **No** | NIST SP 800-57 crypto periods and GCM data limits already answer this. Hard rule. |
| Nonce exhaustion | **No** | Hard invariant, already enforced by `tg_nonce_guard_t`. |
| Per-packet algorithm choice (slides 20–24) | **No** | The 80%/40% threshold heuristic works and is explainable. Keep it, separate layer, different timescale. |
| Lease expiry escalation | **No** | Fail-secure rule in `tg_posture_tick()`. |
| **Graded threat response under detector uncertainty** | **Yes** | This is the contribution. |

**The RL problem, stated precisely:**

> The gateway holds a finite budget — CPU time, latency headroom, bandwidth,
> operator attention — and must allocate it across competing security
> responses while *uncertain whether an attack is actually happening*, using a
> detector that is noisy, delayed, and may itself be under attack.

That is a POMDP: hidden state is "is this system compromised", observation is
the LSTM score plus local telemetry, actions are graded responses with real
measured costs. **The agent never observes ground truth.** That is what makes
the learned policy interesting rather than a lookup table — it has to price
false positives against false negatives given a detector whose reliability it
can only infer.

The Ukraine case study motivates the last clause directly: phase 5 was a DDoS
against operators, i.e. an attack on the detection channel itself. An agent
that reasons about *"my detector has gone quiet"* is doing something a
threshold rule cannot.

---

## 2. Timing model

**One step = one aggregation window = 1 s.**

Per-packet (10 Hz × 5 channels) is far too fast for key decisions and would
make credit assignment hopeless. The 1 s window also matches the piggybacked
lease cadence, so one step is exactly one control-plane round trip.

| Layer | Period | Owner |
|---|---|---|
| Sensor sample | 100 ms | ESP32 |
| Per-packet algorithm choice | per packet | threshold heuristic (not the DQN) |
| **DQN step** | **1 s** | **agent** |
| Lease renewal | 1 s (piggybacked) | server |
| Lease expiry | 3 s | `tg_posture_tick()` |
| Episode | 3600 steps (1 h) | simulator |

---

## 3. State space — 26 dimensions

All features normalised to roughly `[0, 1]`, clipped where noted. Grouped by
origin so it is obvious which are already available and which need plumbing.

### 3.1 Threat (7)

| # | Feature | Source | Notes |
|---|---|---|---|
| 0 | `lstm_score` | server | raw anomaly score, 0–1 |
| 1 | `lstm_ewma_fast` | derived | α = 0.3 |
| 2 | `lstm_ewma_slow` | derived | α = 0.05; the gap between 1 and 2 encodes trend |
| 3–5 | `posture` one-hot | `tg_posture_effective()` | NORMAL / SUSPICIOUS / ANOMALY |
| 6 | `time_in_posture / min_hold_ms` | `posture_since_ms` | clipped to 2.0; tells the agent when de-escalation becomes legal |

### 3.2 Control plane (5)

| # | Feature | Source | Notes |
|---|---|---|---|
| 7 | `lease_remaining / lease_ms` | `lease_expires_ms` | **0 means expired.** The "is my detector still alive" signal |
| 8 | `time_since_last_ctrl / lease_ms` | state machine | clipped to 3.0 |
| 9 | `directive_floor / 2` | `directive_floor` | 0, 0.5, 1 |
| 10 | `quarantined_channels / n_channels` | `node_mask` popcount | channels, not endpoints — see REMAINING_WORK §0b |
| 11 | `ctrl_reject_rate` | counter | replay/stale rejections per window — someone is forging control messages |

### 3.3 Key lifecycle (6)

| # | Feature | Source | Notes |
|---|---|---|---|
| 12 | `seq / TG_SEQ_MAX` | `tg_nonce_guard_t` | nonce exhaustion |
| 13 | `key_age_wall / crypto_period` | timer | clipped to 2.0 |
| 14 | `bytes_under_key / volume_threshold` | counter | GCM data limit |
| 15 | `time_since_root_transfer / root_period` | timer | clipped to 2.0 |
| 16 | `rotations_in_window / max_rotations` | counter | lets the agent see its own thrash |
| 17 | `pool_size / max_pool` | KDF pool | |

### 3.4 Local fast-path detection (4)

These are the gateway's own signals, available in microseconds rather than
waiting a server round trip. **Free and high-value** — no inference needed.

| # | Feature | Source | Notes |
|---|---|---|---|
| 18 | `gcm_auth_fail_rate` | `AEAD_ERR_AUTH_FAILED` count / frames | the single best cheap intrusion signal: normal operation produces zero |
| 19 | `replay_reject_rate` | `tg_replay_check()` failures | |
| 20 | `silent_channels / n_channels` | per-channel timers | |
| 21 | `rate_deviation` | `|rate − baseline| / baseline` | clipped to 2.0 |

### 3.5 Resource (4)

| # | Feature | Source | Notes |
|---|---|---|---|
| 22 | `worst_endpoint_budget_util` | slides 20–23 metrics | the existing 80% breach metric; constant when m=1 |
| 23 | `mean_budget_util` | same | |
| 24 | `queue_depth / queue_max` | gateway | |
| 25 | `cpu_headroom` | `1 − utilisation` | |

**Frame stacking:** stack the last 4 observations → effective input 104-dim.
Cheap, and it gives the network temporal context without an RNN. Revisit only
if that proves insufficient.

---

## 4. Action space — 8 discrete actions

| # | Action | Effect | Measured cost |
|---|---|---|---|
| 0 | `HOLD` | nothing | 0 (but exposure accrues) |
| 1 | `ROTATE_SESSION_KEY` | bump `key_epoch`, re-derive one endpoint's key | ~1 KMAC, sub-ms |
| 2 | `REFRESH_POOL` | re-derive every endpoint key | m × KMAC |
| 3 | `REQUEST_ROOT_KEY` | full PQC handshake | **91 ms**, 3.2 KB |
| 4 | `ESCALATE_POSTURE` | `tg_posture_request(posture+1)` | ~0 crypto |
| 5 | `DEESCALATE_POSTURE` | `tg_posture_request(posture−1)` | ~0, often refused |
| 6 | `QUARANTINE_WORST_CHANNEL` | isolate the highest-suspicion channel, recycle its endpoint's key | high operational |
| 7 | `FORCE_FLUSH` | send the aggregation buffer now | bandwidth; gets data to the LSTM sooner |

Action 7 is worth noting: it lets the agent **buy information**. Flushing
early shortens detection latency at bandwidth cost — a genuine
explore/exploit tradeoff inside the security problem, not a bolted-on one.

Costs for 1–3 come from `benchmark.py` on real hardware. That is a real
strength of this work: the cost model is measured, not assumed.

---

## 5. Reward

```
r_t = −( w_exp  · exposure_t
       + w_act  · action_cost_t
       + w_lat  · latency_penalty_t
       + w_miss · missed_detection_t
       + w_fp   · false_positive_t )
```

### 5.1 Exposure — the term that makes the whole thing work

```
exposure_t = (key_age_norm + bytes_under_key_norm) · posture_multiplier
posture_multiplier = {NORMAL: 1.0, SUSPICIOUS: 2.0, ANOMALY: 4.0}
```

**Continuous and always accruing.** This is non-negotiable. Anomalies are
rare, so a reward of "minimise rotations subject to no anomaly" teaches the
agent to *never rotate* — the single most common failure in RL-for-security
work. Exposure makes `HOLD` cost something, always.

The posture multiplier encodes that stale keys matter more when you already
suspect an intrusion.

### 5.2 Missed detection — requires simulator ground truth

```
missed_detection_t = 1 if (compromised_t AND posture == NORMAL) else 0
```

Large weight. **The agent cannot observe `compromised_t`** — only the noisy
score. This asymmetry is the learning signal.

### 5.3 False positive

```
false_positive_t = 1 if (NOT compromised_t AND posture == ANOMALY) else 0
```

Plus quarantine cost while a healthy node is isolated. Without this the agent
learns to sit in ANOMALY forever, which is safe and useless.

### 5.4 Suggested starting weights

| Weight | Value | Rationale |
|---|---|---|
| `w_exp` | 1.0 | reference scale |
| `w_act` | 1.0 | costs already in comparable units |
| `w_lat` | 2.0 | a missed deadline on a grid is worse than a rekey |
| `w_miss` | 20.0 | ~20× an unnecessary rekey **[DECIDE]** |
| `w_fp` | 3.0 | real but recoverable |

**Run a sensitivity sweep over `w_miss / w_fp` and report it.** That preempts
"you tuned the reward until it worked" — the honest framing is a Pareto curve
of missed detections vs false escalations, with the chosen operating point
justified.

---

## 6. The shield

The agent proposes; the guard disposes. Unsafe actions are **unreachable**,
not penalised — a policy must not be able to learn its way into a nonce reuse.

| Rule | Enforced by |
|---|---|
| Never reuse (key, nonce) | `tg_nonce_guard_t` — already built |
| `seq > 0.9 · TG_SEQ_MAX` → force rotate | shield wrapper |
| key age > crypto period → force rotate | shield wrapper |
| ≤ N rotations/min, ≤ 1 root transfer/M min | shield wrapper |
| No de-escalation below `directive_floor` | `tg_posture_request()` — already built |
| No de-escalation before `min_hold_ms` | `tg_posture_request()` — already built |
| `QUARANTINE` legal only at ANOMALY | shield wrapper |
| Lease expiry forces escalation | `tg_posture_tick()` — already built |

Four of eight already exist in shipped, tested C and Python. The shield
wrapper adds the rest.

**Report "unsafe actions attempted and blocked" as a metric.** It shows the
envelope is load-bearing rather than decorative, and it is the answer to
"would you let an RL agent run a substation?"

---

## 7. Simulator

No public dataset exists for key-rotation decisions, and that is not a gap —
it is a category error. A DQN learns from an *environment*. Public data
supplies the observation stream.

### 7.1 Components

**Telemetry generator.** Replays MSU/ORNL power-system traces (two-line
three-bus, 4 PMUs, 37 scenarios: 1 normal, 8 natural disturbances, 28
attacks), resampled to the 1 s window. Natural disturbances are important —
they are the false-positive source that makes the problem non-trivial.

**Attack model.** Episode has probability `p_attack` of containing a
compromise window `[t_start, t_end]`. During it `compromised_t = 1`, the
telemetry switches to an attack scenario, and local signals shift
(`gcm_auth_fail_rate` rises if the attacker is forging).

**Detector surrogate — this is what unblocks the ordering problem.** You
planned to gather LSTM data after the DQN runs, which is circular. It isn't,
if the detector is modelled parametrically:

```
score_t ~ Beta(a_pos, b_pos)  if compromised and t > t_start + delay
score_t ~ Beta(a_neg, b_neg)  otherwise
```

parameterised by `(fpr, fnr, delay)`. Train the DQN **now** against a
distribution over detector quality, then swap in the real LSTM. You get a
better result than a single trained pair: a **robustness curve across detector
quality**, which is a stronger claim than "it works with our LSTM".

**Crypto cost model.** Measured values from `benchmark.py`: ML-KEM encaps
5.0 ms, decaps 6.7 ms, ML-DSA sign 56 ms, verify 12.7 ms, end-to-end root
transfer 91 ms, AES-GCM ~0.03 ms.

**Control plane model.** Server issues leases at 1 Hz; the attacker may block
the channel during a compromise window, exercising fail-secure escalation.

### 7.2 Episode

- 3600 steps (1 simulated hour)
- `p_attack = 0.3`; compromise window 60–600 s at a random offset
- Terminates at step limit; no early termination (the system does not "die")

---

## 8. Agent

**Double DQN + dueling heads.** Double DQN because vanilla DQN's
overestimation bias is dangerous here: it would systematically overvalue
expensive actions like `REQUEST_ROOT_KEY`. Dueling because most states have
no urgent decision, so separating V(s) from A(s,a) helps a lot.

| Hyperparameter | Value |
|---|---|
| Network | MLP 104 → 256 → 256 → (V:1, A:8) |
| Activation | ReLU |
| Optimiser | Adam, lr 1e-4 |
| γ | 0.99 (≈100 s horizon at 1 Hz) |
| Replay buffer | 200k transitions |
| Batch | 64 |
| Target update | every 1000 steps |
| ε-greedy | 1.0 → 0.05 over 100k steps |
| Training steps | 1–2 M |

Prioritised replay is optional — try it only if compromise windows prove too
rare for the agent to learn from. Start without; it is a common source of
silent bugs.

---

## 9. Evaluation

**Baselines are mandatory.** Without them this is not a result.

| Baseline | Why |
|---|---|
| `never-rotate` | floor |
| `fixed-interval` | NIST crypto period — what you would ship without RL |
| `threshold-on-score` | escalate when score > τ, τ tuned — **the one to beat** |
| `always-max-security` | shows the cost of paranoia |
| `oracle` | sees ground truth — ceiling |

If DQN does not beat `threshold-on-score`, that is worth knowing in week one,
and it is publishable either way.

**Metrics:** mean episode return · time-to-escalation after compromise onset ·
false escalation rate · rekeys/hour · missed-detection step count ·
nonce-exhaustion events (must be 0) · unsafe actions blocked · robustness
curve across `(fpr, fnr, delay)`.

---

## 10. Integration path

1. Env with stubbed control plane → trainable agent (fastest to a result)
2. Swap stubs for the real `PostureState` / `NonceGuard` (both already exist
   and are tested)
3. Replace the detector surrogate with the trained LSTM
4. Run the policy on the RPi against live telemetry

The env should import the **real** `protocol.py` `PostureState` from step 1
rather than reimplementing the semantics — the shield is already written and
cross-validated against C, so reimplementing it in the simulator would just
create a second version to keep in sync.

---

## 11. [DECIDE] — questions before implementation

1. ~~**Node count.**~~ **Settled.** Prototype is **5 measurement channels,
   1 crypto endpoint (ESP32), 1 gateway, 1 server**; industry scales the
   endpoint count. `node_mask` indexes channels (up to 32). The environment
   simulates 6-12 endpoints so per-endpoint features are not degenerate, while
   the prototype runs 1 — state-vector shape is identical either way. See
   [REMAINING_WORK.md](REMAINING_WORK.md) §0b.

   Still needed: **which 5 channels?** The deck names voltage (ZMPT101B),
   current (ACS712), temperature (DHT22) and relay state — that is 4. The
   fifth pins the LSTM input dimension (`F = channels x features_per_channel`).

2. ~~**Where does the agent run?**~~ **Settled: Python on the RPi**, in the
   gateway daemon process, using the Python crypto modules directly. Measured
   at 2.9% of the 1 s window, with Python's AES-GCM actually faster than the C
   build (OpenSSL/AES-NI vs table-based tiny-AES). The environment therefore
   imports the real `PostureState` and `NonceGuard`, not a mirror. Key-hygiene
   caveat and mitigations in [REMAINING_WORK.md](REMAINING_WORK.md) §0c.

3. **`w_miss / w_fp` ratio.** Suggested 20:3. This is a utility judgement
   about your deployment, not something I can derive — how much worse is a
   missed intrusion than an unnecessary escalation, roughly?

4. **Detector surrogate:** sweep `(fpr, fnr)` over a plausible range, or fit
   them from a quick classifier on MSU/ORNL first? Fitting is more defensible;
   sweeping is faster and gives the robustness curve.

5. **Framework:** PyTorch (recommended — you will want it for the LSTM anyway)
   or stay NumPy-only for a dependency-light gateway?

---

## 12. Findings from the first training runs

Recorded because two of these are reportable results in their own right, and
one is a methodological trap worth warning others about.

### 12.1 The agent exploited a gap in the reward (run 1)

The first trained agent beat the `threshold` baseline by 17.4% and closed 32%
of the gap to the perfect-information reference. Inspecting what it actually
*did* showed the number was close to meaningless:

| Action | Proposed | Granted |
|---|---|---|
| ROTATE_SESSION_KEY | **63.6%** | 132 / 1800 |
| REFRESH_POOL | 15.8% | 44 / 1800 |
| HOLD | **0.2%** | — |

It requested a key rotation 79% of the time and chose to do nothing in 3 steps
out of 1800. The shield's rate limiter refused roughly four in five requests,
so **the effective policy was the rate limiter, not the agent.** It had not
learned *when* to rotate; it had learned that asking is free and delegation
works.

The cause was a reward-design error: a blocked action was converted to HOLD and
charged nothing, so spamming requests strictly dominated. Fixed by charging
`w_blocked = 0.15` per refused proposal — below the 0.34 cost of actually
rotating, so asking wrongly hurts but less than doing it wrongly.

**The generalisable lesson: a safety envelope that silently absorbs bad
decisions will be exploited by any optimiser placed behind it.** If the shield
can turn a wrong action into a free no-op, the policy learns to let it. Anyone
combining learned control with a safety layer should price the refusals.

Early evidence from run 2, at matched episodes (raw counts, comparable across
runs; returns are not, since the reward changed):

| At episode 500 | Run 1 | Run 2 |
|---|---|---|
| Refused requests | 365.2 | **81.3** (-78%) |
| Rotations performed | 45.1 | **17.9** (-60%) |
| Steps with attacker holding the key | 41.2 | **30.3** (-26%) |

Fewer rotations *and* better protection — the signature of rotating at the
right moments rather than constantly.

### 12.2 The first evaluation could not have detected a real difference

Run 1 scored -1068.8 against `threshold` at -1294.5, a gap of 225.7. But the
per-seed spread was 500-950. Comparing two independent means, that gap is well
inside the noise.

Most of the spread is the **seed**, not the policy: an episode containing a
long intrusion is bad for everyone. `paired_compare()` now runs both policies
on identical seeds and reports the mean *difference* with a 95% confidence
interval, which cancels the shared difficulty. Evaluation seeds went from 5 to
15. If the interval spans zero, the tool says so and instructs against claiming
a win.

### 12.3 Training is high-variance, and a single endpoint is not a result

Run 1 sampled every 200 episodes looked like sustained divergence from episode
600 onward. At 50-episode resolution it was oscillation of roughly +/-300
around a slowly improving trend, and the run ended near its best.

The reporting rule that follows: **never characterise a training run from
sparse checkpoints**, and never persist only the final weights. Run 1 saved at
the end and happened to finish near its peak, which was luck. Training now
evaluates greedily on fixed seeds every 50 episodes and keeps the best.

### 12.4 First complete result (SUPERSEDED by 12.13)

> Measured against the wrong benign score distribution; see 12.11. Kept
> as the record of how the project reached 12.13, not as a result to cite.

**Selected model:** `runs/SELECTED_7000_seed6/agent_best.pt` -- 7000 episodes,
chosen over five other candidates on 15 selection seeds held disjoint from the
reporting seeds (12.10). Evaluation: 600-step episodes, 15 seeds x 4 episodes,
detector `fpr=0.05 fnr=0.15 delay=3`.

| policy | return | compromised | rotations | blocked | false-pos |
|---|---|---|---|---|---|
| **dqn** | **-427.8** | **19.1** | 39.8 | 19.5 | 9.0 |
| oracle | -677.5 | 5.3 | 5.0 | 0.3 | 173.7 |
| threshold | -1560.6 | 76.0 | 25.7 | 10.5 | 4.0 |
| always-max | -3481.8 | 91.8 | 60.0 | 538.0 | 507.2 |
| never | -3723.1 | 177.4 | 0.0 | 0.0 | 24.8 |
| fixed-interval | -3946.3 | 191.1 | 2.0 | 0.0 | 24.8 |

```
dqn - threshold = +1132.8   (95% CI +569.7 .. +1695.8),  wins 14/15 seeds
robustness: 24 of 27 detector settings
```

The commitment in the earlier version of this section was to report "no
measurable difference from a threshold rule on this evidence" if the interval
spanned zero. It does not; the lower bound is +569.7.

**What the agent is actually trading.** It takes **4x fewer compromised steps**
than `threshold` (19.1 vs 76.0) and pays for it with more action: 39.8
rotations against 25.7, and 9.0 false-positive steps against 4.0. Under the
action costs the reward encodes -- which come from measured benchmarks, not
guesses -- that trade is strongly worth making. It is still a trade, and the
paper should present it as one.

**A caution about a claim that did not survive.** An earlier 3500-episode model
(banked at `runs/BANKED_3500_seed2/`) reached *rotation parity* with
`threshold` -- 25.9 against 25.7 -- for 3.6x fewer compromised steps, at a
lower overall score of -491.9. That was a cleaner operational story: same cost,
better timing. **It is not a property of the final model and must not be
quoted as one.** If rotation cost is later found to be underpriced in
`costs.py` -- each rotation is an ML-KEM handshake propagated across the fleet,
and at scale that is not free -- the banked 3500-episode model is the variant
to revisit, and the comparison is already recorded here.

### 12.5 Beating the perfect-information reference is expected, not a bug

The agent (-427.8) scores above `oracle` (-677.5). `OraclePolicy` is documented
as a perfect-information *reference and explicitly not an upper bound*: it sees
the hidden compromise state but escalates on any attacker presence, including
while the attacker does not hold the key. The evaluation shows the price --
**173.7 false-positive steps per episode against the agent's 9.0.** The agent
has not acquired better information; it declines a cost the oracle pays.

`verdict()` previously printed "closes 478% of the gap between threshold and
the perfect-information reference" -- a fraction of a gap that had already been
passed, and a headline number meaning nothing. It now detects that case and
names the mechanism instead. It also no longer asserts the shield was
"load-bearing" while printing `forced 0.0`; it reports what each path did and
says plainly when a path is **untested** by the run. Here the blocking path
fired 19.5 times per episode and the forcing path never fired, so forcing rests
on the shield's unit tests, not on this result.

### 12.6 Transferability: 24 of 27 detector settings

The agent beats `threshold` at 24 of the 27 `(fpr, fnr, delay)` grid points.
All three losses share one feature -- `delay = 1`:

| fpr | fnr | delay | dqn | threshold |
|---|---|---|---|---|
| 0.05 | 0.05 | 1 | -257.4 | **-248.1** |
| 0.05 | 0.15 | 1 | -257.4 | **-234.5** |
| 0.15 | 0.05 | 1 | -414.1 | **-375.8** |

When the detector reports instantly, a threshold rule is already close to
optimal and the agent's learned caution is slight overkill. Its advantage grows
as the detector slows: at `delay = 6` it wins every one of the nine settings,
by margins up to 1800. That is the regime the real LSTM is likely to occupy --
a sequence model scoring a window of telemetry does not report instantly -- so
the failures sit in the corner of the grid that matters least.

### 12.7 The selection signal was itself too noisy to select on

`train.py` kept the best checkpoint by greedy eval on **three** fixed seeds.
That signal could not rank anything:

- one of the three (seed 902) scored about -1090 for *every* agent -- zero
  discriminating power;
- another swung by 700 between agents.

So the ranking rested on essentially one episode. Re-ranking the same three
trained seeds over **15** episodes **reversed the winner**: the built-in
3-seed signal chose seed 3, the 15-seed evaluation chose seed 2.

Three consequences, all now in the code:

1. Selection uses 15 seeds (`train.EVAL_SEEDS = 9001..9015`).
2. The selection score is **printed** every eval. Its absence is why the run's
   only real progress signal was invisible for 40 minutes, leaving file
   timestamps as the only proxy.
3. Selection seeds are asserted **disjoint** from the reporting seeds, so
   weights are never chosen using the episodes the confidence interval is
   computed on. The obvious range `901..915` is *not* disjoint -- it contains
   909, which is in `evaluate.EVAL_SEEDS`. The assertion caught it on first
   run.

A methodological note worth keeping: with a signal that weak, **neither**
"training has plateaued" **nor** "training was still improving" could be
established. Both were claimed during this session -- the first from checkpoint
file timestamps, the second from the episode numbers of late best-checkpoints --
and neither was supported by the evidence available at the time. The rerun at
7000 episodes with the corrected metric exists to answer that question properly
rather than to chase a number.

### 12.8 Which model won is within noise

```
7000 seed6 - 7000 seed5 = +37.0   (95% CI -105.5 .. +179.6),  wins 6/15
```

The top two candidates are **not separable**. Seed 6 is *a defensible choice,
not "the best model"*, and the report should say so. The same standard applied
to the threshold comparison applies here; it simply produces the opposite
verdict.

Note the direction of the error this prevents: seed 6 wins only 6 of 15
selection episodes yet has the higher mean, i.e. it wins big and loses small.
Quoting "best of six" without the interval would imply a reliability the
evidence does not support.

### 12.9 The nonce-exhaustion gate was vacuous at the evaluated episode length

M3's acceptance list requires **zero nonce-exhaustion events across all
evaluation episodes**. The evaluation reported `forced 0.0`, which looks like a
pass. It was not evidence of one.

`seq_scale = 700_000` per step against `SEQ_MAX = 1,073,741,824` means the
shield's 0.9 threshold needs **1381 steps of never rotating**, and full
exhaustion 1534. The evaluation ran **600-step** episodes. The path was
*structurally unreachable*, so `forced = 0` carried no information about the
policy -- a "never rotate" agent would have scored 0 there too.

Re-run at both lengths, 15 seeds, selected model:

| episode_steps | threshold reachable | forced | exhaustion events | peak seq use |
|---|---|---|---|---|
| 600 | no (needs 1381) | 0 | 0 | 3.7% of SEQ_MAX |
| **1800** | **yes** | **0** | **0** | **5.8% of SEQ_MAX** |

At 1800 steps the guard rail is reachable and the agent still never trips it.
Peak sequence consumption is 5.8% of `SEQ_MAX` -- about fifteen times below the
0.9 threshold -- because the agent's own rotation cadence resets the counter
long before nonce pressure builds. **The gate passes on evidence.**

Two consequences:

1. The shield's forced-rotation path is never exercised *by this agent*. Its
   correctness rests on the shield's unit tests, and the paper must say so
   rather than cite `forced = 0` as a safety result. This is why `verdict()`
   now reports an untriggered path as **untested** instead of asserting the
   envelope was load-bearing.
2. Any future claim about nonce safety must state the episode length alongside
   it. A safety property that cannot fire in the window you measured has not
   been measured.

### 12.10 What the extra training actually bought, and what it did not

A second run -- 3 fresh seeds x 7000 episodes, 1,049,500 gradient steps each --
was launched to settle a question the first run could not answer: whether
training had plateaued. It had not been answerable because the selection signal
was too weak to distinguish a plateau from continued improvement (12.7), and
both readings had been asserted from weak proxies during the session: a plateau
from checkpoint file timestamps, and continued improvement from the episode
numbers of late best-checkpoints. Neither was supported.

**The plateau is now measured.** With the 15-seed signal, the last improvement
in each long run came at episodes **5200, 5150 and 4700**. Nothing in the final
1800-2300 episodes of any seed. Training converges by roughly episode 5000.

**All six candidates re-scored on one selection set** (15 seeds, disjoint from
the reporting seeds), since the two runs used different internal selection
criteria and their self-reported bests are not comparable:

| | 3500-episode runs | 7000-episode runs |
|---|---|---|
| group mean, **best checkpoint** | -1120.8 | **-673.2** |
| group mean, **final weights** (no selection) | -1078.7 | -968.9 |

Every long run beat every short run, so the winner is not cherry-picked.

**But the obvious attribution is wrong.** Two things changed at once: episode
count *and* the selection fix. The final weights involve no selection on either
side, so differencing that row isolates training length:

- longer training: **+110**
- fixed selection metric: **+338**

**Roughly three quarters of the improvement came from fixing how the checkpoint
was chosen, not from training longer.** Reporting "we trained twice as long and
it got much better" would have been false.

**The 3-seed selection was worse than no selection at all.** For the
3500-episode runs the *final* weights (-1078.7) beat the checkpoints the 3-seed
metric picked as best (-1120.8). It was not merely a weak signal -- it actively
chose worse weights than doing nothing would have. With 15 seeds the same
mechanism adds +296. The lesson generalises past this project: **a selection
rule evaluated on too little data is not a conservative version of a good one,
it is a randomiser**, and it will happily discard your best weights.

### 12.11 The surrogate's benign distribution was wrong, and the calibration contract says so

The single most consequential defect found in this project, discovered only by
running the trained detector and the trained policy in the same loop at M5.

**What was assumed.** `SurrogateParams` drew benign scores from `Beta(1.5, 6)`,
mean **0.20** — a detector that reports near zero when nothing is wrong. A
reasonable detector. Not the one this project builds.

**What was measured.** Scoring the trained LSTM's held-out MSU/ORNL windows:

| | measured | surrogate assumed |
|---|---|---|
| benign (no-event) | mean **0.503**, `Beta(0.96, 0.95)` — uniform | mean 0.200, `Beta(1.5, 6)` |
| alarming (attack) | mean **0.992**, pinned at 1.0 | mean 0.769, `Beta(5, 1.5)` |

**The benign result is not an accident and not a flaw in the detector — it is
forced by the calibration contract.** `score = ECDF of reconstruction error
over held-out normal` makes normal data uniform on [0, 1] *by construction*.
"0.99 means worse than 99% of normal windows" is precisely the statement that
1% of normal windows exceed 0.99. Any correctly calibrated detector of this
kind has mean score 0.5 on normal traffic. The surrogate and the calibration
module were written to the same spec, by the same hand, and contradicted each
other; neither was wrong in isolation.

**What it cost.** A policy trained to read 0.2 as "calm" meets a real detector
sitting at 0.5 on an untroubled grid and reads permanent mild alarm. Measured
in the M5 loop, on calm data, proposed actions:

| | training env | real loop |
|---|---|---|
| HOLD | **60.1%** | **5%** |
| ROTATE_SESSION_KEY | 7.0% | 42% |
| QUARANTINE_WORST_CHANNEL | 0.3% | 8% |

The policy was not broken. It was answering a question it had never been asked.

**The harder property this exposes.** Under a uniform benign distribution,
roughly **10% of perfectly normal windows score above 0.9**. A single high
score is not evidence of anything. The old surrogate hid that completely: with
`Beta(1.5, 6)`, a benign window above 0.9 is a once-in-a-thousand event, so a
policy could treat one alarm as near-proof and never be punished. The real
problem is strictly harder than the one the agent was trained on, and the
robustness sweep did not cover it because the sweep varied `fpr` while holding
the *shape* of both distributions fixed.

**What changed.** `SurrogateParams` defaults are now the measured values:
benign `Beta(1, 1)` (uniform, exactly what ECDF implies), alarming
`Beta(2, 0.05)` (the measured shape with a numerically usable tail — the raw
moment fit `Beta(1.78, 0.01)` is degenerate). `lease.py`'s thresholds were
re-derived for a uniform score, where a threshold *is* its false-alarm rate.
The agent is being retrained.

**Every DQN result before this measurement used the old distributions**
(12.4–12.10) and must be reported as such, or re-run.

**The transferable lesson.** Domain randomisation covered `(fpr, fnr, delay)`
and transferred well across all of it — including, as 12.12 shows, to a regime
outside the training grid entirely. It could not cover an error in the
*parameterisation itself*. Sweeping a parameter protects you against not
knowing its value; it does nothing about the distribution being the wrong
shape. The only thing that caught this was connecting the two trained
components and measuring what actually came out.

### 12.12 The policy survives a detector that cries wolf at every fault

M4 measured the LSTM false-alarming on 98–100% of natural disturbances. The
surrogate had no way to express that — a single `fpr` cannot be 0.05 on a calm
grid and 1.0 during a storm — so `SurrogateParams` gained a benign-disturbance
process (`disturbance_rate`, `disturbance_len`, `fpr_disturbed`), default off
so prior results reproduce exactly.

A disturbance is **benign**: it never sets `compromised`, so an agent that
escalates through one is simply wrong. Evaluated across rates of 0.01 / 0.03 /
0.06 per step with `fpr_disturbed = 1.0`, paired against `threshold` on 8
shared seeds:

```
significantly ahead  5/9 settings
not separable        4/9   (all point estimates positive, +326 to +1127)
behind               0/9
```

**It never loses**, in a regime it was never trained for and that lies outside
the robustness grid. That is the strongest evidence so far that the domain
randomisation produced a transferable policy rather than a tuned one — and it
is the reason the M4 false-alarm result, while a genuine failure of the
detector, does not by itself sink the system.

### 12.13 Results at 1900/5000 episodes (SUPERSEDED by 12.14)

> The retraining run was stopped by a platform time limit. Kept because
> 12.15 compares against it; the shipped numbers are in 12.14.

**Everything in 12.4 through 12.10 was measured against the wrong benign score
distribution** (12.11) and is retained as the record of how the project got
here, not as the result. These are the numbers to quote.

Agent: `runs/cal_seed12/agent_best.pt`, best of 3 seeds on 15 selection seeds
disjoint from the reporting seeds. Evaluation: 600-step episodes, 15 seeds x 4
episodes, detector `fpr=0.05 fnr=0.15 delay=3`.

| policy | return | compromised | rotations | blocked | false-pos |
|---|---|---|---|---|---|
| **dqn** | **-634.7** | **26.7** | **14.0** | 23.8 | 13.5 |
| oracle | -677.5 | 5.3 | 5.0 | 0.3 | 173.7 |
| threshold | -1610.9 | 75.6 | 53.9 | 150.6 | 12.8 |
| always-max | -3481.8 | 91.8 | 60.0 | 538.0 | 507.2 |
| never | -3723.0 | 177.4 | 0.0 | 0.0 | 24.8 |
| fixed-interval | -3946.3 | 191.1 | 2.0 | 0.0 | 24.8 |

```
dqn - threshold = +976.1   (95% CI +399.2 .. +1553.0),  wins 14/15 seeds
robustness grid:        27 / 27 detector settings
disturbance regime:      9 / 9 settings, significantly ahead, none tied, none behind
integration (M5):       24 / 24 checks
```

**The claim to make.** Not the 60.6% return improvement — the rotations column:
**14.0 against `threshold`'s 53.9**. The agent protects the system with **a
quarter of the key rotations** and takes **65% fewer compromised steps** (26.7
vs 75.6). It is cheaper *and* safer, on the cost the grid operator actually
pays: every rotation is an ML-KEM handshake propagated across the fleet.

This is stronger than anything the pre-recalibration runs produced. The best of
those (12.4) reached rotation *parity* with `threshold` at 39.8 vs 25.7 — it
bought protection with extra work. Training against the detector's true score
distribution produced a policy that buys it with better timing instead.

**Transferability is now complete.** 27/27 on the detector grid, up from 24/27;
the three former losses were all at `delay=1`, where a threshold rule is nearly
optimal, and those are now wins too. 9/9 in the disturbance regime, up from 5
significant and 4 ties.

**What is weaker than it should be.** `cal_seed12` reached **1900 of 5000
episodes**; the retraining run was stopped by a platform background-time limit,
not by convergence. 12.10 measured the remaining gain from more episodes at
roughly +110 against +338 from fixing checkpoint selection, so the shortfall is
bounded and known rather than unknown — but these numbers are a floor, not a
ceiling, and the run should be repeated to 5000 in an uninterrupted window.

**The methodological point worth keeping.** Every number improved when the
surrogate was corrected, including ones that already looked good. The old
results were not noise and were not fabricated; they were a careful measurement
of the wrong thing. Nothing in the training pipeline could have detected that,
because the pipeline was self-consistent. Only connecting the trained detector
to the trained policy and measuring what actually came out could.

### 12.14 Final result — fully trained, and the model that ships

Supersedes 12.13, which reported a run stopped at 1900/5000 episodes by a
platform time limit. Training now completes in resumable chunks
(`train.py --resume`), and all three seeds reached **5000 episodes / 748,000
gradient steps**.

**Deployed: `runs/final_seed22/agent_best.pt`.**

| policy | return | compromised | rotations | blocked | false-pos |
|---|---|---|---|---|---|
| **dqn** | **-435.8** | **19.3** | **12.9** | 3.5 | 7.0 |
| oracle | -677.5 | 5.3 | 5.0 | 0.3 | 173.7 |
| threshold | -1610.9 | 75.6 | 53.9 | 150.6 | 12.8 |
| always-max | -3481.8 | 91.8 | 60.0 | 538.0 | 507.2 |
| never | -3723.0 | 177.4 | 0.0 | 0.0 | 24.8 |
| fixed-interval | -3946.3 | 191.1 | 2.0 | 0.0 | 24.8 |

```
dqn - threshold = +1175.1   (95% CI +600.8 .. +1749.3),  wins 15/15 seeds
robustness grid:        27 / 27 detector settings
disturbance regime:      9 / 9 settings, none tied, none behind
integration (M5):       24 / 24 checks
```

**The claim.** Against the threshold rule the agent takes **74% fewer
compromised steps** (19.3 vs 75.6) using **76% fewer key rotations** (12.9 vs
53.9). Cheaper and safer at the same time, on the cost that is actually paid:
every rotation is an ML-KEM handshake propagated across the fleet. It wins on
every evaluation seed and every detector setting tested.

### 12.15 Why seed 22 ships rather than the highest-scoring seed

Seed 21 scored better on the trained objective and is **not** the deployed
model. The reasoning should be visible rather than buried.

| | seed 21 | **seed 22 (shipped)** |
|---|---|---|
| return | **-356.6** | -435.8 |
| compromised | **14.5** | 19.3 |
| rotations | 34.0 | **12.9** |
| false positives | 14.8 | **7.0** |
| blocked actions | 22.9 | **3.5** |
| paired vs threshold | +1254.2 | +1175.1 |
| seeds won / robustness | 15/15, 27/27 | 15/15, 27/27 |
| posture on calm data | **parks at SUSPICIOUS, never returns** | holds NORMAL |

Two reasons, and the second is the decisive one.

1. **Seed 21 buys its 79 extra points by rotating 2.6x more often.** The reward
   prices rotations, so this is a legitimate optimum under the model — but the
   model arguably underprices them relative to a real fleet-wide PQC handshake.
   Where two policies are statistically indistinguishable on the evidence that
   establishes the result (both 15/15 and 27/27), the cheaper one is the better
   engineering choice.

2. **Seed 21 parks the system at SUSPICIOUS indefinitely.** Measured over 300
   calm cycles: SUSPICIOUS on all 300, never returning to NORMAL, never
   escalating further, never quarantining. It is not unsafe — but it never uses
   the bottom rung of the posture ladder in steady state, which wastes the
   ladder's dynamic range and would misrepresent the system in a demo. Seed 23
   behaves the same way; seed 22 holds NORMAL.

**On the method.** The seed was selected on the held-out set as always, which
is what makes the confidence interval honest. Preferring seed 22 adds a
*second* criterion — steady-state posture behaviour — measured on the
integration harness, not on the seeds the interval is computed from. That keeps
selection and reporting disjoint. Reporting seed 21's superior score here, in
the same table, is the point: the choice is an engineering judgement about
operational cost, not a claim that seed 22 scored better.

**A reward-design observation worth carrying forward.** That two of three seeds
converge on "sit at SUSPICIOUS permanently" suggests the reward does not
sufficiently price a *steady-state* posture elevation — only the transitions.
In a real control room a permanently raised posture is alarm fatigue. If the
reward is ever revisited, add a standing cost for time spent above NORMAL.
