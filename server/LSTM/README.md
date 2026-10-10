# Phase B — LSTM anomaly detection

Trains an LSTM autoencoder on **normal traffic only**, calibrates its
reconstruction error into a `[0, 1]` score, and serves it behind the
`Detector` protocol in `server/python/detector.py`.

Full design: [`docs/REMAINING_WORK.md`](../../docs/REMAINING_WORK.md) §3.
Milestone and acceptance: [`docs/IMPLEMENTATION_PLAN.md`](../../docs/IMPLEMENTATION_PLAN.md) M4.

## Files

| File | Role |
|---|---|
| `data.py` | MSU/ORNL loader, windowing, normalisation, synthetic stand-in |
| `model.py` | LSTM autoencoder; per-window / per-feature / per-step error |
| `calibrate.py` | ECDF over held-out normal → calibrated score |
| `train.py` | trains on normal only, keeps the best epoch by held-out normal loss |
| `detector.py` | `LSTMDetector`, drop-in for `StubDetector` |
| `evaluate.py` | PR curve, per-scenario, detection delay, latency, attribution |
| `tests/test_lstm.py` | 61 checks; runs entirely on synthetic data |

## The dataset

**MSU/ORNL Power System Attack Datasets** (Morris et al., Mississippi State
University / Oak Ridge National Laboratory), **multiclass** variant.

- 15 CSV files, ~15 MB zipped / 60–70 MB extracted
- 128 features per row (4 PMUs + relay, control-panel and Snort logs) plus a
  `marker` column holding the scenario id
- **37 scenarios: 1 no-event, 8 natural disturbances, 28 attacks**

Put the CSVs anywhere and point `--data` at that directory.

### Why this dataset specifically

The **8 natural disturbances** are the reason. Storms, line maintenance and
equipment trips are violent in the data and are *not* attacks. Separating
"quiet" from "loud" is easy and worthless; separating a *fault* from an
*attack* is the actual problem, and very few public datasets label both. It is
also the only route to the per-attack-type breakdown and detection-delay
figures the paper needs — a healthy rig produces no labelled attacks, ever,
which is the same reason the model is an autoencoder rather than a classifier.

The scenario grouping in `data.py` (`NATURAL_SCENARIOS`) **must be checked
against the dataset README on first download**. `load_multiclass` asserts 37
scenarios / 8 natural / 1 no-event and raises on mismatch rather than warning:
a natural event silently relabelled as an attack would flatter the detector
exactly where it should be hardest.

### If it is unavailable

**HAI** (HIL-based Augmented ICS, freely on GitHub) is the closest fallback —
a power/steam-turbine testbed with both faults and attacks labelled.
SWaT/WADI are better known but need a signed request form.

## Running

```bash
# no download needed — pipeline check only, nothing publishable
python server/LSTM/train.py --synthetic --epochs 40 --out server/LSTM/runs_synth
python server/LSTM/evaluate.py --run server/LSTM/runs_synth --synthetic

# the real thing
python server/LSTM/train.py --data <csv dir> --out server/LSTM/runs
python server/LSTM/evaluate.py --run server/LSTM/runs --data <csv dir>

python server/LSTM/tests/test_lstm.py
```

## Two models, not one

The MSU/ORNL data has 128 PMU and relay features with no relationship to our
five sensors, so **weights do not transfer to the rig**. What transfers is the
method and this code path. The public dataset earns the evaluation; the rig
model is trained later with the same functions on rig-normal telemetry.

Stating this plainly because the obvious misreading — "we trained on a public
power-grid dataset and deployed it" — would be false.

## Results on the real data

Trained on MSU/ORNL multiclass (15 ARFF files, 10,917 windows of 60 rows at
120 Hz, 128 features). Model selected by held-out benign loss; calibrated on
held-out benign windows; evaluated on windows never trained on.

### The headline is not the average precision

| | average precision | precision | recall |
|---|---|---|---|
| **Operational** — faults count as false alarms | **0.964** | **0.937** | 0.964 |
| Attacks vs calm grid only | 0.999 | 0.980 | 0.983 |

The second row is the one most papers report and it is close to meaningless
here. It asks "can you tell an attack from a calm grid?", which no operator
ever needs to know. Excluding faults from the negatives is the easiest way to
overstate an ICS detector, and on this data it moves average precision from
0.964 to 0.999.

Worse, **the operational number is itself a function of the test set**: it
depends on how many natural disturbances happen to be in it. See below.

### What works

| | |
|---|---|
| Recall on attacks | 0.96–0.98 across the DQN's fpr grid |
| Detection delay | median 3–4 rows = **0.03 s** |
| Inference latency | **2.5 ms**, 0.25% of the 1 s budget |
| Per-scenario recall | median 1.000 over 28 attack scenarios |

Detection speed and latency pass M4's acceptance comfortably.

### What does not: natural disturbances

**The detector flags 98–100% of natural disturbances as attacks, at every
operating point.** Storms, line faults and maintenance all raise an attack
alarm.

This is not a tuning problem. A reconstruction autoencoder measures *unusual*,
and a fault is extremely unusual. The mechanism that detects attacks is the
same one that fires on faults.

#### A fix that was tried and did not work

"Normal" should arguably mean *not under attack* rather than *nothing
happening* — a real substation throws faults constantly, and a rig collecting
its own training data records them without labelling them. So the autoencoder
was retrained with natural disturbances included as benign.

At first this looked like a large win: operational average precision 0.851 →
0.967, precision 0.767 → 0.937. **It was an artifact.** Moving 80% of the
natural windows into training shrank them from 1654 to 337 in the evaluation
set, so the false-alarm denominator changed. Re-scoring **both** models on the
identical split:

| | calm-grid trained | benign trained |
|---|---|---|
| operational AP | 0.9640 | 0.9666 |
| precision @ fpr 0.05 | 0.937 | 0.937 |
| recall @ fpr 0.05 | 0.964 | 0.954 |
| false alarms on faults | 1.000 | 0.988 |

Identical precision, slightly worse recall, faults still essentially always
flagged. The hypothesis was wrong and the first comparison was invalid.

**The general lesson: any aggregate precision here is a statement about how
many faults were in the test set, not about the detector.** Report the
false-alarm rate on natural disturbances directly, because that number is
stable and the aggregate is not.

#### Why this is still usable, stated carefully

The architecture already tolerates it. The detector output is a *calibrated
score*, not a verdict, and the DQN decides what to do with it — it is trained
with an explicit false-positive cost and the posture ladder is "isolate and
continue as untrusted", not instant quarantine. A detector with a **known**
false-alarm rate on faults is workable. One with an unmeasured rate is not.

So the honest framing for the paper: this is a **disturbance detector**, and
the system's discrimination comes from the DQN's handling of uncertain
evidence, not from the detector alone. Claiming an attack detector at 0.999
average precision would not survive review.

#### What the DQN surrogate does not yet model

M3's surrogate has a single `fpr`. The real detector has **two very different
rates** — about 0.05 on a calm grid and about 1.0 during a fault — so its
effective false-positive rate depends on how often the grid is disturbed. The
27-point robustness sweep covers fpr up to 0.15, which does not reach this.
This is a genuine M4 → M3 finding and the sweep should be extended before any
end-to-end claim at M5.

### Hardest attacks

Per-scenario recall is 1.000 for most scenarios; the two weak ones are
**#40 (0.46)** and **#39 (0.77)** — both "line maintenance with relays
disabled". The attacks hardest to catch are the ones disguised as routine
maintenance, which is a coherent result rather than a scattered failure.

### Attribution

Not measurable on this dataset: the multiclass labels name the scenario, not
which PMU column was manipulated. `attribute()` is implemented and tested on
synthetic data (top-1 0.87, top-3 0.98) and needs rig-injected attacks for a
real number. Reporting a figure from scenario labels would be inventing one.
