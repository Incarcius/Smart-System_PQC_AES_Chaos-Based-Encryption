"""evaluate.py — the five things M4 has to show, and one it must not hide.

Acceptance (IMPLEMENTATION_PLAN M4):
  1. precision-recall, not just ROC
  2. per-scenario breakdown across the attack types
  3. detection delay distribution
  4. inference latency well inside the 1 s window
  5. the natural disturbances handled as the false-positive source they are

Why PR and not ROC
------------------
Attacks are rare. With a few percent positives, a detector that fires almost
never still gets a flattering ROC curve, because the false-positive *rate* has a
huge denominator. Precision answers the question an operator actually asks --
"when this thing alarms, how often is it right?" -- and it is the number that
collapses under class imbalance. Reporting AUC alone would be the single
easiest way to overstate this model.

Why the naturals get their own row
----------------------------------
The 8 natural disturbances are faults, not attacks: storms, line maintenance,
equipment trips. They are large, obvious departures from normal, so any
detector that merely separates "quiet" from "loud" will flag them. Lumping them
into one overall false-positive figure hides exactly the failure that matters,
so they are reported separately throughout. The DQN's false-positive cost only
means anything if this number is real.

Usage:
    python server/LSTM/evaluate.py --run server/LSTM/runs --synthetic
    python server/LSTM/evaluate.py --run server/LSTM/runs --data <dir>
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from data import (  # noqa: E402
    LABEL_ATTACK,
    LABEL_NATURAL,
    LABEL_NORMAL,
    WindowSpec,
    load_multiclass,
    split_normal,
    synthetic,
)
from lstm_detector import LSTMDetector  # noqa: E402


# ---------------------------------------------------------------------------
# Precision / recall
# ---------------------------------------------------------------------------

def pr_curve(scores: np.ndarray, is_attack: np.ndarray, n_points: int = 200):
    """Precision, recall and the thresholds that produced them."""
    order = np.argsort(-scores)
    s, y = scores[order], is_attack[order].astype(np.int64)

    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    total_pos = max(int(y.sum()), 1)

    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / total_pos

    if len(s) > n_points:
        ix = np.unique(np.linspace(0, len(s) - 1, n_points).astype(int))
        return precision[ix], recall[ix], s[ix]
    return precision, recall, s


def average_precision(precision: np.ndarray, recall: np.ndarray) -> float:
    """Area under the PR curve, by the step rule.

    Trapezoidal integration would interpolate between operating points that no
    threshold actually produces, which inflates the number.
    """
    r = np.concatenate([[0.0], recall])
    p = np.concatenate([[precision[0] if len(precision) else 0.0], precision])
    return float(np.sum(np.diff(r) * p[1:]))


def best_f1(precision: np.ndarray, recall: np.ndarray, thr: np.ndarray):
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-12)
    i = int(np.argmax(f1))
    return float(f1[i]), float(thr[i]), float(precision[i]), float(recall[i])


# ---------------------------------------------------------------------------
# Detection delay
# ---------------------------------------------------------------------------

def detection_delay(det: LSTMDetector, X: np.ndarray, onset: np.ndarray,
                    step_threshold: float, spec: WindowSpec):
    """Rows from event onset to the first step whose error crosses threshold.

    This is the quantity the DQN's surrogate calls `delay`, and M3 trained
    against a grid of 1 / 3 / 6 steps. If the measured delay falls outside that
    grid, the DQN was trained for a detector that does not exist and the
    robustness sweep is the only thing standing between that and a wrong claim
    -- so this number is reported in both rows and seconds, and compared with
    the grid explicitly.

    Windows never detected at all are counted separately rather than being
    given an arbitrary large delay, which would quietly turn a miss into a
    slow detection.
    """
    per_step = det.errors_per_step(X)
    delays, missed = [], 0

    for i in range(len(X)):
        o = int(onset[i])
        if o < 0:
            continue
        after = per_step[i, o:]
        hit = np.flatnonzero(after > step_threshold)
        if hit.size:
            delays.append(int(hit[0]))
        else:
            missed += 1

    d = np.asarray(delays, dtype=np.float64)
    if d.size == 0:
        return {"n": 0, "missed": missed, "median_rows": None,
                "median_seconds": None, "p90_rows": None}
    return {
        "n": int(d.size),
        "missed": missed,
        "mean_rows": float(d.mean()),
        "median_rows": float(np.median(d)),
        "p90_rows": float(np.quantile(d, 0.9)),
        "median_seconds": float(spec.rows_to_seconds(float(np.median(d)))),
        "p90_seconds": float(spec.rows_to_seconds(float(np.quantile(d, 0.9)))),
    }


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------

def attribution_accuracy(det: LSTMDetector, X: np.ndarray,
                         truth: list[list[int]] | None, top_k: int = 3):
    """Does the worst-reconstructed feature actually name a corrupted channel?

    Only measurable where ground truth exists at channel level. The MSU/ORNL
    multiclass labels name the scenario, not which PMU column was manipulated,
    so this is reported on synthetic and on rig-injected attacks and is
    explicitly `None` otherwise. Reporting a number here from scenario labels
    would be inventing one.
    """
    if not truth:
        return None

    err = det.errors_per_feature(X)
    top1 = 0
    topk = 0
    for i, feats in enumerate(truth):
        if not feats:
            continue
        order = np.argsort(-err[i])
        if int(order[0]) in feats:
            top1 += 1
        if set(order[:top_k].tolist()) & set(feats):
            topk += 1
    n = sum(1 for f in truth if f)
    if n == 0:
        return None
    return {"n": n, "top1": top1 / n, f"top{top_k}": topk / n}


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------

def measure_latency(det: LSTMDetector, X: np.ndarray, reps: int = 50):
    """Single-window inference time — the deployment constraint.

    The server has a 1 s aggregation window to fit inference plus crypto into.
    Batched throughput is irrelevant here; production scores one window at a
    time, so that is what gets timed.
    """
    one = X[:1]
    det.score_array(one)  # warm up lazy init / caches
    t0 = time.perf_counter()
    for _ in range(reps):
        det.score_array(one)
    ms = (time.perf_counter() - t0) / reps * 1000.0
    return {"per_window_ms": ms, "budget_ms": 1000.0,
            "fraction_of_budget": ms / 1000.0}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def evaluate(det: LSTMDetector, ds, fpr_targets=(0.02, 0.05, 0.15)) -> dict:
    # Rank by RAW error, not the calibrated score. The calibrated score is a
    # rank among a finite calibration set and saturates at 1.0, so ties at the
    # ceiling collapse the ordering the PR curve depends on and can place an
    # operating-point threshold at exactly 1.0, where nothing ever exceeds it.
    # The calibrated score is reported alongside, because that is the number
    # the DQN consumes.
    errors = det.errors(ds.X)
    scores = det.score_array(ds.X)
    is_attack = ds.y == LABEL_ATTACK
    is_natural = ds.y == LABEL_NATURAL
    is_normal = ds.y == LABEL_NORMAL

    out: dict = {"counts": ds.counts()}

    # 1. PR, attacks against no-event normal only. Naturals are excluded here
    #    and reported on their own, because folding them in would let a
    #    detector that flags every fault look precise.
    keep = is_attack | is_normal
    precision, recall, thr = pr_curve(errors[keep], is_attack[keep])
    f1, f1_thr, f1_p, f1_r = best_f1(precision, recall, thr)
    out["pr"] = {
        "average_precision": average_precision(precision, recall),
        "best_f1": f1, "at_threshold": f1_thr,
        "precision_at_best_f1": f1_p, "recall_at_best_f1": f1_r,
        "positive_rate": float(is_attack[keep].mean()),
    }

    # 1b. The OPERATIONAL curve: everything that is not an attack counts as a
    #     negative, naturals included.
    #
    #     This is the number to report. The curve above excludes natural
    #     disturbances from the negatives, which quietly asks "can you tell an
    #     attack from a calm grid?" -- a question no operator has. The question
    #     they do have is "when this alarms, is something malicious happening?",
    #     and a storm that raises an attack alarm is a false alarm regardless of
    #     how interesting the physics were. Excluding faults from the negatives
    #     is the single easiest way to overstate an ICS detector, and on this
    #     dataset the two numbers are very far apart.
    prec_o, rec_o, thr_o = pr_curve(errors, is_attack)
    f1o, f1o_t, f1o_p, f1o_r = best_f1(prec_o, rec_o, thr_o)
    out["pr_operational"] = {
        "average_precision": average_precision(prec_o, rec_o),
        "best_f1": f1o, "at_threshold": f1o_t,
        "precision_at_best_f1": f1o_p, "recall_at_best_f1": f1o_r,
        "positive_rate": float(is_attack.mean()),
        "negatives_include_natural": True,
    }

    # 2. Operating points on the DQN's own fpr grid.
    ops = []
    for target in fpr_targets:
        t = (float(np.quantile(errors[is_normal], 1.0 - target))
             if is_normal.any() else float("inf"))
        fired_atk = float((errors[is_attack] > t).mean()) if is_attack.any() else 0.0
        fired_nat = float((errors[is_natural] > t).mean()) if is_natural.any() else 0.0
        fired_nor = float((errors[is_normal] > t).mean()) if is_normal.any() else 0.0
        tp = fired_atk * int(is_attack.sum())
        fp = (fired_nor * int(is_normal.sum())
              + fired_nat * int(is_natural.sum()))
        ops.append({
            "precision_operational": float(tp / max(tp + fp, 1e-9)),
            "target_fpr": target,
            "threshold_raw_error": t,
            "threshold_as_score": float(np.atleast_1d(det.calib.score(t))[0]),
            "recall_on_attacks": fired_atk,
            "fnr": 1.0 - fired_atk,
            "false_positive_rate_normal": fired_nor,
            "false_positive_rate_natural": fired_nat,
        })
    out["operating_points"] = ops

    # 3. Per-scenario recall at the middle operating point.
    mid = ops[len(ops) // 2]
    mid_t = mid["threshold_raw_error"]
    per_scn = {}
    for s in sorted(set(ds.scenario[is_attack].tolist())):
        m = is_attack & (ds.scenario == s)
        per_scn[int(s)] = {"n": int(m.sum()),
                           "recall": float((errors[m] > mid_t).mean())}
    out["per_scenario"] = per_scn
    out["per_scenario_threshold"] = mid_t
    out["per_scenario_target_fpr"] = mid["target_fpr"]

    nat_scn = {}
    for s in sorted(set(ds.scenario[is_natural].tolist())):
        m = is_natural & (ds.scenario == s)
        nat_scn[int(s)] = {"n": int(m.sum()),
                           "false_alarm_rate": float((errors[m] > mid_t).mean())}
    out["per_natural_scenario"] = nat_scn

    # 4. Detection delay, at the same operating point, in raw-error units.
    step_err = det.errors_per_step(ds.X[is_normal]) if is_normal.any() else None
    step_thr = float(np.quantile(step_err, 1.0 - mid["target_fpr"])) if step_err is not None and step_err.size else 0.0
    out["delay"] = detection_delay(det, ds.X[is_attack], ds.onset[is_attack],
                                   step_thr, ds.spec)
    out["delay"]["step_threshold"] = step_thr
    if out["delay"].get("median_rows") is not None:
        out["delay"]["dqn_grid_rows"] = [1, 3, 6]
        out["delay"]["inside_dqn_grid"] = bool(
            out["delay"]["median_rows"] <= 6.0)

    # 5. Latency and attribution.
    out["latency"] = measure_latency(det, ds.X)
    # attack_features travels inside the Dataset and is aligned with X, so the
    # attack subset indexes the same way every other array does.
    truth = ds.attack_features
    if truth is not None:
        truth = [truth[i] for i in np.flatnonzero(is_attack)]
    out["attribution"] = attribution_accuracy(det, ds.X[is_attack], truth)

    return out


def print_report(r: dict, synthetic_run: bool) -> None:
    if synthetic_run:
        print("!! SYNTHETIC DATA — pipeline check only. None of this goes in "
              "the paper. !!\n")

    print(f"windows: {r['counts']}\n")

    pr = r["pr"]
    pro = r["pr_operational"]
    print("1. precision-recall")
    print(f"   OPERATIONAL (naturals count as negatives -- report this one)")
    print(f"     average precision {pro['average_precision']:.4f}   "
          f"best F1 {pro['best_f1']:.4f}  "
          f"(P {pro['precision_at_best_f1']:.3f}, R {pro['recall_at_best_f1']:.3f})")
    print(f"   attacks vs no-event only (flattering, do NOT headline)")
    print(f"     average precision {pr['average_precision']:.4f}   "
          f"best F1 {pr['best_f1']:.4f}  "
          f"(P {pr['precision_at_best_f1']:.3f}, R {pr['recall_at_best_f1']:.3f})")

    print("\n2. operating points on the DQN's fpr grid")
    print(f"   {'target':>7s} {'recall':>8s} {'fnr':>7s} {'fp normal':>10s} "
          f"{'fp NATURAL':>11s} {'precision':>10s}")
    for op in r["operating_points"]:
        print(f"   {op['target_fpr']:7.2f} {op['recall_on_attacks']:8.3f} "
              f"{op['fnr']:7.3f} {op['false_positive_rate_normal']:10.3f} "
              f"{op['false_positive_rate_natural']:11.3f} "
              f"{op['precision_operational']:10.3f}")
    print("   (precision counts naturals as false alarms: faults are not attacks)")

    scn = r["per_scenario"]
    print(f"\n3. per-scenario recall, {len(scn)} attack scenarios "
          f"@ threshold {r['per_scenario_threshold']:.4f}")
    if scn:
        vals = [v["recall"] for v in scn.values()]
        worst = sorted(scn.items(), key=lambda kv: kv[1]["recall"])[:5]
        print(f"   median {np.median(vals):.3f}   min {min(vals):.3f}   "
              f"max {max(vals):.3f}")
        print("   weakest: " + ", ".join(f"#{k} {v['recall']:.2f}" for k, v in worst))
    nat = r["per_natural_scenario"]
    if nat:
        nv = [v["false_alarm_rate"] for v in nat.values()]
        print(f"   natural disturbances false-alarm: median {np.median(nv):.3f} "
              f"max {max(nv):.3f} over {len(nat)} scenarios")

    d = r["delay"]
    print("\n4. detection delay")
    if d.get("median_rows") is None:
        print("   never detected at this threshold")
    else:
        print(f"   median {d['median_rows']:.1f} rows "
              f"({d['median_seconds']:.2f} s), p90 {d['p90_rows']:.1f} rows")
        print(f"   detected {d['n']}, never detected {d['missed']}")
        print(f"   DQN trained against delays of {d['dqn_grid_rows']} steps -> "
              f"{'inside' if d['inside_dqn_grid'] else 'OUTSIDE'} that grid")

    lat = r["latency"]
    print("\n5. inference latency")
    print(f"   {lat['per_window_ms']:.2f} ms per window "
          f"= {lat['fraction_of_budget']*100:.2f}% of the 1 s budget")

    att = r["attribution"]
    print("\n6. attribution")
    if att is None:
        print("   not measurable: no channel-level ground truth in this data")
    else:
        print(f"   top-1 {att['top1']:.3f}   top-3 {att.get('top3', float('nan')):.3f} "
              f"over {att['n']} attack windows")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, default=_HERE / "runs")
    ap.add_argument("--data", type=Path, default=None)
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--train-on", choices=["no-event", "benign"],
                    default="no-event",
                    help="MUST match the value train.py was run with, or "
                         "the split differs and the model is scored on "
                         "windows it trained on.")
    ap.add_argument("--loose", action="store_true")
    args = ap.parse_args()

    if args.data:
        ds = load_multiclass(args.data,
                             WindowSpec(length=args.window, stride=10,
                                        sample_hz=120.0),
                             strict=not args.loose)
    elif args.synthetic:
        ds = synthetic(spec=WindowSpec(length=args.window, stride=args.window,
                                       sample_hz=1.0), seed=args.seed)
    else:
        ap.error("pass --data <dir> or --synthetic")

    # Evaluate on everything the model never trained on. `subset` carries the
    # attribution ground truth across the split.
    benign = ((LABEL_NORMAL, LABEL_NATURAL) if args.train_on == "benign"
              else (LABEL_NORMAL,))
    _, _, ev = split_normal(ds, seed=args.seed, benign=benign)

    det = LSTMDetector.from_dir(args.run)
    report = evaluate(det, ev)
    print_report(report, synthetic_run=bool(args.synthetic))

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, default=float))
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
