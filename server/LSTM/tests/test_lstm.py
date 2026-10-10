"""
test_lstm.py — the detector's mechanics, before trusting any detection number.

Checks the things that fail silently rather than loudly: a calibrator that is
not monotone, normalisation statistics refitted at inference, attribution
ground truth that drifts out of alignment with its windows, and the deployed
scoring path disagreeing with the evaluated one. Every one of those produces
plausible numbers and a wrong model.

Usage (from repo root):
    python server/LSTM/tests/test_lstm.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import numpy as np
import torch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from calibrate import ECDFCalibrator, fit_calibrator  # noqa: E402
from data import (  # noqa: E402
    LABEL_ATTACK,
    LABEL_NATURAL,
    LABEL_NORMAL,
    Normaliser,
    WindowSpec,
    make_windows,
    scenario_to_label,
    split_normal,
    synthetic,
)
from lstm_detector import LSTMDetector  # noqa: E402
from model import LSTMAutoencoder, ModelConfig  # noqa: E402

failures = 0
checks = 0


def check(ok, label, detail=""):
    global failures, checks
    checks += 1
    if ok:
        print(f"  ok       {label}")
    else:
        failures += 1
        print(f"  FAIL     {label}")
        if detail:
            print(f"           {detail}")


class _S:
    def __init__(self, cid, val, quality=0):
        self.channel_id, self.value, self.quality = cid, val, quality


class _B:
    def __init__(self, samples):
        self.trusted = samples
        self.untrusted = []


def test_scenario_grouping():
    print("\n-- scenario grouping --")
    check(scenario_to_label(41) == LABEL_NORMAL, "41 is no-event")
    check(scenario_to_label(1) == LABEL_NATURAL, "1 is a natural disturbance")
    check(scenario_to_label(13) == LABEL_NATURAL, "13 is a natural disturbance")
    check(scenario_to_label(20) == LABEL_ATTACK, "20 is an attack")


def test_windowing():
    print("\n-- windowing --")
    rows = np.arange(100, dtype=np.float32).reshape(100, 1)
    labels = np.full(100, LABEL_NORMAL, np.int64)
    labels[50:] = LABEL_ATTACK
    scen = np.where(labels == LABEL_ATTACK, 20, 41).astype(np.int64)

    X, y, sc, on = make_windows(rows, labels, scen, WindowSpec(length=10, stride=10))
    check(X.shape == (10, 10, 1), f"shape {X.shape}")

    # The window spanning rows 50-59 contains the attack onset at its row 0.
    i = 5
    check(y[i] == LABEL_ATTACK, "onset window labelled attack, not normal")
    check(on[i] == 0, f"onset index recorded ({on[i]})")
    check(y[4] == LABEL_NORMAL, "the window before onset stays normal")
    check(sc[i] == 20, "scenario taken from the event row")

    # Severity, not recency: an attack anywhere in the window dominates.
    lab2 = np.full(20, LABEL_NORMAL, np.int64)
    lab2[2] = LABEL_ATTACK
    lab2[10] = LABEL_NATURAL
    _, y2, _, on2 = make_windows(np.zeros((20, 1), np.float32), lab2,
                                 np.full(20, 20, np.int64),
                                 WindowSpec(length=20, stride=20))
    check(y2[0] == LABEL_ATTACK, "attack outranks natural in the same window")
    check(on2[0] == 2, "onset is the first occurrence of the worst label")

    short = make_windows(np.zeros((3, 1), np.float32), np.zeros(3, np.int64),
                         np.zeros(3, np.int64), WindowSpec(length=10))
    check(short[0].shape[0] == 0, "fewer rows than the window yields nothing")


def test_normaliser():
    print("\n-- normalisation --")
    X = np.random.default_rng(0).standard_normal((50, 10, 4)).astype(np.float32)
    X[:, :, 2] = 7.0  # a channel that never moves

    n = Normaliser.fit(X)
    Z = n(X)
    check(abs(float(Z[:, :, 0].mean())) < 1e-4, "zero-mean on a live feature")
    check(abs(float(Z[:, :, 0].std()) - 1.0) < 1e-3, "unit-variance on a live feature")
    check(np.isfinite(Z).all(), "constant feature did not divide by zero")

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "n.npz"
        n.save(p)
        n2 = Normaliser.load(p)
        check(np.allclose(n.mean, n2.mean) and np.allclose(n.std, n2.std),
              "statistics survive a save/load round trip")

    # The deployment property: applying FITTED statistics to new data must not
    # recentre it. If it did, an attack would be normalised back to looking
    # ordinary.
    shifted = X + 5.0
    Zs = n(shifted)
    check(float(Zs[:, :, 0].mean()) > 1.0,
          "a shifted input stays shifted (no refitting at inference)")


def test_calibrator():
    print("\n-- ECDF calibration --")
    errs = np.linspace(0.0, 1.0, 1000)
    c = ECDFCalibrator(errs)

    check(0.49 < c.score(0.5) < 0.51, f"median scores ~0.5 ({c.score(0.5):.3f})")
    check(c.score(5.0) == 1.0, "far above calibration scores 1.0")
    check(c.score(-1.0) == 0.0, "below all calibration scores 0.0")

    s = c.score(np.array([0.1, 0.9, 0.5]))
    check(bool(s[0] < s[2] < s[1]), "monotone in the error")

    t = c.threshold_for_fpr(0.05)
    measured = c.measured_fpr(t)
    check(abs(measured - 0.05) < 0.02,
          f"threshold_for_fpr(0.05) measures {measured:.3f}")

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.npz"
        c.save(p)
        check(abs(ECDFCalibrator.load(p).score(0.5) - c.score(0.5)) < 1e-9,
              "calibrator survives a save/load round trip")

    try:
        ECDFCalibrator(np.array([1.0]))
        check(False, "too-small calibration set should raise")
    except ValueError:
        check(True, "too-small calibration set raises")


def test_model():
    print("\n-- autoencoder --")
    cfg = ModelConfig(n_features=6, window=20, latent=4)
    m = LSTMAutoencoder(cfg)
    x = torch.randn(8, 20, 6)

    out = m(x)
    check(out.shape == x.shape, f"reconstruction matches input shape {tuple(out.shape)}")
    check(torch.isfinite(out).all(), "reconstruction finite")
    check(m.encode(x).shape == (8, 4), "latent is the bottleneck width")

    ew, ef, es = (m.error_per_window(x), m.error_per_feature(x), m.error_per_step(x))
    check(ew.shape == (8,), f"per-window {tuple(ew.shape)}")
    check(ef.shape == (8, 6), f"per-feature {tuple(ef.shape)}")
    check(es.shape == (8, 20), f"per-step {tuple(es.shape)}")
    # All three are reductions of one error surface, so their means must agree.
    check(torch.allclose(ew, ef.mean(1), atol=1e-5)
          and torch.allclose(ew, es.mean(1), atol=1e-5),
          "the three error reductions are consistent")

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.pt"
        m.save(p)
        m2 = LSTMAutoencoder.load(p)
        with torch.no_grad():
            check(torch.allclose(m(x), m2(x), atol=1e-6),
                  "model survives a save/load round trip")


def test_split_is_disjoint():
    print("\n-- normal split --")
    ds = synthetic(n_normal=100, n_natural=20, n_attack=40, n_features=5,
                   spec=WindowSpec(length=20, stride=20), seed=1)
    tr, ca, ev = split_normal(ds, seed=1)

    check(all(tr.y == LABEL_NORMAL), "training split is normal only")
    check(all(ca.y == LABEL_NORMAL), "calibration split is normal only")
    check(len(tr) + len(ca) + len(ev) == len(ds), "split is a partition")

    # Disjointness is what keeps calibration thresholds honest.
    tr_rows = {x.tobytes() for x in tr.X}
    ca_rows = {x.tobytes() for x in ca.X}
    check(not (tr_rows & ca_rows), "train and calibration share no window")
    check((ev.y == LABEL_ATTACK).any() and (ev.y == LABEL_NATURAL).any(),
          "evaluation split retains attacks and naturals")


def test_attack_feature_alignment():
    """Regression: ground truth must be reindexed with its windows."""
    print("\n-- attribution ground truth alignment --")
    ds = synthetic(n_normal=40, n_natural=10, n_attack=30, n_features=6,
                   spec=WindowSpec(length=20, stride=20), seed=2)

    check(ds.attack_features is not None
          and len(ds.attack_features) == len(ds),
          "ground truth is aligned with X, one entry per window")
    check(all(ds.attack_features[i] == [] for i in np.flatnonzero(ds.y == LABEL_NORMAL)),
          "normal windows carry no injected features")

    mask = np.zeros(len(ds), bool)
    picked = np.flatnonzero(ds.y == LABEL_ATTACK)[[0, 5, 9]]
    mask[picked] = True
    sub = ds.subset(mask)
    check(sub.attack_features == [ds.attack_features[i] for i in picked],
          "subset carries the matching ground truth, not a reindexed shuffle")

    # And the corrupted features really are the ones that were changed.
    i = int(picked[0])
    feats = ds.attack_features[i]
    check(len(feats) >= 2 and max(feats) < ds.n_features,
          f"recorded features are in range ({feats})")

    # Regression: `onset` must be the row the fault was injected at, not an
    # independent draw. Detection delay is measured from it, so a mismatch
    # scatters the delay distribution around the truth and looks entirely
    # plausible. One injected feature is frozen from the onset onward, so a
    # correct onset makes it constant from there and (almost surely) not before.
    bad = 0
    for j in np.flatnonzero(ds.y == LABEL_ATTACK):
        o = int(ds.onset[j])
        fs = ds.attack_features[j]
        frozen = [f for f in fs
                  if np.allclose(ds.X[j, o:, f], ds.X[j, o, f], atol=1e-6)]
        if not frozen:
            bad += 1
    check(bad == 0,
          f"onset marks the real injection point in every attack window "
          f"({bad} mismatched)")


def _tiny_trained(td: Path, n_features=5, window=20, seed=0):
    from train import train
    ds = synthetic(n_normal=160, n_natural=30, n_attack=60,
                   n_features=n_features,
                   spec=WindowSpec(length=window, stride=window, sample_hz=1.0),
                   seed=seed)
    train(ds, td, epochs=6, batch=32, latent=4, patience=6, seed=seed, quiet=True)
    return ds


def test_detector_protocol():
    print("\n-- Detector protocol --")
    # The SERVER's protocol. A plain import now, since the LSTM module was
    # renamed to `lstm_detector` (P11); before that this had to be loaded by
    # file path or it silently resolved to the wrong module and tested nothing.
    sys.path.insert(0, str(_HERE.parent.parent / "python"))
    from detector import Detector

    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        _tiny_trained(out)
        det = LSTMDetector.from_dir(out, channel_ids=[0, 1, 2, 3, 4])

        check(isinstance(det, Detector), "satisfies the server's Detector protocol")
        check(isinstance(det.latency_ms, float), "exposes latency_ms")

        # Warm-up: no evidence, not a guess.
        b = _B([_S(i, 0.5) for i in range(5)])
        check(det.score(b) == 0.0, "returns 0.0 before the window fills")
        check(not det.ready, "reports itself not ready")

        for _ in range(25):
            det.score(_B([_S(i, float(np.sin(i))) for i in range(5)]))
        check(det.ready, "ready once the window has filled")

        s = det.score(_B([_S(i, float(np.sin(i))) for i in range(5)]))
        check(0.0 <= s <= 1.0, f"score stays in [0,1] ({s:.3f})")
        check(det.latency_ms > 0.0, f"latency measured ({det.latency_ms:.2f} ms)")

        m = det.attribute(_B([_S(i, 9.9 if i == 2 else 0.0) for i in range(5)]))
        check(isinstance(m, int) and m >= 0, f"attribute returns a bitmap ({m:#x})")

        # A dropped channel must hold its last value, not read as zero --
        # otherwise packet loss alarms the detector.
        det.reset()
        for _ in range(25):
            det.score(_B([_S(i, 3.0) for i in range(5)]))
        before = det._last_row.copy()
        det.score(_B([_S(0, 3.0)]))          # channels 1-4 missing
        check(np.allclose(det._last_row[1:], before[1:]),
              "missing channels carry forward instead of reading zero")


def test_deployed_matches_evaluated():
    """The scored-in-production path and the evaluated path must agree."""
    print("\n-- production path == evaluation path --")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        _tiny_trained(out)
        det = LSTMDetector.from_dir(out, channel_ids=[0, 1, 2, 3, 4])

        rng = np.random.default_rng(5)
        window = rng.standard_normal((20, 5)).astype(np.float32)

        array_score = float(det.score_array(window[None, ...])[0])

        det.reset()
        live = 0.0
        for row in window:
            live = det.score(_B([_S(i, float(row[i])) for i in range(5)]))

        check(abs(array_score - live) < 1e-5,
              f"same score both ways ({array_score:.6f} vs {live:.6f})")


def test_end_to_end():
    print("\n-- train, calibrate, evaluate --")
    from evaluate import evaluate

    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        ds = _tiny_trained(out)
        check((out / "model_best.pt").exists(), "saved model_best.pt")
        check((out / "calibrator.npz").exists(), "saved calibrator.npz")
        check((out / "normaliser.npz").exists(), "saved normaliser.npz")
        check((out / "train_meta.json").exists(), "saved train_meta.json")

        det = LSTMDetector.from_dir(out, channel_ids=list(range(5)))
        _, _, ev = split_normal(ds, seed=0)
        rep = evaluate(det, ev)

        check("average_precision" in rep["pr"], "report has a PR result")
        check(len(rep["operating_points"]) == 3, "three operating points")
        check(all("false_positive_rate_natural" in op
                  for op in rep["operating_points"]),
              "naturals reported separately at every operating point")
        check(rep["latency"]["per_window_ms"] > 0, "latency measured")
        ap = rep["pr"]["average_precision"]
        check(0.0 <= ap <= 1.0, f"average precision in range ({ap:.3f})")
        print(f"           (6-epoch smoke run: AP {ap:.3f}, "
              f"{rep['latency']['per_window_ms']:.2f} ms/window)")


def main() -> int:
    print("=== LSTM anomaly detector ===")
    torch.manual_seed(0)
    np.random.seed(0)

    test_scenario_grouping()
    test_windowing()
    test_normaliser()
    test_calibrator()
    test_model()
    test_split_is_disjoint()
    test_attack_feature_alignment()
    test_detector_protocol()
    test_deployed_matches_evaluated()
    test_end_to_end()

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
