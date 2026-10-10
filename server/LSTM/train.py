"""train.py — fit the autoencoder on normal traffic only.

What "normal only" means operationally
--------------------------------------
The attack windows in the dataset are never shown to the optimiser. They exist
in this file only to be *withheld*. That is not a limitation to apologise for —
it is the property that lets the same code train on rig data later, where no
labelled attack will ever exist.

Model selection
---------------
Best epoch by held-out normal loss, not final epoch. This is the lesson from
the DQN runs written down and applied: the first DQN run saved only its final
weights and happened to finish near its peak, which was luck, and a selection
signal computed on too little data turned out to be worse than no selection at
all (DQN_SPEC 12.10). Here the validation set is thousands of windows rather
than three episodes, so the signal is sound — but it is still held-out normal,
never attacks. Selecting on attack performance would quietly turn this into a
supervised detector that cannot be reproduced on the rig.

Usage:
    python server/LSTM/train.py --data <dir>      # MSU/ORNL CSVs
    python server/LSTM/train.py --synthetic       # no download needed
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

torch.set_num_threads(1)

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from calibrate import fit_calibrator  # noqa: E402
from data import (  # noqa: E402
    LABEL_NATURAL,
    LABEL_NORMAL,
    Normaliser,
    WindowSpec,
    load_multiclass,
    split_normal,
    synthetic,
)
from model import LSTMAutoencoder, ModelConfig, count_parameters  # noqa: E402


def train(
    ds,
    out_dir: Path,
    epochs: int = 60,
    batch: int = 64,
    lr: float = 1e-3,
    latent: int = 16,
    patience: int = 12,
    seed: int = 0,
    benign: tuple[int, ...] = (LABEL_NORMAL,),
    quiet: bool = False,
) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    tr, ca, ev = split_normal(ds, seed=seed, benign=benign)
    if not quiet:
        print(f"windows: train-normal {len(tr)}  calib-normal {len(ca)}  "
              f"evaluate {len(ev)}  ({ds.counts()})")

    # Statistics from TRAINING normal only. Fitting them on everything would
    # leak attack scale into the normalisation and shrink the very deviation
    # the detector exists to notice.
    norm = Normaliser.fit(tr.X)
    Xtr, Xca = norm(tr.X), norm(ca.X)

    # A slice of training normal is held back as the epoch-selection signal.
    # It is normal data the optimiser never sees, which is the only honest
    # early-stopping criterion available on a rig.
    cut = max(1, int(len(Xtr) * 0.85))
    Xfit, Xval = Xtr[:cut], Xtr[cut:]
    if len(Xval) == 0:
        Xval = Xfit[:1]

    cfg = ModelConfig(n_features=ds.n_features, window=ds.spec.length,
                      latent=latent)
    model = LSTMAutoencoder(cfg)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    lossf = nn.MSELoss()

    if not quiet:
        print(f"model: {count_parameters(model)} parameters, "
              f"latent {latent}, window {cfg.window}, features {cfg.n_features}")

    best, best_ep, bad = float("inf"), -1, 0
    history = {"train": [], "val": []}
    t0 = time.time()

    for ep in range(epochs):
        model.train()
        perm = np.random.permutation(len(Xfit))
        tot, nb = 0.0, 0
        for i in range(0, len(perm), batch):
            xb = torch.from_numpy(Xfit[perm[i:i + batch]])
            opt.zero_grad()
            loss = lossf(model(xb), xb)
            loss.backward()
            # The recurrent layers make exploding gradients a real possibility
            # early on; clipping keeps a single bad batch from destroying a run.
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            tot += float(loss)
            nb += 1
        tr_loss = tot / max(nb, 1)

        model.eval()
        with torch.no_grad():
            vb = torch.from_numpy(Xval)
            val_loss = float(lossf(model(vb), vb))

        history["train"].append(tr_loss)
        history["val"].append(val_loss)

        improved = val_loss < best - 1e-9
        if improved:
            best, best_ep, bad = val_loss, ep + 1, 0
            model.save(out_dir / "model_best.pt")
        else:
            bad += 1

        if not quiet:
            print(f"  epoch {ep+1:3d}  train {tr_loss:.6f}  val {val_loss:.6f}"
                  + ("   <-- saved" if improved else ""), flush=True)

        if bad >= patience:
            if not quiet:
                print(f"  early stop: {patience} epochs without improvement")
            break

    model = LSTMAutoencoder.load(out_dir / "model_best.pt")

    # Calibrate on the held-out normal split, which the optimiser never saw.
    calib = fit_calibrator(model, Xca)
    calib.save(out_dir / "calibrator.npz")
    norm.save(out_dir / "normaliser.npz")

    meta = {
        "best_epoch": best_ep,
        "best_val_loss": best,
        "epochs_run": len(history["train"]),
        "seconds": time.time() - t0,
        "n_features": ds.n_features,
        "window": ds.spec.length,
        "sample_hz": ds.spec.sample_hz,
        "latent": latent,
        "calibration_windows": len(calib),
        "counts": ds.counts(),
        "trained_on": [int(b) for b in benign],
        "thresholds": {str(f): calib.threshold_for_fpr(f)
                       for f in (0.02, 0.05, 0.15)},
    }
    (out_dir / "train_meta.json").write_text(json.dumps(meta, indent=2))

    if not quiet:
        print(f"\nbest val loss {best:.6f} at epoch {best_ep} "
              f"({meta['seconds']:.1f}s)")
        print(f"calibrated on {len(calib)} held-out normal windows")
        print("thresholds mapping onto the DQN's trained fpr grid:")
        for f, t in meta["thresholds"].items():
            print(f"  fpr {f}: raw error > {t:.6g} "
                  f"(measured {calib.measured_fpr(t):.3f})")
        print(f"saved to {out_dir}")

    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=None,
                    help="directory of MSU/ORNL multiclass CSVs")
    ap.add_argument("--synthetic", action="store_true",
                    help="use the synthetic stand-in (no download)")
    ap.add_argument("--out", type=Path, default=_HERE / "runs")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--latent", type=int, default=16)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--features", type=int, default=12,
                    help="synthetic only: channel count. The rig has 5.")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--train-on", choices=["no-event", "benign"],
                    default="no-event",
                    help="no-event: calm grid only. benign: include natural "
                         "disturbances, which is what a real rig collects.")
    ap.add_argument("--loose", action="store_true",
                    help="warn instead of raising on scenario-table mismatch")
    args = ap.parse_args()

    if args.data:
        ds = load_multiclass(args.data,
                             WindowSpec(length=args.window, stride=10,
                                        sample_hz=120.0),
                             strict=not args.loose)
    elif args.synthetic:
        ds = synthetic(n_features=args.features,
                       spec=WindowSpec(length=args.window, stride=args.window,
                                       sample_hz=1.0), seed=args.seed)
        print("SYNTHETIC DATA — for pipeline testing only. "
              "Nothing from this run belongs in the paper.")
    else:
        ap.error("pass --data <dir> or --synthetic")

    benign = ((LABEL_NORMAL, LABEL_NATURAL) if args.train_on == 'benign'
              else (LABEL_NORMAL,))
    train(ds, args.out, epochs=args.epochs, latent=args.latent,
          seed=args.seed, benign=benign)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
