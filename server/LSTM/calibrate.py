"""calibrate.py — turn reconstruction error into a score the DQN can read.

The problem
-----------
Raw reconstruction error is unbounded and scale-dependent: "0.0043" means
nothing on its own, and it changes if you retrain, change the feature set, or
deploy on different sensors. The DQN was trained against a surrogate detector
emitting a calibrated `[0, 1]`, and `env.py` reads that number directly. Hand it
raw error and every threshold it learned becomes meaningless.

The fix (REMAINING_WORK 3.3)
----------------------------
    score = empirical CDF of reconstruction error, fitted on held-out NORMAL

So `score = 0.99` means "worse than 99% of normal windows" — a statement about
*this* detector's own normal behaviour, which is exactly what makes it portable
across retraining and across the MSU/ORNL-to-rig swap. It also means the
`(fpr, fnr)` grid the DQN trained against maps onto real thresholds instead of
arbitrary units: a threshold set at the 0.95 quantile of normal gives a 5%
false-positive rate **by construction**.

That last property is why this file exists rather than a `min/max` rescale.

Held-out is load-bearing
------------------------
The calibration set must be normal windows the autoencoder never trained on.
Calibrating on training data reports errors lower than production will ever
produce, so every quantile sits too low, and the deployed detector fires
constantly on ordinary traffic. `data.split_normal` keeps them disjoint.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np


class ECDFCalibrator:
    """Maps raw error to [0, 1] by its rank among held-out normal errors."""

    def __init__(self, normal_errors: np.ndarray) -> None:
        e = np.asarray(normal_errors, dtype=np.float64).ravel()
        e = e[np.isfinite(e)]
        if e.size < 2:
            raise ValueError("need at least 2 finite calibration errors")
        self.sorted = np.sort(e)

    def __len__(self) -> int:
        return int(self.sorted.size)

    def score(self, error) -> np.ndarray | float:
        """Fraction of calibration errors at or below `error`.

        `side="right"` so an error equal to the largest calibration value
        scores 1.0 rather than just under it. Monotone by construction, which
        the posture ladder depends on: a worse reconstruction can never produce
        a lower score.
        """
        e = np.asarray(error, dtype=np.float64)
        idx = np.searchsorted(self.sorted, e, side="right")
        out = idx / self.sorted.size
        return float(out) if np.isscalar(error) or out.ndim == 0 else out

    def threshold_for_fpr(self, fpr: float) -> float:
        """Raw-error threshold giving this false-positive rate on normal.

        This is the bridge to the DQN: `detector.py`'s surrogate is
        parameterised by `fpr`, and the sweep grid used 0.02 / 0.05 / 0.15. Those
        now correspond to concrete thresholds instead of a modelling assumption.
        """
        if not 0.0 < fpr < 1.0:
            raise ValueError(f"fpr must be in (0,1), got {fpr}")
        return float(np.quantile(self.sorted, 1.0 - fpr))

    def measured_fpr(self, threshold: float) -> float:
        """What the threshold actually costs on the calibration set.

        Quantile interpolation and ties mean the realised rate can differ from
        the requested one on small calibration sets. Reporting the measured
        value keeps the claim honest.
        """
        return float((self.sorted > threshold).mean())

    def save(self, path: Path) -> None:
        np.savez_compressed(path, sorted=self.sorted)

    @classmethod
    def load(cls, path: Path) -> "ECDFCalibrator":
        obj = cls.__new__(cls)
        obj.sorted = np.load(path)["sorted"]
        return obj


def fit_calibrator(model, X_normal: np.ndarray, batch: int = 256) -> ECDFCalibrator:
    """Run held-out normal windows through the model and fit the ECDF."""
    import torch

    model.eval()
    errs = []
    with torch.no_grad():
        for i in range(0, len(X_normal), batch):
            xb = torch.from_numpy(X_normal[i:i + batch])
            errs.append(model.error_per_window(xb).cpu().numpy())
    return ECDFCalibrator(np.concatenate(errs))
