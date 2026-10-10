"""detector.py — the trained autoencoder behind the `Detector` protocol.

Drop-in for `StubDetector`. Everything downstream — the lease issuer, the
posture ladder, the quarantine mask — talks only to the protocol, so swapping
this in changes one constructor argument in the server daemon and nothing else.

Two entry points, deliberately
------------------------------
`score(batch)` / `attribute(batch)` are the **production** path: they take the
aggregated telemetry batch the server already builds, maintain their own
rolling window, and return what the posture machinery expects.

`score_array(X)` / `errors_per_step(X)` are the **evaluation** path, taking
(N, T, F) arrays straight from `data.py`. Keeping them separate avoids the
usual trap of evaluating a different code path from the one that is deployed:
both reduce to `_calibrated_from_error`, so a change to scoring cannot apply to
one and not the other.

Warm-up is not a detail
-----------------------
The model needs T rows before it can score anything. Until then the detector
returns 0.0 — "no evidence" — rather than a guess. Returning a high score while
uninitialised would escalate posture on every server restart; returning a
middling one would be invented evidence. The DQN reads this number as fact.
"""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path

import numpy as np
import torch

_HERE = Path(__file__).resolve().parent
import sys  # noqa: E402

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from calibrate import ECDFCalibrator  # noqa: E402
from data import Normaliser  # noqa: E402
from model import LSTMAutoencoder  # noqa: E402


class LSTMDetector:
    """Autoencoder + ECDF calibration, satisfying `Detector`."""

    def __init__(
        self,
        model: LSTMAutoencoder,
        normaliser: Normaliser,
        calibrator: ECDFCalibrator,
        channel_ids: list[int] | None = None,
        feature_to_channel: np.ndarray | None = None,
    ) -> None:
        self.model = model
        self.model.eval()
        self.norm = normaliser
        self.calib = calibrator

        self.window = model.cfg.window
        self.n_features = model.cfg.n_features

        # Feature order is fixed at construction. If it drifted between
        # training and deployment every feature would be compared against the
        # wrong statistics, and the failure would look like "the detector got
        # worse" rather than like a bug.
        self.channel_ids = list(channel_ids or range(self.n_features))
        if len(self.channel_ids) != self.n_features and feature_to_channel is None:
            raise ValueError(
                f"model expects {self.n_features} features but "
                f"{len(self.channel_ids)} channel ids were given; pass "
                f"feature_to_channel for datasets whose features are not "
                f"one-per-channel (e.g. MSU/ORNL)"
            )
        self._col = {cid: i for i, cid in enumerate(self.channel_ids)}
        self.feature_to_channel = (
            np.asarray(feature_to_channel) if feature_to_channel is not None
            else np.asarray(self.channel_ids)
        )

        self._buf: deque[np.ndarray] = deque(maxlen=self.window)
        self._last_row = np.zeros(self.n_features, np.float32)
        self._last_feature_error: np.ndarray | None = None
        self._latency_ms = 0.0

    # -- protocol -----------------------------------------------------------

    @property
    def latency_ms(self) -> float:
        return self._latency_ms

    @property
    def ready(self) -> bool:
        return len(self._buf) >= self.window

    def reset(self) -> None:
        self._buf.clear()
        self._last_feature_error = None

    def score(self, batch) -> float:
        t0 = time.perf_counter()
        self._push(batch)

        if not self.ready:
            self._latency_ms = (time.perf_counter() - t0) * 1000.0
            return 0.0

        X = np.stack(self._buf)[None, ...]
        s = float(self._calibrated_from_error(self._forward(X))[0])
        self._latency_ms = (time.perf_counter() - t0) * 1000.0
        return s

    def attribute(self, batch) -> int:
        """Bitmap of the channels most responsible.

        Per-feature reconstruction error comes free with the forward pass that
        produced the score, which is the practical reason this is an
        autoencoder and not a classifier: quarantine must name a node, and
        `tg_control_t.node_mask` carries exactly this bitmap.

        Channels within 75% of the worst error are included, matching
        `StubDetector` so the two behave alike where they can.
        """
        if self._last_feature_error is None:
            self.score(batch)
        if self._last_feature_error is None:
            return 0

        per_chan: dict[int, float] = {}
        for feat_ix, err in enumerate(self._last_feature_error):
            cid = int(self.feature_to_channel[feat_ix])
            if cid < 0:
                continue
            per_chan[cid] = max(per_chan.get(cid, 0.0), float(err))

        if not per_chan:
            return 0
        worst = max(per_chan.values())
        if worst <= 0:
            return 0

        mask = 0
        for cid, err in per_chan.items():
            if err >= 0.75 * worst and 0 <= cid < 32:
                mask |= 1 << cid
        return mask

    # -- evaluation path ----------------------------------------------------

    def score_array(self, X: np.ndarray, batch: int = 256) -> np.ndarray:
        """Calibrated scores for (N, T, F) raw (un-normalised) windows."""
        out = []
        for i in range(0, len(X), batch):
            out.append(self._calibrated_from_error(X[i:i + batch]))
        return np.concatenate(out) if out else np.empty(0)

    def errors(self, X: np.ndarray, batch: int = 256) -> np.ndarray:
        """(N,) RAW per-window reconstruction error, uncalibrated.

        Evaluation thresholds must come from this, not from `score_array`. The
        calibrated score is a rank among a finite calibration set, so it
        saturates: every window worse than the worst calibration window scores
        exactly 1.0. Choosing a threshold as a high quantile of saturated
        scores can land on 1.0, and `score > 1.0` is then never true -- which
        reports zero detections for a model that is detecting perfectly well.
        Raw error is continuous and has no such ceiling.

        The calibrated score remains the right thing to hand the DQN: it is
        stable across retraining, which is what the surrogate's fpr/fnr grid
        depends on. The two uses are different and so are the units.
        """
        outs = []
        with torch.no_grad():
            for i in range(0, len(X), batch):
                xb = torch.from_numpy(self.norm(X[i:i + batch]))
                outs.append(self.model.error_per_window(xb).cpu().numpy())
        return np.concatenate(outs) if outs else np.empty(0)

    def errors_per_step(self, X: np.ndarray, batch: int = 256) -> np.ndarray:
        """(N, T) reconstruction error, for measuring detection delay."""
        outs = []
        with torch.no_grad():
            for i in range(0, len(X), batch):
                xb = torch.from_numpy(self.norm(X[i:i + batch]))
                outs.append(self.model.error_per_step(xb).cpu().numpy())
        return np.concatenate(outs) if outs else np.empty((0, self.window))

    def errors_per_feature(self, X: np.ndarray, batch: int = 256) -> np.ndarray:
        """(N, F) reconstruction error, for measuring attribution accuracy."""
        outs = []
        with torch.no_grad():
            for i in range(0, len(X), batch):
                xb = torch.from_numpy(self.norm(X[i:i + batch]))
                outs.append(self.model.error_per_feature(xb).cpu().numpy())
        return np.concatenate(outs) if outs else np.empty((0, self.n_features))

    # -- internals ----------------------------------------------------------

    def _forward(self, X_raw: np.ndarray) -> np.ndarray:
        """Returns per-window error and caches the per-feature breakdown."""
        with torch.no_grad():
            xb = torch.from_numpy(self.norm(X_raw))
            recon = self.model(xb)
            sq = (xb - recon) ** 2
            self._last_feature_error = sq.mean(dim=1)[-1].cpu().numpy()
            return sq.mean(dim=(1, 2)).cpu().numpy()

    def _calibrated_from_error(self, X_or_err) -> np.ndarray:
        if isinstance(X_or_err, np.ndarray) and X_or_err.ndim == 3:
            err = self._forward(X_or_err)
        else:
            err = np.asarray(X_or_err)
        return np.atleast_1d(self.calib.score(err))

    def _push(self, batch) -> None:
        """One aggregation window becomes one row.

        Channels missing from the batch entirely carry their previous value
        forward rather than reading zero. A dropped sample is not a reading of
        zero, and injecting one would itself look like an anomaly — the
        detector would alarm on packet loss.

        **Quarantined channels are still ingested.** They arrive in
        `batch.untrusted` rather than `batch.trusted`, and reading only the
        trusted list creates a trap: the quarantined channel's last bad value
        is carried forward for every subsequent window, so the detector keeps
        scoring it anomalous forever and the channel can never be observed to
        recover. Release is then undone on the very next tick, and quarantine
        becomes permanent in practice — which contradicts the documented
        "isolate and continue as untrusted, triage, release" cycle.

        Ingesting untrusted data is safe here because this is a *detector*, not
        a control path. Quarantine means "do not trust this channel's readings
        for control decisions", and nothing downstream acts on the score alone:
        the DQN weighs it, the shield bounds the response, and release stays an
        explicit triage action at both ends. A compromised channel can push the
        score **up**, which is fail-secure; reconstruction error does not fall
        because an input is hostile.
        """
        row = self._last_row.copy()
        # Trusted last, so it wins if a channel somehow appears in both.
        for group in ("untrusted", "trusted"):
            for sample in getattr(batch, group, []):
                ix = self._col.get(sample.channel_id)
                if ix is not None:
                    row[ix] = float(sample.value)
        self._last_row = row
        self._buf.append(row)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dir(cls, run_dir: Path, **kw) -> "LSTMDetector":
        run_dir = Path(run_dir)
        return cls(
            LSTMAutoencoder.load(run_dir / "model_best.pt"),
            Normaliser.load(run_dir / "normaliser.npz"),
            ECDFCalibrator.load(run_dir / "calibrator.npz"),
            **kw,
        )


__all__ = ["LSTMDetector"]
