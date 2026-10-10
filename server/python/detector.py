"""
detector.py — the anomaly-detection interface, and a stub that satisfies it.

The LSTM (Phase B) will implement `Detector`. Everything downstream — the lease
issuer, the posture ladder, the quarantine mask — talks only to this interface,
so swapping the stub for the trained model changes one constructor argument and
nothing else.

Why the contract matters more than the model
--------------------------------------------
The DQN is trained against a *surrogate* detector parameterised by
`(fpr, fnr, delay)`. For that training to transfer, the real detector has to
expose the same three things the surrogate does:

  * `score()`  — calibrated to [0, 1], where 0.99 means "worse than 99% of
                 normal windows". Raw reconstruction error is unbounded and
                 scale-dependent; a calibrated score is what makes the
                 surrogate's fpr/fnr map onto real thresholds.
  * `attribute()` — WHICH channels. `tg_control_t.node_mask` carries a bitmap,
                 and a detector that only says "something is wrong" cannot
                 drive quarantine at all.
  * `latency_ms` — measured, because the server has a 1 s window to fit
                 inference plus crypto into, and the gateway reads it as a
                 resource feature.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Protocol, runtime_checkable


@runtime_checkable
class Detector(Protocol):
    """What Phase B must implement."""

    @property
    def latency_ms(self) -> float: ...

    def score(self, batch) -> float:
        """Calibrated anomaly score in [0, 1] for one aggregation window."""

    def attribute(self, batch) -> int:
        """Bitmap of the channels most responsible. Feeds node_mask."""


class StubDetector:
    """Rolling per-channel z-score. Stands in until the LSTM lands.

    Deliberately simple and deliberately *not* good: it exists so the pipe can
    be built and soaked end to end, and so the server has something to issue
    postures from. It is also one of the DQN's baselines, so writing it is not
    throwaway work.

    What it cannot do, and the LSTM must: use temporal structure. A z-score
    sees each sample independently, so a slow drift or a coordinated
    multi-channel pattern is invisible to it. That is exactly the gap the
    autoencoder is for.
    """

    def __init__(self, window: int = 60, warmup: int = 10, z_saturate: float = 6.0):
        self.window = window
        self.warmup = warmup
        self.z_saturate = z_saturate
        self._history: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self._last_z: dict[int, float] = {}
        self._latency_ms = 0.0

    @property
    def latency_ms(self) -> float:
        return self._latency_ms

    def _z_scores(self, batch) -> dict[int, float]:
        z: dict[int, float] = {}

        for sample in batch.trusted:
            hist = self._history[sample.channel_id]

            if len(hist) >= self.warmup:
                mean = sum(hist) / len(hist)
                var = sum((x - mean) ** 2 for x in hist) / len(hist)
                sd = math.sqrt(var)
                # A channel that has genuinely never moved (a relay that has
                # not switched) has sd == 0. Treat any deviation from a
                # constant as maximally surprising rather than dividing by zero.
                if sd < 1e-9:
                    z[sample.channel_id] = 0.0 if abs(sample.value - mean) < 1e-9 else self.z_saturate
                else:
                    z[sample.channel_id] = abs(sample.value - mean) / sd

            hist.append(sample.value)

        # A quality flag is evidence in its own right: a sensor reporting
        # STALE or out-of-range is not an attack, but it IS something the
        # operator should see, so it lifts the score rather than being ignored.
        for sample in batch.trusted:
            if sample.quality != 0:
                z[sample.channel_id] = max(z.get(sample.channel_id, 0.0), 2.0)

        self._last_z = z
        return z

    def score(self, batch) -> float:
        t0 = time.perf_counter()
        z = self._z_scores(batch)
        self._latency_ms = (time.perf_counter() - t0) * 1000.0

        if not z:
            return 0.0

        # Max, not mean: one channel behaving badly is the signal, and
        # averaging would let four quiet channels hide it.
        return min(1.0, max(z.values()) / self.z_saturate)

    def attribute(self, batch) -> int:
        """Channels within 25% of the worst z-score. Bitmap for node_mask."""
        if not self._last_z:
            self._z_scores(batch)
        if not self._last_z:
            return 0

        worst = max(self._last_z.values())
        if worst <= 0:
            return 0

        mask = 0
        for cid, z in self._last_z.items():
            if z >= 0.75 * worst and cid < 32:
                mask |= 1 << cid
        return mask


__all__ = ["Detector", "StubDetector"]
