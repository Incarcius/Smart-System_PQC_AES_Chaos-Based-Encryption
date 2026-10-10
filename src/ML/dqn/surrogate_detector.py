"""
detector.py — a surrogate for the LSTM, parameterised by its error rates.

The DQN has to train before the LSTM exists, and this is what makes that
possible without circularity: instead of a model, the environment supplies a
detector *characterised by* `(fpr, fnr, delay)`.

Why a surrogate is better than waiting for the real thing
---------------------------------------------------------
Training against one fixed detector produces a policy tuned to that detector's
quirks. Training across a *distribution* of `(fpr, fnr, delay)` produces a
policy that has learned the underlying tradeoff — when to trust an alarm, when
to act on local evidence instead, when a quiet detector means "safe" versus
"blinded". That policy transfers to the real LSTM whatever its error rates turn
out to be, and the robustness curve is the evidence for it.

So the surrogate is not scaffolding to be thrown away. It is how the policy is
made transferable, and the sweep over it is a headline result.

Calibration contract
--------------------
Scores are in [0, 1] with the same meaning the real detector must provide:
0.99 means "worse than 99% of normal windows". `server/LSTM/calibrate.py` will
fit an empirical CDF over held-out normal data to produce exactly that, which
is what makes the swap clean rather than a re-tuning exercise.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class SurrogateParams:
    """How good the detector is. Sweeping these produces the robustness curve."""

    fpr: float = 0.05
    """Fraction of clean windows scored as alarming."""

    fnr: float = 0.15
    """Fraction of compromised windows scored as benign. Higher than fpr on
    purpose: missing an intrusion is the harder error, and a detector tuned to
    avoid false alarms will miss more."""

    delay: int = 3
    """Steps between compromise and the detector being able to see it. Comes
    from the aggregation window plus inference plus the control round trip, so
    it is never zero — and it is why the gateway's local signals matter."""

    # -- score distributions, MEASURED at M4 ---------------------------------
    #
    # These were guesses until the LSTM existed. Scoring its held-out windows
    # (server/LSTM/runs) gave:
    #
    #     benign (no-event)   mean 0.503  Beta(0.96, 0.95)  -- i.e. UNIFORM
    #     alarming (attack)   mean 0.992  near-degenerate at 1.0
    #
    # The benign result is not an accident, it is forced by the calibration
    # contract. `score = ECDF of error over normal` makes normal data uniform
    # on [0, 1] BY CONSTRUCTION: that is what "0.99 means worse than 99% of
    # normal windows" entails. The old default, Beta(1.5, 6) with mean 0.2,
    # described a detector that reports near-zero when nothing is wrong -- a
    # perfectly reasonable detector, and not the one this project builds.
    #
    # The consequence was not subtle. A policy trained to read 0.2 as "calm"
    # sees a real calibrated detector sitting at 0.5 on an untroubled grid and
    # reads permanent mild alarm. In the M5 loop that collapsed HOLD from 60%
    # of calm steps to 5% and pushed ROTATE from 7% to 42%. The policy was not
    # broken; it was answering a question nobody had asked it before.
    #
    # Changing these defaults invalidates every DQN result produced before this
    # measurement. Those were obtained with alarm Beta(5, 1.5) / benign
    # Beta(1.5, 6); see DQN_SPEC 12.

    alarm_a: float = 2.0
    alarm_b: float = 0.05
    """Mass tight against 1.0, matching the measured attack distribution. The
    exact moment-fit was Beta(1.78, 0.01), which is numerically degenerate;
    this is the same shape with a usable tail."""

    benign_a: float = 1.0
    benign_b: float = 1.0
    """Uniform. Not a modelling choice -- the direct consequence of ECDF
    calibration, measured at Beta(0.96, 0.95).

    Note what this makes hard: roughly 10% of perfectly normal windows score
    above 0.9. A policy cannot treat a high score as proof of anything, which
    is the real problem and was previously hidden by a benign distribution that
    almost never produced one."""

    # -- benign disturbances ------------------------------------------------
    #
    # Added after M4 measured the real detector. The LSTM false-alarms on
    # 98-100% of natural disturbances -- storms, line faults, maintenance --
    # at every operating point (server/LSTM/README.md). A single `fpr` cannot
    # express that: the real detector has about 0.05 on a calm grid and about
    # 1.0 during a fault, and which one applies depends on the weather.
    #
    # A disturbance is BENIGN. It never sets `compromised`, so the reward is
    # unchanged and an agent that escalates through one is simply wrong. That
    # is the point: this is the regime where trusting the detector is
    # punished, and the agent has to weigh the alarm against its own local
    # evidence instead.
    #
    # Defaults are off, so every existing result reproduces exactly.

    disturbance_rate: float = 0.0
    """Probability per step that a benign disturbance begins."""

    disturbance_len: int = 5
    """How many steps one lasts. A fault transient is short but not
    instantaneous, and a detector averaging over a window keeps firing after
    the physics have settled."""

    fpr_disturbed: float = 1.0
    """False-alarm rate while a disturbance is active. Measured at 0.98-1.00
    on MSU/ORNL, so 1.0 is the honest default rather than a pessimistic one."""


class SurrogateDetector:
    """Emits scores consistent with a detector of the given quality.

    Deliberately stateful about `delay`: the score reflects the compromise
    state as it was `delay` steps ago, so the agent experiences detection lag
    exactly as it will in deployment.
    """

    def __init__(self, params: SurrogateParams | None = None, rng=None) -> None:
        self.params = params or SurrogateParams()
        self.rng = rng if rng is not None else np.random.default_rng()
        self._history: list[bool] = []
        self._disturbed_until: int = -1

    def reset(self) -> None:
        self._history = []
        self._disturbed_until = -1

    @property
    def disturbed(self) -> bool:
        """Is a benign disturbance active right now?

        Exposed for instrumentation only. The agent must NOT observe this --
        if it could see which alarms were storms it would not need a policy.
        """
        return len(self._history) <= self._disturbed_until

    def _advance_disturbance(self) -> None:
        p = self.params
        if p.disturbance_rate <= 0.0:
            return
        now = len(self._history)
        if now > self._disturbed_until and self.rng.random() < p.disturbance_rate:
            self._disturbed_until = now + p.disturbance_len

    def _effective_fpr(self) -> float:
        return (self.params.fpr_disturbed if self.disturbed
                else self.params.fpr)

    def observe(self, compromised: bool) -> float:
        """Advance one step and return this step's score."""
        self._history.append(bool(compromised))
        self._advance_disturbance()

        # What the detector can actually see, `delay` steps behind.
        idx = len(self._history) - 1 - self.params.delay
        visible = self._history[idx] if idx >= 0 else False

        p = self.params
        if visible:
            # A compromised window. With probability fnr the detector misses it
            # and draws from the benign distribution instead.
            if self.rng.random() < p.fnr:
                return float(self.rng.beta(p.benign_a, p.benign_b))
            return float(self.rng.beta(p.alarm_a, p.alarm_b))

        # A clean window. It false-alarms with probability fpr normally, and
        # with fpr_disturbed while a benign fault is in progress.
        if self.rng.random() < self._effective_fpr():
            return float(self.rng.beta(p.alarm_a, p.alarm_b))
        return float(self.rng.beta(p.benign_a, p.benign_b))

    def peek_now(self, compromised: bool) -> float:
        """Score with zero delay. Models FORCE_FLUSH: the agent spends
        bandwidth to shorten detection lag for one step, which is a genuine
        buy-information action rather than a bolted-on one.

        Note it does not escape a disturbance: paying for a faster look at a
        detector that is currently crying wolf buys a faster false alarm.
        """
        p = self.params
        if compromised:
            if self.rng.random() < p.fnr:
                return float(self.rng.beta(p.benign_a, p.benign_b))
            return float(self.rng.beta(p.alarm_a, p.alarm_b))
        if self.rng.random() < self._effective_fpr():
            return float(self.rng.beta(p.alarm_a, p.alarm_b))
        return float(self.rng.beta(p.benign_a, p.benign_b))


def sweep_grid() -> list[SurrogateParams]:
    """The detector qualities to train and evaluate across.

    Spans plausible-to-poor. A policy that only works at (0.02, 0.05) has
    learned to trust the detector unconditionally, which is precisely the
    failure the Ukraine case study warns about.
    """
    grid = []
    for fpr in (0.02, 0.05, 0.15):
        for fnr in (0.05, 0.15, 0.35):
            for delay in (1, 3, 6):
                grid.append(SurrogateParams(fpr=fpr, fnr=fnr, delay=delay))
    return grid


def disturbance_grid(base: SurrogateParams | None = None) -> list[SurrogateParams]:
    """The regime M4 actually measured: a detector that cries wolf at faults.

    `fpr` stays at its calm-grid value because that is what the LSTM measures
    on quiet data; what changes is how often the grid is disturbed, and during
    a disturbance the detector is useless (fpr_disturbed = 1.0).

    Disturbance rates of 0.01 / 0.03 / 0.06 per step with a 5-step duration put
    roughly 5% / 14% / 26% of steps inside a disturbance. There is no published
    fault rate for a prototype rig, so this is a sweep rather than a value, for
    the same reason the detector quality is swept rather than assumed.
    """
    base = base or SurrogateParams()
    out = []
    for rate in (0.01, 0.03, 0.06):
        for delay in (1, 3, 6):
            out.append(SurrogateParams(
                fpr=base.fpr, fnr=base.fnr, delay=delay,
                disturbance_rate=rate, disturbance_len=5, fpr_disturbed=1.0))
    return out


__all__ = ["SurrogateDetector", "SurrogateParams", "sweep_grid",
           "disturbance_grid"]
