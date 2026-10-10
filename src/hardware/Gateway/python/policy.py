"""
policy.py — the key-lifecycle decision layer, and the shield around it.

This is the seam the DQN plugs into. Everything here is deliberately small:
the daemon builds an `Observation`, the policy returns an `Action`, and the
shield decides whether that action is allowed. Swapping the stub for a trained
agent is one constructor argument.

The shield is the important part
--------------------------------
The agent proposes; the shield disposes. Unsafe actions are unreachable by
construction rather than learned-away, which is what makes it defensible to
run a learned policy on a substation gateway at all:

  - nonce exhaustion forces a rotation regardless of what the policy wants
  - a rotation rate limit stops a policy that has learned to thrash, and stops
    a forged-control-message flood turning into a rekey-storm DoS
  - root-key requests are rate limited separately (they cost ~91 ms measured)
  - posture de-escalation obeys the ENFORCE floor and `min_hold_ms`, both
    already enforced inside `PostureState.request()`
  - quarantine requires ANOMALY posture

Two stubs ship here, and they are not throwaway: `FixedIntervalPolicy` and
`ThresholdPolicy` are two of the five baselines the DQN must be evaluated
against (docs/DQN_SPEC.md §9), so building them now is work that counts twice.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Protocol

_REPO = Path(__file__).resolve().parents[4]
_ACCM = _REPO / "src" / "security" / "ACCM" / "python"
if str(_ACCM) not in sys.path:
    sys.path.insert(0, str(_ACCM))

from protocol import Posture, SEQ_MAX  # noqa: E402


class Action(IntEnum):
    """The eight actions from docs/DQN_SPEC.md §4."""

    HOLD = 0
    ROTATE_SESSION_KEY = 1
    REFRESH_POOL = 2
    REQUEST_ROOT_KEY = 3
    ESCALATE_POSTURE = 4
    DEESCALATE_POSTURE = 5
    QUARANTINE_WORST_CHANNEL = 6
    FORCE_FLUSH = 7


@dataclass
class Observation:
    """What the policy sees each tick.

    Mirrors the DQN state vector so the trained agent needs no adapter. The
    agent never sees ground truth about compromise — only the detector score
    and the gateway's own local signals. That is what makes the policy
    interesting rather than a lookup table.
    """

    # threat
    lstm_score: float = 0.0
    lstm_ewma_fast: float = 0.0
    lstm_ewma_slow: float = 0.0
    posture: int = int(Posture.NORMAL)
    time_in_posture_ms: int = 0

    # control plane
    lease_remaining_ms: int = 0
    lease_ms: int = 0
    time_since_ctrl_ms: int = 0
    directive_floor: int = int(Posture.NORMAL)
    quarantined_channels: int = 0
    ctrl_reject_rate: float = 0.0

    # key lifecycle
    seq_used: int = 0
    key_age_ms: int = 0
    bytes_under_key: int = 0
    time_since_root_ms: int = 0
    rotations_in_window: int = 0

    # local fast-path detection
    gcm_auth_fail_rate: float = 0.0
    replay_reject_rate: float = 0.0
    silent_channels: int = 0

    # resource
    queue_depth: int = 0
    n_channels: int = 1

    def to_vector(self) -> list[float]:
        """Normalised feature vector for a learned policy.

        Clipped to keep a pathological value from dominating the input; the
        DQN spec pins the exact ordering.
        """
        def clip(x: float, hi: float = 1.0) -> float:
            return 0.0 if x < 0.0 else (hi if x > hi else x)

        lease = max(self.lease_ms, 1)
        return [
            clip(self.lstm_score),
            clip(self.lstm_ewma_fast),
            clip(self.lstm_ewma_slow),
            1.0 if self.posture == Posture.NORMAL else 0.0,
            1.0 if self.posture == Posture.SUSPICIOUS else 0.0,
            1.0 if self.posture == Posture.ANOMALY else 0.0,
            clip(self.lease_remaining_ms / lease),
            clip(self.time_since_ctrl_ms / lease, 3.0),
            self.directive_floor / 2.0,
            clip(self.quarantined_channels / max(self.n_channels, 1)),
            clip(self.ctrl_reject_rate),
            clip(self.seq_used / SEQ_MAX),
            clip(self.key_age_ms / 3_600_000, 2.0),
            clip(self.bytes_under_key / 1e9),
            clip(self.time_since_root_ms / 86_400_000, 2.0),
            clip(self.rotations_in_window / 10.0),
            clip(self.gcm_auth_fail_rate),
            clip(self.replay_reject_rate),
            clip(self.silent_channels / max(self.n_channels, 1)),
            clip(self.queue_depth / 1000.0),
        ]


class Policy(Protocol):
    """What the DQN will implement. Deliberately one method."""

    name: str

    def decide(self, obs: Observation) -> Action: ...


# ── baselines / stubs ───────────────────────────────────────────────────────


class FixedIntervalPolicy:
    """Rotate every N ticks, ignore everything else.

    DQN baseline "fixed". Also the sensible stub for bringing the daemon up:
    it exercises the rotation path without needing a detector.
    """

    name = "fixed-interval"

    def __init__(self, interval_ticks: int = 300) -> None:
        self.interval = max(1, interval_ticks)
        self._ticks = 0

    def decide(self, obs: Observation) -> Action:
        self._ticks += 1
        if self._ticks % self.interval == 0:
            return Action.ROTATE_SESSION_KEY
        return Action.HOLD


class ThresholdPolicy:
    """Escalate above a score threshold, de-escalate below it, rotate on entry.

    DQN baseline "threshold" — the obvious hand-written rule, and the one the
    learned policy has to beat to be worth anything. Also uses the free local
    signals (GCM auth failures) that need no detector at all.
    """

    name = "threshold"

    def __init__(self, escalate: float = 0.7, deescalate: float = 0.3) -> None:
        self.escalate = escalate
        self.deescalate = deescalate
        self._last_posture = int(Posture.NORMAL)

    def decide(self, obs: Observation) -> Action:
        # A burst of authentication failures is unambiguous: normal operation
        # produces exactly zero. Worth acting on before any inference arrives.
        if obs.gcm_auth_fail_rate > 0.1 and obs.posture < int(Posture.ANOMALY):
            return Action.ESCALATE_POSTURE

        # A decayed lease means the server has gone quiet. PostureState
        # escalates on its own, but flushing early shortens the detection gap
        # if the link is merely slow rather than dead.
        if obs.lease_ms and obs.lease_remaining_ms == 0:
            return Action.FORCE_FLUSH

        if obs.lstm_score >= self.escalate and obs.posture < int(Posture.ANOMALY):
            entering = obs.posture == int(Posture.NORMAL)
            self._last_posture = obs.posture
            # Rotate on the way in: the key may have been exposed for as long
            # as the detector took to notice.
            return Action.ROTATE_SESSION_KEY if entering else Action.ESCALATE_POSTURE

        if obs.lstm_score <= self.deescalate and obs.posture > int(Posture.NORMAL):
            return Action.DEESCALATE_POSTURE

        return Action.HOLD


class NeverRotatePolicy:
    """DQN baseline "never". Exists to show what the exposure cost buys."""

    name = "never"

    def decide(self, obs: Observation) -> Action:
        return Action.HOLD


class AlwaysMaxPolicy:
    """DQN baseline "always-max": rotate constantly, stay at ANOMALY.

    Maximally safe and operationally useless — the upper bound on action cost.
    """

    name = "always-max"

    def decide(self, obs: Observation) -> Action:
        if obs.posture < int(Posture.ANOMALY):
            return Action.ESCALATE_POSTURE
        return Action.ROTATE_SESSION_KEY


# ── the shield ──────────────────────────────────────────────────────────────


@dataclass
class ShieldLimits:
    max_rotations_per_min: int = 6
    min_root_request_interval_ms: int = 300_000       # 5 min; costs ~91 ms each
    seq_exhaustion_threshold: float = 0.9             # force rotate at 90%
    key_max_age_ms: int = 24 * 3_600_000              # NIST-style crypto period


@dataclass
class ShieldDecision:
    action: Action
    forced: bool = False
    blocked: bool = False
    reason: str = ""


@dataclass
class Shield:
    """Wraps a policy. The only thing the daemon is allowed to act on."""

    limits: ShieldLimits = field(default_factory=ShieldLimits)
    _rotation_times: list[int] = field(default_factory=list)
    _last_root_request_ms: int = -10**12
    blocked_count: int = 0
    forced_count: int = 0

    def apply(self, proposed: Action, obs: Observation, now_ms: int) -> ShieldDecision:
        # ── forced actions come first: they override the policy entirely ──

        if obs.seq_used >= self.limits.seq_exhaustion_threshold * SEQ_MAX:
            # Not negotiable. Running out of sequence space and continuing
            # would mean nonce reuse.
            self.forced_count += 1
            self._record_rotation(now_ms)
            return ShieldDecision(
                Action.ROTATE_SESSION_KEY, forced=True, reason="nonce space exhausted"
            )

        if obs.key_age_ms >= self.limits.key_max_age_ms:
            self.forced_count += 1
            self._record_rotation(now_ms)
            return ShieldDecision(
                Action.ROTATE_SESSION_KEY, forced=True, reason="crypto period expired"
            )

        # ── rate limits: block, degrade to HOLD ──

        if proposed in (Action.ROTATE_SESSION_KEY, Action.REFRESH_POOL):
            if self._rotations_in_last_minute(now_ms) >= self.limits.max_rotations_per_min:
                self.blocked_count += 1
                return ShieldDecision(
                    Action.HOLD, blocked=True, reason="rotation rate limit"
                )
            self._record_rotation(now_ms)

        if proposed == Action.REQUEST_ROOT_KEY:
            since = now_ms - self._last_root_request_ms
            if since < self.limits.min_root_request_interval_ms:
                self.blocked_count += 1
                return ShieldDecision(
                    Action.HOLD, blocked=True, reason="root-key request rate limit"
                )
            self._last_root_request_ms = now_ms

        # Quarantine is destructive to data flow, so it needs the posture to
        # justify it. PostureState also refuses it without an authenticated
        # QUARANTINE directive; this is the policy-side half of that.
        if proposed == Action.QUARANTINE_WORST_CHANNEL:
            if obs.posture < int(Posture.ANOMALY):
                self.blocked_count += 1
                return ShieldDecision(
                    Action.HOLD, blocked=True, reason="quarantine requires ANOMALY"
                )

        return ShieldDecision(proposed)

    def _record_rotation(self, now_ms: int) -> None:
        self._rotation_times.append(now_ms)

    def _rotations_in_last_minute(self, now_ms: int) -> int:
        cutoff = now_ms - 60_000
        self._rotation_times = [t for t in self._rotation_times if t >= cutoff]
        return len(self._rotation_times)


__all__ = [
    "Action",
    "Observation",
    "Policy",
    "Shield",
    "ShieldDecision",
    "ShieldLimits",
    "FixedIntervalPolicy",
    "ThresholdPolicy",
    "NeverRotatePolicy",
    "AlwaysMaxPolicy",
]
