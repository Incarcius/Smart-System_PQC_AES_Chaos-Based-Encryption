"""
lease.py — deciding what to tell the gateway, and renewing its lease.

Every telemetry batch gets a response, and that response **is** the lease
renewal. The cadence follows the aggregation window with no extra timer and no
second connection, and a server that stops *responding* decays the lease
exactly like one that stops *renewing*.

The directive ladder
--------------------
The server detects; the gateway's policy decides. This ladder keeps the agent
in charge of the ordinary cost/benefit tradeoff while leaving a hard override
for a live intrusion:

  ADVISE      an observation. Feeds the agent's state; it chooses the response.
  ENFORCE     a floor. The agent may escalate above it, never below.
  QUARANTINE  mandatory, carries the node_mask, bypasses policy entirely.

Hysteresis is not optional
--------------------------
A single threshold on a noisy score produces a system that flaps between
postures, and flapping is worse than either state: it burns key rotations and
teaches an operator to ignore the alerts. So escalation and de-escalation use
different thresholds, and `min_hold_ms` (enforced gateway-side in
`PostureState.request`) stops the agent dropping back too quickly.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_ACCM = _REPO / "src" / "security" / "ACCM" / "python"
if str(_ACCM) not in sys.path:
    sys.path.insert(0, str(_ACCM))

from protocol import Control, Directive, Posture  # noqa: E402


@dataclass
class LeasePolicy:
    """Thresholds and timings for the control plane."""

    lease_ms: int = 3000
    """Validity granted per renewal. Three renewal periods, so two lost
    responses are tolerated before the gateway escalates on its own."""

    renew_period_ms: int = 1000
    """Matches the aggregation window; the response carries the renewal."""

    # -- score thresholds ---------------------------------------------------
    #
    # Re-derived at M5 against the real detector, and the originals were badly
    # wrong in a way nothing caught until the whole loop ran.
    #
    # They were chosen for a score that reads near zero when nothing is wrong.
    # The detector is ECDF calibrated, so by construction its score on normal
    # data is UNIFORM on [0, 1]: "0.99 means worse than 99% of normal windows"
    # is exactly the statement that 1% of normal windows exceed 0.99. Measured
    # on held-out MSU/ORNL normal: mean 0.503, Beta(0.96, 0.95).
    #
    # Under a uniform score, a threshold IS its false-alarm rate: `1 - t`. So
    # the old values meant
    #
    #     escalate_suspicious 0.45  ->  55% of normal windows
    #     escalate_anomaly    0.75  ->  25% of normal windows
    #     quarantine_score    0.90  ->  10% of normal windows
    #
    # A 10% chance per window of quarantining a healthy channel is not a
    # tuning imperfection, it makes quarantine unusable: in the M5 run a
    # just-released channel was re-quarantined within a minute of clean data.
    #
    # Chosen for the false-alarm rate each action deserves, given one window
    # per second:
    THRESHOLD_NOTE = "under a uniform-on-normal score, false-alarm rate = 1 - t"

    escalate_suspicious: float = 0.95
    """5% of normal windows: about one nudge every 20 s. Cheap and reversible,
    so a loose threshold is affordable here."""

    escalate_anomaly: float = 0.99
    """1% of normal windows, roughly once every 100 s."""

    deescalate: float = 0.80
    """Separate up and down thresholds; the gap is the hysteresis band. Below
    the 0.95 escalation point but still high, because under a uniform score
    'quiet' is around 0.5 rather than near zero."""

    min_hold_ms: int = 5000
    """How long the gateway must stay at a posture before dropping back."""

    quarantine_score: float = 0.999
    """0.1% of normal windows, about one false quarantine every 17 minutes.
    Quarantine isolates a channel and needs far more evidence than escalation,
    and the attack distribution is pinned near 1.0 (measured mean 0.992), so
    almost nothing real is lost by demanding this much."""


class LeaseIssuer:
    """Turns a detector score into the control message that answers a batch."""

    def __init__(self, policy: LeasePolicy | None = None) -> None:
        self.policy = policy or LeasePolicy()
        self._quarantined_mask = 0

    def decide(
        self,
        score: float,
        attribution_mask: int,
        session,
        now_ms: int | None = None,
    ) -> Control:
        """Build the control message for one batch.

        Always returns something: the lease must be renewed on every response,
        whatever the posture. A response that merely says "carry on" is still
        load-bearing — it is the proof that the server is alive.
        """
        p = self.policy
        now = now_ms if now_ms is not None else int(time.time() * 1000)

        posture = Posture.NORMAL
        directive = Directive.ADVISE
        node_mask = self._quarantined_mask

        if score >= p.quarantine_score and attribution_mask:
            # Enough evidence to stop trusting specific channels. Accumulate
            # rather than replace: two overlapping detections must not clear
            # each other's channels.
            self._quarantined_mask |= attribution_mask
            node_mask = self._quarantined_mask
            posture = Posture.ANOMALY
            directive = Directive.QUARANTINE

        elif score >= p.escalate_anomaly:
            posture = Posture.ANOMALY
            directive = Directive.ENFORCE

        elif score >= p.escalate_suspicious:
            posture = Posture.SUSPICIOUS
            directive = Directive.ENFORCE

        elif score <= p.deescalate:
            # Below the lower threshold: release the floor and let the agent
            # decide when to actually come down. ADVISE, not ENFORCE NORMAL —
            # forcing NORMAL would override an agent that has local evidence
            # (GCM auth failures, say) the server cannot see.
            posture = Posture.NORMAL
            directive = Directive.ADVISE

        else:
            # Inside the hysteresis band. Say nothing about posture; just renew.
            posture = Posture.NORMAL
            directive = Directive.ADVISE

        return Control(
            ctrl_seq=session.next_ctrl_seq(),
            issued_ms=now,
            lease_ms=p.lease_ms,
            min_hold_ms=p.min_hold_ms,
            node_mask=node_mask,
            posture=posture,
            directive=directive,
        )

    def release(self, channel_id: int) -> None:
        """Clear a quarantine after triage has cleared the channel."""
        self._quarantined_mask &= ~(1 << channel_id)

    @property
    def quarantined_mask(self) -> int:
        return self._quarantined_mask


__all__ = ["LeaseIssuer", "LeasePolicy"]
