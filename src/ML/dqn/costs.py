"""
costs.py — what each action actually costs, in milliseconds.

Every number here is **measured on real hardware**, not assumed. That is a
genuine strength of this work: most RL-for-security papers invent a cost model,
so their policies optimise a fiction. These come from
`temp_codes/pqcrypto_project/pqcrypto_project/benchmark.py` and from
`src/hardware/ESP32/tests/test_node.c`.

Re-measure on the deployment hardware before quoting them in the paper — the
figures below are from an x86 development machine, and the RPi 4 will be
slower. The ratios matter more than the absolutes, and the ratios are what the
policy learns from.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionCosts:
    """Milliseconds of gateway time per action.

    Sources:
      ML-KEM-512 encaps         5.017 ms   benchmark.py
      ML-KEM-512 decaps         6.702 ms   benchmark.py
      ML-DSA-44 sign           55.952 ms   benchmark.py
      ML-DSA-44 verify         12.687 ms   benchmark.py
      end-to-end root transfer 91.262 ms   benchmark.py
      RXCR-KDF 2-key pool      17.13  ms   bench_gateway.py
      ACCM mask, 1 KB          23.57  ms   bench_gateway.py
    """

    hold: float = 0.0
    """Free in CPU terms — but exposure accrues, which is the entire point."""

    rotate_session_key: float = 17.13
    """One RXCR-KMAC-KDF pool derivation. Pure-Python Keccak dominates."""

    refresh_pool: float = 34.26
    """Two derivations for the prototype's two-key pool; scales with endpoints."""

    request_root_key: float = 91.26
    """Full ML-KEM + ML-DSA + AES-GCM transfer, measured end to end. The most
    expensive thing the system does, and the reason the shield rate-limits it."""

    escalate_posture: float = 0.0
    """Changing epsilon costs no crypto. It is close to free, which is exactly
    why an agent that only ever escalates would be useless — the cost of a
    false alarm is operational, not computational."""

    deescalate_posture: float = 0.0
    quarantine_channel: float = 0.0
    """No CPU cost. The real cost is losing a channel's data, priced in the
    reward as a false-positive penalty rather than as milliseconds."""

    force_flush: float = 23.57
    """An extra ACCM mask plus a frame out of band."""

    def for_action(self, action: int) -> float:
        return (
            self.hold,
            self.rotate_session_key,
            self.refresh_pool,
            self.request_root_key,
            self.escalate_posture,
            self.deescalate_posture,
            self.quarantine_channel,
            self.force_flush,
        )[int(action)]


@dataclass(frozen=True)
class RewardWeights:
    """Relative weights. Only the ratios matter; the scale is absorbed by the
    learning rate.

    `w_compromise / w_false_positive` is the one judgement call in the whole
    design: how much worse is an undetected intrusion than a false alarm? It is
    a utility question about the grid, not a technical one, and it should be
    stated explicitly in the paper rather than buried in a config file.
    Reported results should include a sensitivity sweep over it.
    """

    w_exposure: float = 1.0
    """Continuous, always accruing. THE load-bearing term: without it,
    anomalies are rare enough that the agent learns to never act, which is the
    single most common failure in RL-for-security work."""

    w_action: float = 0.02
    """Per millisecond. A root-key transfer therefore costs ~1.8 reward units,
    comparable to two steps of full exposure — roughly right."""

    w_compromise: float = 20.0
    """An attacker holding the current session key, right now. The agent cannot
    observe this; it only ever sees the detector's noisy opinion of it."""

    w_false_positive: float = 3.0
    """ANOMALY posture while nothing is wrong. Costs operator trust and, when
    it escalates to quarantine, real telemetry."""

    w_latency: float = 0.5
    """Breaching a node's timing budget."""

    w_blocked: float = 0.15
    """Proposing an action the shield refuses.

    Without this a refused request is free, and the first trained agent
    exploited exactly that: it proposed ROTATE 79% of the time and let the
    rate limiter ration it. It scored well, but it had not learned *when* to
    rotate -- it had learned to delegate that to the limiter, so the effective
    policy was the limiter rather than the agent.

    Charging for a refusal forces the decision back into the policy. Set below
    the cost of actually rotating (0.02 x 17.13 = 0.34): asking wrongly should
    hurt, but less than doing it.

    This is also true to deployment. A gateway whose policy constantly requests
    things it cannot have produces log noise, obscures real events, and tells
    an operator nothing about why a rotation happened."""


DEFAULT_COSTS = ActionCosts()
DEFAULT_WEIGHTS = RewardWeights()

__all__ = ["ActionCosts", "RewardWeights", "DEFAULT_COSTS", "DEFAULT_WEIGHTS"]
