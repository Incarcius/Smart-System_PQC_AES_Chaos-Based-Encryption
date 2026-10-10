"""
telemetry.py — the traffic conditions the agent operates under.

The DQN's state vector does not contain raw sensor values — it contains
*derived* traffic features: how many channels went silent, how far the message
rate has drifted, how full the queue is, how close nodes are to their timing
budgets. Those are what a key-lifecycle policy actually reacts to.

So this module produces those features, not voltages. Two sources:

  `SyntheticTraffic`  — closed-form, deterministic given a seed. Used for
                        training, because it is fast and reproducible.
  `TraceTraffic`      — replays a recorded trace. The MSU/ORNL loader lands
                        here once the dataset is in place; the interface is
                        already fixed so nothing downstream changes.

Attacks affect traffic, and that matters
----------------------------------------
A real intrusion perturbs the traffic shape as well as the readings: injected
commands raise the message rate, a compromised node may go silent, relay
manipulation changes the timing profile. Feeding that through means the agent
can in principle learn to notice an attack from traffic alone — the same free
local evidence the gateway already gets from GCM auth failures. Whether it
*does* learn that is an empirical question, and one worth reporting.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


@dataclass
class TrafficFeatures:
    """What one aggregation window looked like, from the gateway's side."""

    silent_channels: int = 0
    rate_deviation: float = 0.0
    queue_depth: int = 0
    worst_budget_util: float = 0.3
    mean_budget_util: float = 0.2
    bytes_this_window: int = 1024
    gcm_auth_fail_rate: float = 0.0
    replay_reject_rate: float = 0.0


class SyntheticTraffic:
    """Closed-form traffic model. Deterministic given a seed."""

    def __init__(self, n_channels: int = 5, rng=None) -> None:
        self.n_channels = n_channels
        self.rng = rng if rng is not None else np.random.default_rng()
        self.step = 0

    def reset(self) -> None:
        self.step = 0

    def sample(self, compromised: bool, quarantined: int = 0) -> TrafficFeatures:
        """One window. `compromised` perturbs the traffic, as a real one would."""
        self.step += 1
        t = self.step

        # Baseline: a slow diurnal drift plus noise, so "normal" is not constant.
        base_rate = 1.0 + 0.05 * math.sin(t / 300.0)
        rate = base_rate + self.rng.normal(0, 0.02)

        silent = 0
        auth_fail = 0.0
        replay = 0.0
        queue = int(max(0, self.rng.normal(20, 5)))

        if compromised:
            # An attacker with the session key can forge frames, but a forged
            # frame that gets the nonce or the AAD wrong fails the GCM tag. So
            # a low but non-zero auth-failure rate is the signature, and it is
            # free evidence the agent can act on without the detector.
            auth_fail = float(abs(self.rng.normal(0.04, 0.02)))
            replay = float(abs(self.rng.normal(0.01, 0.01)))
            rate += abs(self.rng.normal(0.15, 0.08))     # injected traffic
            queue += int(abs(self.rng.normal(30, 15)))
            if self.rng.random() < 0.15:
                silent += 1                               # a node knocked over

        # Quarantined channels stop contributing to the trusted aggregate, so
        # they look like reduced load rather than like silence.
        active = max(1, self.n_channels - bin(quarantined).count("1"))

        budget = 0.25 + 0.4 * (rate - 1.0) + abs(self.rng.normal(0, 0.05))
        budget = float(min(1.5, max(0.0, budget)))

        return TrafficFeatures(
            silent_channels=silent,
            rate_deviation=float(abs(rate - base_rate) / base_rate),
            queue_depth=queue,
            worst_budget_util=budget,
            mean_budget_util=budget * 0.7,
            bytes_this_window=int(200 * active * rate),
            gcm_auth_fail_rate=auth_fail,
            replay_reject_rate=replay,
        )


class TraceTraffic:
    """Replays recorded traffic features.

    Placeholder for the MSU/ORNL loader. The interface is fixed now so that
    swapping the source changes nothing in `env.py` — the same discipline used
    for the sensor HAL and the detector surrogate.

    To implement: resample the dataset to the 1 s grid, derive the fields of
    `TrafficFeatures` per window, and label each window with its scenario so
    the 8 natural disturbances can be separated from the 28 attacks.
    """

    def __init__(self, windows: list[TrafficFeatures]) -> None:
        if not windows:
            raise ValueError("TraceTraffic needs at least one window")
        self.windows = windows
        self.idx = 0

    def reset(self) -> None:
        self.idx = 0

    def sample(self, compromised: bool, quarantined: int = 0) -> TrafficFeatures:
        w = self.windows[self.idx % len(self.windows)]
        self.idx += 1
        return w


__all__ = ["TrafficFeatures", "SyntheticTraffic", "TraceTraffic"]
