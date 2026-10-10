"""
baselines.py — what the DQN has to beat.

Four of the five are the **production policies from `policy.py`**, not
reimplementations. That matters: if the baselines were separate code, a DQN
that beat them would only have beaten a strawman. These are the same objects
the gateway daemon can actually run today.

The fifth is the oracle, which cheats by reading the environment's hidden
state. It cannot be deployed — it exists to bound how much of the gap is due
to the detector's noise rather than to the policy. If the DQN approaches the
oracle, the remaining loss is irreducible given the detector; if it does not,
there is policy headroom left.

Reporting all five is what makes a result interpretable. "The DQN scored -412"
means nothing on its own.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_GW = _REPO / "src" / "hardware" / "Gateway" / "python"
if str(_GW) not in sys.path:
    sys.path.insert(0, str(_GW))

from policy import (  # noqa: E402
    Action,
    AlwaysMaxPolicy,
    FixedIntervalPolicy,
    NeverRotatePolicy,
    Observation,
    ThresholdPolicy,
)
from protocol import Posture  # noqa: E402


class OraclePolicy:
    """Reads the hidden compromise state. Not deployable.

    Rotates whenever an attacker actually holds the key, escalates while the
    intrusion is live, and otherwise does nothing. It still pays action costs
    and still obeys the shield.

    It is a **perfect-information reference, not an upper bound.** It is a
    heuristic that happens to see the truth, and it is not reward-optimal: it
    escalates whenever an attacker is present, including while that attacker
    does not hold the key, so it pays a large false-positive cost. A DQN that
    beats it has not acquired better information -- it has found a better
    tradeoff, which is a legitimate and interesting result.

    What the gap to the oracle actually measures is how much of the remaining
    loss is attributable to *detector uncertainty* versus to policy. Report it
    as that, not as "distance from optimal".
    """

    name = "oracle"

    def __init__(self, env) -> None:
        self.env = env

    def decide(self, obs: Observation) -> Action:
        if self.env.compromised:
            # Evict, every step it holds the key. Expensive and correct.
            return Action.ROTATE_SESSION_KEY
        if self.env.attacker_present and obs.posture < int(Posture.ANOMALY):
            return Action.ESCALATE_POSTURE
        if not self.env.attacker_present and obs.posture > int(Posture.NORMAL):
            return Action.DEESCALATE_POSTURE
        return Action.HOLD


def all_baselines(env=None) -> dict:
    """The five. `env` is needed only for the oracle."""
    out = {
        "never": NeverRotatePolicy(),
        "fixed-interval": FixedIntervalPolicy(interval_ticks=300),
        "threshold": ThresholdPolicy(escalate=0.7, deescalate=0.3),
        "always-max": AlwaysMaxPolicy(),
    }
    if env is not None:
        out["oracle"] = OraclePolicy(env)
    return out


def rollout(env, policy, episodes: int = 10, seed: int | None = None) -> dict:
    """Run a policy and collect the metrics the comparison table needs."""
    import numpy as np

    if seed is not None:
        env.rng = np.random.default_rng(seed)

    returns, compromised_steps, rotations = [], [], []
    blocked, forced, fp_steps = [], [], []

    for _ in range(episodes):
        obs = env.reset()
        total = 0.0
        comp = rot = blk = frc = fp = 0
        done = False

        while not done:
            action = policy.decide(env.current_observation())
            obs, reward, done, info = env.step(int(action))
            total += reward
            comp += int(info.compromised)
            rot += int(info.action_taken in (1, 2, 3))
            blk += int(info.blocked)
            frc += int(info.forced)
            fp += int(not info.compromised and info.posture == 2)

        returns.append(total)
        compromised_steps.append(comp)
        rotations.append(rot)
        blocked.append(blk)
        forced.append(frc)
        fp_steps.append(fp)

    return {
        "policy": getattr(policy, "name", type(policy).__name__),
        "mean_return": float(np.mean(returns)),
        "std_return": float(np.std(returns)),
        "compromised_steps": float(np.mean(compromised_steps)),
        "rotations": float(np.mean(rotations)),
        "blocked_actions": float(np.mean(blocked)),
        "forced_actions": float(np.mean(forced)),
        "false_positive_steps": float(np.mean(fp_steps)),
    }


__all__ = ["OraclePolicy", "all_baselines", "rollout"]
