"""
env.py — the key-lifecycle environment the DQN trains in.

**It imports the REAL `PostureState`, `NonceGuard` and `Shield`**, the same
objects the gateway daemon runs. Not reimplementations. If the environment
modelled the system instead of using it, the policy would learn against a
fiction and every safety property proved in simulation would be worthless in
deployment.

The hidden state
----------------
`compromised` means *an attacker currently holds the session key*. The agent
never observes it. It sees the detector's delayed, noisy opinion, plus the
gateway's own local signals. That is what makes this a POMDP rather than a
lookup table, and it is the whole reason the problem is interesting.

Why rotation is the lever
-------------------------
An attacker who is inside the network re-acquires the key some time after each
rotation. So rotating **evicts** them, but only until they get back in. The
agent cannot solve the problem once; it has to keep paying. That is what
creates a real cost/benefit tradeoff instead of a one-shot decision, and it is
why "rotate on alarm" is not automatically the right policy.

Episode shape
-------------
One step = one aggregation window = 1 s, matching the gateway's tick and the
piggybacked lease cadence. Default 1800 steps (30 minutes), with zero or more
attack windows per episode.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

_REPO = Path(__file__).resolve().parents[3]
for _p in (
    _REPO / "src" / "hardware" / "Gateway" / "python",
    _REPO / "src" / "security" / "ACCM" / "python",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# The real thing, deliberately.
from policy import Action, Observation, Shield, ShieldLimits  # noqa: E402
from protocol import (  # noqa: E402
    Control,
    Directive,
    NonceGuard,
    Posture,
    PostureState,
    SEQ_MAX,
)

from costs import DEFAULT_COSTS, DEFAULT_WEIGHTS, ActionCosts, RewardWeights  # noqa: E402
from surrogate_detector import SurrogateDetector, SurrogateParams  # noqa: E402
from telemetry import SyntheticTraffic  # noqa: E402

N_ACTIONS = len(Action)
OBS_DIM = 20          # len(Observation.to_vector())
STACK = 4             # frame stacking; see DQN_SPEC §3
STATE_DIM = OBS_DIM * STACK


@dataclass
class EnvConfig:
    episode_steps: int = 1800
    n_channels: int = 5
    tick_ms: int = 1000

    attack_prob_per_episode: float = 0.6
    """Fraction of episodes containing an intrusion. Not 1.0: a policy that has
    only ever seen attacks learns to treat alarm as the default state."""

    attack_min_len: int = 60
    attack_max_len: int = 600

    reacquire_steps_mean: float = 30.0
    """How long an attacker inside the network takes to regain the key after a
    rotation. Small enough that one rotation is not a fix."""

    lease_ms: int = 3000
    min_hold_ms: int = 5000
    crypto_period_ms: int = 24 * 3_600_000

    seq_scale: int = 700_000
    """Sequence numbers consumed per step, scaled so nonce exhaustion is
    reachable inside an episode. Real exhaustion takes ~3.4 years at 10 Hz;
    without scaling the agent would never see that part of the state space and
    the shield's forced rotation would never be exercised. At 700k/step the
    0.9 x SEQ_MAX threshold arrives after ~1380 steps of not rotating, which
    is inside the default 1800-step episode."""

    ctrl_outage_prob: float = 0.3
    """Probability that an attack also disrupts the control channel. This is
    the Ukraine phase-5 scenario -- blind the operators while you act -- and it
    is what forces the agent to reason about a detector that has gone quiet
    rather than one that is merely saying 'nothing wrong'."""


@dataclass
class StepInfo:
    compromised: bool = False
    attacker_present: bool = False
    action_taken: int = 0
    action_proposed: int = 0
    blocked: bool = False
    forced: bool = False
    posture: int = 0
    detector_score: float = 0.0
    reward_terms: dict = field(default_factory=dict)


class KeyLifecycleEnv:
    """Gym-style, without the gymnasium dependency.

    `reset() -> obs` and `step(action) -> (obs, reward, done, info)`.
    """

    def __init__(
        self,
        config: EnvConfig | None = None,
        detector_params: SurrogateParams | None = None,
        costs: ActionCosts | None = None,
        weights: RewardWeights | None = None,
        seed: int | None = None,
    ) -> None:
        self.cfg = config or EnvConfig()
        self.costs = costs or DEFAULT_COSTS
        self.weights = weights or DEFAULT_WEIGHTS
        self.detector_params = detector_params or SurrogateParams()
        self.rng = np.random.default_rng(seed)

        self.detector = SurrogateDetector(self.detector_params, self.rng)
        self.traffic = SyntheticTraffic(self.cfg.n_channels, self.rng)

        self.reset()

    # ── episode lifecycle ────────────────────────────────────────────────

    def reset(self) -> np.ndarray:
        cfg = self.cfg
        self.t = 0
        self.now_ms = 0

        # Real gateway objects.
        self.posture = PostureState(self.now_ms)
        self.posture.grace(cfg.lease_ms, self.now_ms)
        self.nonce_guard = NonceGuard(key_epoch=1)
        self.shield = Shield(
            ShieldLimits(
                seq_exhaustion_threshold=0.9,
                key_max_age_ms=cfg.crypto_period_ms,
            )
        )

        self.detector.reset()
        self.traffic.reset()

        # Hidden state.
        self.attacker_present = False
        self.compromised = False
        self._reacquire_at = None
        self._attack_window = (0, 0)
        self._outage_window = (0, 0)
        self._ctrl_seq = 1

        if self.rng.random() < cfg.attack_prob_per_episode:
            length = int(self.rng.integers(cfg.attack_min_len, cfg.attack_max_len))
            length = min(length, cfg.episode_steps)
            start = int(self.rng.integers(0, max(1, cfg.episode_steps - length)))
            self._attack_window = (start, start + length)

            # Some intrusions also take out the control channel.
            if self.rng.random() < cfg.ctrl_outage_prob:
                o_len = int(self.rng.integers(10, max(11, length)))
                o_start = int(self.rng.integers(start, max(start + 1, start + length - o_len)))
                self._outage_window = (o_start, o_start + o_len)

        # Observable bookkeeping.
        self.key_installed_ms = 0
        self.bytes_under_key = 0
        self.last_root_ms = 0
        self.rotations_window = 0
        self.ewma_fast = 0.0
        self.ewma_slow = 0.0
        self._seq_used = 0

        self._stack = [np.zeros(OBS_DIM, dtype=np.float32) for _ in range(STACK)]
        self._last_score = 0.0
        self._last_traffic = self.traffic.sample(False, 0)
        obs = self._build_obs(0.0, self._last_traffic)
        self._push(obs)
        return self._stacked()

    # ── the step ─────────────────────────────────────────────────────────

    def step(self, action: int):
        cfg = self.cfg
        info = StepInfo(action_proposed=int(action))

        # 1. Time advances, and the server renews the lease -- unless the
        #    control channel is out.
        #
        #    Modelling the renewal is not optional. Without it the lease always
        #    lapses, PostureState escalates every episode to ANOMALY and stays
        #    there, and the false-positive term swamps the reward: the agent
        #    would learn from a world where it is permanently in alarm and
        #    nothing it does about posture matters.
        #
        #    The simulated server renews (ADVISE) but never commands a posture.
        #    That leaves posture entirely to the agent, which is the harder
        #    problem and the one worth measuring. A deployment that also sends
        #    ENFORCE only adds a floor the shield already respects.
        self.now_ms += cfg.tick_ms

        if self._ctrl_up():
            self.posture.apply(
                Control(
                    ctrl_seq=self._ctrl_seq,
                    issued_ms=self.now_ms,
                    lease_ms=cfg.lease_ms,
                    min_hold_ms=cfg.min_hold_ms,
                    posture=Posture.NORMAL,
                    directive=Directive.ADVISE,
                ),
                self.now_ms,
                3_600_000,
            )
            self._ctrl_seq += 1

        self.posture.tick(self.now_ms)

        # 2. Attacker dynamics, before the action, so the action responds to
        #    the state that actually exists this step.
        self._advance_attacker()

        # 3. The shield. Built from the CURRENT observation, so forced
        #    rotations trigger on the state the agent was looking at.
        traffic = self.traffic.sample(self.compromised, self.posture.node_mask)
        self._last_traffic = traffic
        obs_obj = self._observation(self._last_score, traffic)
        decision = self.shield.apply(Action(int(action)), obs_obj, self.now_ms)

        info.action_taken = int(decision.action)
        info.blocked = decision.blocked
        info.forced = decision.forced

        # 4. Apply.
        self._apply_action(decision.action, traffic)

        # 5. Consume sequence numbers for the traffic actually sent.
        self._seq_used = min(SEQ_MAX, self._seq_used + cfg.seq_scale)
        self.bytes_under_key += traffic.bytes_this_window

        # 6. Detector. FORCE_FLUSH buys a zero-delay reading at bandwidth cost.
        if decision.action == Action.FORCE_FLUSH:
            score = self.detector.peek_now(self.compromised)
            self.detector.observe(self.compromised)
        else:
            score = self.detector.observe(self.compromised)

        self._last_score = score
        self.ewma_fast = 0.3 * score + 0.7 * self.ewma_fast
        self.ewma_slow = 0.05 * score + 0.95 * self.ewma_slow

        # 7. Reward, from the hidden state the agent cannot see.
        reward, terms = self._reward(decision.action, traffic, decision.blocked)

        info.compromised = self.compromised
        info.attacker_present = self.attacker_present
        info.posture = int(self.posture.posture)
        info.detector_score = score
        info.reward_terms = terms

        self.t += 1
        done = self.t >= cfg.episode_steps

        self._push(self._build_obs(score, traffic))
        return self._stacked(), reward, done, info

    # ── hidden dynamics ──────────────────────────────────────────────────

    def _advance_attacker(self) -> None:
        start, end = self._attack_window
        self.attacker_present = start <= self.t < end

        if not self.attacker_present:
            # The intrusion is over. Holding the key is meaningless once the
            # attacker is out of the network.
            self.compromised = False
            self._reacquire_at = None
            return

        if self.compromised:
            return

        if self._reacquire_at is None:
            # Just entered, or just evicted: schedule the next acquisition.
            delay = max(1, int(self.rng.exponential(self.cfg.reacquire_steps_mean)))
            self._reacquire_at = self.t + delay

        if self.t >= self._reacquire_at:
            self.compromised = True
            self._reacquire_at = None

    def _ctrl_up(self) -> bool:
        """Is the server reachable this step?"""
        lo, hi = self._outage_window
        return not (lo <= self.t < hi)

    def _evict(self) -> None:
        """A rotation invalidates whatever key the attacker holds."""
        if self.compromised:
            self.compromised = False
            self._reacquire_at = None

    # ── actions ──────────────────────────────────────────────────────────

    def _apply_action(self, action: Action, traffic) -> None:
        if action in (Action.ROTATE_SESSION_KEY, Action.REFRESH_POOL,
                      Action.REQUEST_ROOT_KEY):
            self._evict()
            self.key_installed_ms = self.now_ms
            self.bytes_under_key = 0
            self._seq_used = 0
            self.rotations_window += 1
            if action == Action.REQUEST_ROOT_KEY:
                self.last_root_ms = self.now_ms

        elif action == Action.ESCALATE_POSTURE:
            self.posture.request(
                Posture(min(int(self.posture.posture) + 1, int(Posture.ANOMALY))),
                self.now_ms,
            )

        elif action == Action.DEESCALATE_POSTURE:
            self.posture.request(
                Posture(max(int(self.posture.posture) - 1, int(Posture.NORMAL))),
                self.now_ms,
            )

        elif action == Action.QUARANTINE_WORST_CHANNEL:
            # Isolating the channel the attacker is using evicts them from it.
            # Costly: that channel's data stops being trusted.
            free = [c for c in range(self.cfg.n_channels)
                    if not self.posture.is_quarantined(c)]
            if free:
                self.posture.node_mask |= 1 << free[0]
                if self.compromised and self.rng.random() < 0.5:
                    self._evict()

    # ── reward ───────────────────────────────────────────────────────────

    def _reward(self, action: Action, traffic, blocked: bool = False) -> tuple[float, dict]:
        w = self.weights
        cfg = self.cfg

        key_age_norm = min(1.0, (self.now_ms - self.key_installed_ms) / 3_600_000)
        bytes_norm = min(1.0, self.bytes_under_key / 1e7)
        posture_mult = {0: 1.0, 1: 2.0, 2: 4.0}[int(self.posture.posture)]

        # Always accruing. Without this the agent learns to never act.
        exposure = (key_age_norm + bytes_norm) * posture_mult

        action_cost = self.costs.for_action(int(action))

        # The hidden state. The agent reduces this by rotating, which evicts.
        compromise = 1.0 if self.compromised else 0.0

        # Over-reacting when nothing is wrong: lost operator trust, and lost
        # data once it reaches quarantine.
        false_positive = 0.0
        if not self.compromised:
            if int(self.posture.posture) == int(Posture.ANOMALY):
                false_positive += 1.0
            false_positive += 0.5 * bin(self.posture.node_mask).count("1")

        latency = max(0.0, traffic.worst_budget_util - 0.8)

        terms = {
            "exposure": -w.w_exposure * exposure,
            "action": -w.w_action * action_cost,
            "compromise": -w.w_compromise * compromise,
            "false_positive": -w.w_false_positive * false_positive,
            "latency": -w.w_latency * latency,
            # Asking for something the shield refuses is not free: see the
            # w_blocked docstring for why the first agent exploited that.
            "blocked": -w.w_blocked * (1.0 if blocked else 0.0),
        }
        return float(sum(terms.values())), terms

    # ── observation ──────────────────────────────────────────────────────

    def _observation(self, score: float, traffic) -> Observation:
        p = self.posture
        return Observation(
            lstm_score=score,
            lstm_ewma_fast=self.ewma_fast,
            lstm_ewma_slow=self.ewma_slow,
            posture=int(p.posture),
            time_in_posture_ms=self.now_ms - p.posture_since_ms,
            lease_remaining_ms=max(0, p.lease_expires_ms - self.now_ms),
            lease_ms=max(1, p.lease_ms),
            time_since_ctrl_ms=self.now_ms - p.posture_since_ms,
            directive_floor=int(p.directive_floor),
            quarantined_channels=bin(p.node_mask).count("1"),
            ctrl_reject_rate=0.0,
            seq_used=self._seq_used,
            key_age_ms=self.now_ms - self.key_installed_ms,
            bytes_under_key=self.bytes_under_key,
            time_since_root_ms=self.now_ms - self.last_root_ms,
            rotations_in_window=self.rotations_window,
            gcm_auth_fail_rate=traffic.gcm_auth_fail_rate,
            replay_reject_rate=traffic.replay_reject_rate,
            silent_channels=traffic.silent_channels,
            queue_depth=traffic.queue_depth,
            n_channels=self.cfg.n_channels,
        )

    def current_observation(self) -> Observation:
        """The Observation for the current state, without advancing anything.

        `rollout` used to build the policy's view by calling traffic.sample()
        itself, which advanced the generator and handed the policy a DIFFERENT
        window from the one step() then used. The policy was deciding about a
        world that never happened.
        """
        return self._observation(self._last_score, self._last_traffic)

    def _build_obs(self, score: float, traffic) -> np.ndarray:
        return np.asarray(
            self._observation(score, traffic).to_vector(), dtype=np.float32
        )

    def _push(self, obs: np.ndarray) -> None:
        self._stack.pop(0)
        self._stack.append(obs)

    def _stacked(self) -> np.ndarray:
        return np.concatenate(self._stack)

    _last_score: float = 0.0


__all__ = ["KeyLifecycleEnv", "EnvConfig", "StepInfo", "N_ACTIONS", "STATE_DIM", "OBS_DIM"]
