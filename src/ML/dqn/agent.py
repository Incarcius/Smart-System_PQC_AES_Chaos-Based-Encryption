"""
agent.py — Double DQN with a duelling head, and a NumPy-only deployment path.

Why these two variants and not something fancier
------------------------------------------------
**Double DQN** decouples action selection from action evaluation. Vanilla DQN
takes a max over the target network's Q-values, which systematically
over-estimates — and here the over-estimated action would be "rotate", because
rotation has a visible immediate benefit (eviction) and a diffuse cost. An
agent that over-values rotation looks fine in training and thrashes the gateway
in deployment.

**Duelling** splits Q into a state value and an action advantage. Most states
in this problem are ones where the action barely matters (nothing is wrong,
everything is fine), and duelling learns the value of those states without
having to learn eight nearly-identical Q-values for each. That is exactly the
structure of a system that is idle most of the time and occasionally not.

Nothing here is novel, deliberately. The contribution is the problem
formulation and the safety envelope, not the RL algorithm — and using standard,
well-understood components is what makes the results legible to a reviewer.

Deployment
----------
Training uses PyTorch. Inference exports to a `.npz` and runs through
`NumpyPolicy`, which needs only NumPy — so the Raspberry Pi gateway never
installs PyTorch. The forward pass of a three-layer MLP is a handful of matrix
multiplies; `test_agent.py` checks the two paths agree to within float error.
"""

from __future__ import annotations

import random
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from env import N_ACTIONS, OBS_DIM, STACK, STATE_DIM  # noqa: E402
from policy import Action, Observation  # noqa: E402


@dataclass
class AgentConfig:
    hidden: int = 128
    lr: float = 1e-4
    gamma: float = 0.99
    """Episodes are 600-1800 steps and the consequences of a rotation play out
    over tens of steps, so the horizon needs to be long. 0.99 gives an
    effective horizon around 100 steps."""

    batch_size: int = 64
    buffer_size: int = 400_000
    """Must hold a large fraction of the run. At 100k against 720k steps it
    retained only the last ~14% of experience, which with a floored epsilon
    is a narrow, almost entirely on-policy distribution."""
    target_sync: int = 1000
    """Steps between target-network updates. Too frequent and Double DQN loses
    its decorrelation; too rare and learning stalls."""

    eps_start: float = 1.0
    eps_end: float = 0.05
    eps_decay_steps: int = 250_000
    """Exploration must not end too early: attacks are the rare part of the
    state space, and an agent that stops exploring before it has seen enough of
    them converges to 'never act'."""

    learn_every: int = 4
    warmup: int = 2000
    grad_clip: float = 10.0

    n_step: int = 5
    """Multi-step returns.

    This problem has badly delayed, diffuse credit. Rotating a key evicts the
    attacker, but the PAYOFF is the absence of a compromise penalty over the
    following tens of steps -- there is no immediate positive signal at all,
    only a cost now and a cost avoided later. One-step TD has to propagate that
    backwards one step per update, which is why the first runs needed so many
    episodes to stop over-rotating.

    Five-step returns carry the consequence back five times faster. The
    tradeoff is more variance per sample, which is acceptable here because the
    environment is cheap and the buffer is large."""


class DuelingQNet(nn.Module):
    def __init__(self, state_dim: int, n_actions: int, hidden: int = 128):
        super().__init__()
        self.trunk = nn.Sequential(
            nn.Linear(state_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, hidden),
            nn.ReLU(),
        )
        self.value = nn.Linear(hidden, 1)
        self.advantage = nn.Linear(hidden, n_actions)

    def forward(self, x):
        h = self.trunk(x)
        v = self.value(h)
        a = self.advantage(h)
        # Subtracting the mean advantage fixes the identifiability problem:
        # without it, V and A can drift by an arbitrary constant and the
        # decomposition means nothing.
        return v + a - a.mean(dim=1, keepdim=True)


class ReplayBuffer:
    """Uniform replay. Prioritised replay is a possible refinement, but it
    interacts with the reward's heavy tail (a compromise step is ~20x a normal
    one) in ways that need their own investigation — not worth the confound."""

    def __init__(self, capacity: int, state_dim: int):
        self.capacity = capacity
        self.states = np.zeros((capacity, state_dim), dtype=np.float32)
        self.actions = np.zeros(capacity, dtype=np.int64)
        self.rewards = np.zeros(capacity, dtype=np.float32)
        self.next_states = np.zeros((capacity, state_dim), dtype=np.float32)
        self.dones = np.zeros(capacity, dtype=np.float32)
        # How many environment steps each stored return spans. Needed because
        # the bootstrap term is gamma**n, and n is shorter than n_step for the
        # transitions flushed at an episode boundary.
        self.nsteps = np.ones(capacity, dtype=np.float32)
        self.idx = 0
        self.full = False

    def add(self, s, a, r, s2, done, n: int = 1) -> None:
        i = self.idx
        self.states[i] = s
        self.actions[i] = a
        self.rewards[i] = r
        self.next_states[i] = s2
        self.dones[i] = float(done)
        self.nsteps[i] = float(n)
        self.idx = (i + 1) % self.capacity
        if self.idx == 0:
            self.full = True

    def __len__(self) -> int:
        return self.capacity if self.full else self.idx

    def sample(self, batch: int):
        n = len(self)
        idx = np.random.randint(0, n, size=batch)
        return (
            torch.from_numpy(self.states[idx]),
            torch.from_numpy(self.actions[idx]),
            torch.from_numpy(self.rewards[idx]),
            torch.from_numpy(self.next_states[idx]),
            torch.from_numpy(self.dones[idx]),
            torch.from_numpy(self.nsteps[idx]),
        )


class NStepAccumulator:
    """Turns single-step experience into n-step transitions.

    Holds the last n steps; once full, emits a transition whose reward is the
    discounted sum over that window and whose next_state is the state n steps
    on. At an episode boundary it flushes everything still held, with the
    correct (shorter) n recorded for each.
    """

    def __init__(self, n: int, gamma: float):
        self.n = n
        self.gamma = gamma
        self.window: deque = deque(maxlen=n)

    def push(self, s, a, r, s2, done) -> list:
        self.window.append((s, a, r, s2, done))
        out = []

        if len(self.window) == self.n:
            out.append(self._emit(len(self.window)))
            self.window.popleft()

        if done:
            # Flush the tail. These span fewer than n steps, which is why the
            # buffer stores n per transition rather than assuming it.
            while self.window:
                out.append(self._emit(len(self.window)))
                self.window.popleft()

        return out

    def _emit(self, n: int):
        R = 0.0
        for i, (_, _, r, _, _) in enumerate(self.window):
            R += (self.gamma ** i) * r
        s0, a0 = self.window[0][0], self.window[0][1]
        sn, dn = self.window[-1][3], self.window[-1][4]
        return (s0, a0, R, sn, dn, n)

    def reset(self) -> None:
        self.window.clear()


class DQNAgent:
    """Double DQN + duelling. Implements the `Policy` protocol for deployment."""

    name = "dqn"

    def __init__(self, config: AgentConfig | None = None, device: str = "cpu"):
        self.cfg = config or AgentConfig()
        self.device = torch.device(device)

        self.online = DuelingQNet(STATE_DIM, N_ACTIONS, self.cfg.hidden).to(self.device)
        self.target = DuelingQNet(STATE_DIM, N_ACTIONS, self.cfg.hidden).to(self.device)
        self.target.load_state_dict(self.online.state_dict())
        self.target.eval()

        self.opt = torch.optim.Adam(self.online.parameters(), lr=self.cfg.lr)
        self.buffer = ReplayBuffer(self.cfg.buffer_size, STATE_DIM)
        self.nstep = NStepAccumulator(self.cfg.n_step, self.cfg.gamma)

        self.steps = 0
        self.updates = 0
        self.last_loss = 0.0

        # For the Policy protocol: the agent keeps its own frame stack when it
        # is driven by Observations rather than by the env's stacked state.
        self._stack = deque([np.zeros(OBS_DIM, dtype=np.float32)] * STACK, maxlen=STACK)
        self.greedy = False

    # ── acting ───────────────────────────────────────────────────────────

    @property
    def epsilon(self) -> float:
        c = self.cfg
        frac = min(1.0, self.steps / c.eps_decay_steps)
        return c.eps_start + frac * (c.eps_end - c.eps_start)

    def act(self, state: np.ndarray, greedy: bool = False) -> int:
        """Choose an action from the env's stacked state (training path)."""
        if not greedy and random.random() < self.epsilon:
            return random.randrange(N_ACTIONS)
        with torch.no_grad():
            q = self.online(torch.from_numpy(state).float().unsqueeze(0).to(self.device))
            return int(q.argmax(dim=1).item())

    def decide(self, obs: Observation) -> Action:
        """`Policy` protocol: take an Observation, maintain the stack, act
        greedily. This is what the gateway daemon calls."""
        self._stack.append(np.asarray(obs.to_vector(), dtype=np.float32))
        state = np.concatenate(self._stack)
        return Action(self.act(state, greedy=True))

    def reset_stack(self) -> None:
        self._stack = deque([np.zeros(OBS_DIM, dtype=np.float32)] * STACK, maxlen=STACK)

    # ── learning ─────────────────────────────────────────────────────────

    def remember(self, s, a, r, s2, done) -> None:
        for (s0, a0, R, sn, dn, n) in self.nstep.push(s, a, r, s2, done):
            self.buffer.add(s0, a0, R, sn, dn, n)
        self.steps += 1

    def learn(self) -> float | None:
        c = self.cfg
        if len(self.buffer) < max(c.warmup, c.batch_size):
            return None
        if self.steps % c.learn_every != 0:
            return None

        s, a, r, s2, done, nst = self.buffer.sample(c.batch_size)
        s, a, r, s2, done, nst = (
            x.to(self.device) for x in (s, a, r, s2, done, nst)
        )

        q = self.online(s).gather(1, a.unsqueeze(1)).squeeze(1)

        with torch.no_grad():
            # Double DQN: the ONLINE net picks the action, the TARGET net
            # scores it. Using the target for both would over-estimate, and
            # here that bias would land on "rotate" -- immediate visible
            # benefit, diffuse cost.
            best = self.online(s2).argmax(dim=1, keepdim=True)
            q_next = self.target(s2).gather(1, best).squeeze(1)
            # gamma**n, not gamma: the stored reward already spans n steps.
            td_target = r + (c.gamma ** nst) * q_next * (1.0 - done)

        loss = F.smooth_l1_loss(q, td_target)

        self.opt.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(self.online.parameters(), c.grad_clip)
        self.opt.step()

        self.updates += 1
        if self.updates % c.target_sync == 0:
            self.target.load_state_dict(self.online.state_dict())

        self.last_loss = float(loss.item())
        return self.last_loss

    # ── persistence and deployment ───────────────────────────────────────

    def save(self, path: Path) -> None:
        torch.save(
            {"model": self.online.state_dict(), "config": self.cfg.__dict__},
            str(path),
        )

    def load(self, path: Path) -> None:
        blob = torch.load(str(path), map_location=self.device, weights_only=False)
        self.online.load_state_dict(blob["model"])
        self.target.load_state_dict(blob["model"])

    # -- resume -------------------------------------------------------------
    #
    # A 5000-episode run takes about 90 minutes and the harness kills a
    # background command at roughly 30-40. The first attempt died at 1900/5000
    # and the deployed weights are still that partial run, so the published
    # numbers are a floor rather than a result (DQN_SPEC 12.13).
    #
    # The replay buffer is deliberately NOT saved. At 400k transitions it is
    # tens of megabytes per checkpoint, and it refills during warmup within a
    # couple of episodes; paying that cost per chunk to avoid a few hundred
    # wasted steps is a bad trade. Epsilon, the optimizer moments and the
    # target network all ARE saved, because losing those restarts exploration
    # and throws away the learning-rate state, which is not recoverable.

    def save_full(self, path: Path, extra: dict | None = None) -> None:
        torch.save({
            "model": self.online.state_dict(),
            "target": self.target.state_dict(),
            "optim": self.opt.state_dict(),
            "config": self.cfg.__dict__,
            "steps": self.steps,
            "updates": self.updates,
            "extra": extra or {},
        }, str(path))

    def load_full(self, path: Path) -> dict:
        blob = torch.load(str(path), map_location=self.device, weights_only=False)
        self.online.load_state_dict(blob["model"])
        self.target.load_state_dict(blob.get("target", blob["model"]))
        if "optim" in blob:
            self.opt.load_state_dict(blob["optim"])
        self.steps = int(blob.get("steps", 0))
        self.updates = int(blob.get("updates", 0))
        return dict(blob.get("extra", {}))

    def export_numpy(self, path: Path) -> None:
        """Write the weights as a .npz for NumpyPolicy.

        This is what ships to the gateway. The RPi runs NumPy, not PyTorch.
        """
        sd = {k: v.detach().cpu().numpy() for k, v in self.online.state_dict().items()}
        np.savez(
            str(path),
            w0=sd["trunk.0.weight"], b0=sd["trunk.0.bias"],
            w1=sd["trunk.2.weight"], b1=sd["trunk.2.bias"],
            wv=sd["value.weight"],   bv=sd["value.bias"],
            wa=sd["advantage.weight"], ba=sd["advantage.bias"],
        )


class NumpyPolicy:
    """The deployable agent: NumPy only, no PyTorch.

    Implements the same `Policy` protocol as `ThresholdPolicy`, so the gateway
    daemon swaps one for the other with a single constructor argument.
    """

    name = "dqn-numpy"

    def __init__(self, npz_path: Path):
        z = np.load(str(npz_path))
        self.w0, self.b0 = z["w0"], z["b0"]
        self.w1, self.b1 = z["w1"], z["b1"]
        self.wv, self.bv = z["wv"], z["bv"]
        self.wa, self.ba = z["wa"], z["ba"]
        self._stack = deque([np.zeros(OBS_DIM, dtype=np.float32)] * STACK, maxlen=STACK)

    def q_values(self, state: np.ndarray) -> np.ndarray:
        h = np.maximum(0.0, self.w0 @ state + self.b0)
        h = np.maximum(0.0, self.w1 @ h + self.b1)
        v = self.wv @ h + self.bv
        a = self.wa @ h + self.ba
        return v + a - a.mean()

    def decide(self, obs: Observation) -> Action:
        self._stack.append(np.asarray(obs.to_vector(), dtype=np.float32))
        state = np.concatenate(self._stack)
        return Action(int(np.argmax(self.q_values(state))))

    def reset_stack(self) -> None:
        self._stack = deque([np.zeros(OBS_DIM, dtype=np.float32)] * STACK, maxlen=STACK)


__all__ = ["AgentConfig", "DQNAgent", "DuelingQNet", "NStepAccumulator",
           "NumpyPolicy", "ReplayBuffer"]
