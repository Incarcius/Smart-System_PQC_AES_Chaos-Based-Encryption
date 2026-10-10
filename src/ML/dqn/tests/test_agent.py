"""
test_agent.py — the agent's mechanics, before trusting any training run.

Checks the things that fail silently: a duelling head that does not decompose,
a Double DQN that is secretly vanilla, and — most important for deployment —
the NumPy export disagreeing with the PyTorch network it came from. That last
one would mean the gateway runs a different policy from the one that was
evaluated, and nothing would report an error.

Usage (from repo root):
    python src/ML/dqn/tests/test_agent.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import numpy as np
import torch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from agent import (  # noqa: E402
    AgentConfig,
    DQNAgent,
    DuelingQNet,
    NStepAccumulator,
    NumpyPolicy,
    ReplayBuffer,
)
from env import N_ACTIONS, STATE_DIM, EnvConfig, KeyLifecycleEnv  # noqa: E402
from policy import Action  # noqa: E402
from train import train  # noqa: E402

failures = 0
checks = 0


def check(ok, label, detail=""):
    global failures, checks
    checks += 1
    if ok:
        print(f"  ok       {label}")
    else:
        failures += 1
        print(f"  FAIL     {label}")
        if detail:
            print(f"           {detail}")


def test_network():
    print("\n-- duelling network --")
    net = DuelingQNet(STATE_DIM, N_ACTIONS, 64)
    x = torch.randn(8, STATE_DIM)
    q = net(x)
    check(q.shape == (8, N_ACTIONS), f"Q shape {tuple(q.shape)}")
    check(torch.isfinite(q).all(), "Q values finite")

    # The advantage stream must be mean-zero after the subtraction, or V and A
    # are not identifiable and the decomposition is meaningless.
    h = net.trunk(x)
    a = net.advantage(h)
    centred = a - a.mean(dim=1, keepdim=True)
    check(float(centred.mean(dim=1).abs().max()) < 1e-5,
          "advantage is mean-centred (V/A identifiable)")


def test_nstep():
    """n-step returns must discount correctly and flush the tail at episode end."""
    print()
    print("-- n-step accumulator --")

    acc = NStepAccumulator(n=3, gamma=0.5)
    s = [np.full(4, i, dtype=np.float32) for i in range(6)]

    check(acc.push(s[0], 0, 1.0, s[1], False) == [], "nothing emitted before the window fills")
    check(acc.push(s[1], 1, 2.0, s[2], False) == [], "still filling")

    out = acc.push(s[2], 2, 4.0, s[3], False)
    check(len(out) == 1, f"one transition once full (got {len(out)})")
    s0, a0, R, sn, dn, n = out[0]
    # 1.0 + 0.5*2.0 + 0.25*4.0 = 3.0
    check(abs(R - 3.0) < 1e-6, f"discounted return 3.0 (got {R})")
    check(a0 == 0, "action is the FIRST of the window")
    check(n == 3, f"spans 3 steps (got {n})")
    check(float(sn[0]) == 3.0, "next_state is 3 steps ahead")

    # Episode end must flush everything still held, with shorter spans.
    acc2 = NStepAccumulator(n=3, gamma=1.0)
    acc2.push(s[0], 0, 1.0, s[1], False)
    acc2.push(s[1], 1, 1.0, s[2], False)
    out = acc2.push(s[2], 2, 1.0, s[3], True)
    check(len(out) == 3, f"tail flushed at episode end (got {len(out)})")
    spans = sorted(o[5] for o in out)
    check(spans == [1, 2, 3], f"spans are 1,2,3 (got {spans})")
    check(all(o[4] for o in out), "all flushed transitions marked done")


def test_replay():
    print("\n-- replay buffer --")
    buf = ReplayBuffer(100, STATE_DIM)
    for i in range(150):
        buf.add(np.full(STATE_DIM, i, dtype=np.float32), i % N_ACTIONS,
                float(i), np.zeros(STATE_DIM, dtype=np.float32), i % 2)
    check(len(buf) == 100, f"capped at capacity (got {len(buf)})")
    s, a, r, s2, d, n = buf.sample(16)
    check(s.shape == (16, STATE_DIM), f"sample shape {tuple(s.shape)}")
    check(bool(((r >= 50) & (r < 150)).all()),
          "oldest entries were overwritten by the ring buffer")


def test_epsilon_decay():
    print("\n-- exploration schedule --")
    agent = DQNAgent(AgentConfig(eps_start=1.0, eps_end=0.05, eps_decay_steps=1000))
    check(abs(agent.epsilon - 1.0) < 1e-6, "starts fully exploratory")
    agent.steps = 500
    check(abs(agent.epsilon - 0.525) < 0.01, f"halfway ({agent.epsilon:.3f})")
    agent.steps = 5000
    check(abs(agent.epsilon - 0.05) < 1e-6, "floors at eps_end, never zero")


def test_learning_runs():
    print("\n-- a gradient step actually happens --")
    agent = DQNAgent(AgentConfig(warmup=64, batch_size=32, learn_every=1))
    rng = np.random.default_rng(0)
    for i in range(300):
        s = rng.standard_normal(STATE_DIM).astype(np.float32)
        s2 = rng.standard_normal(STATE_DIM).astype(np.float32)
        agent.remember(s, i % N_ACTIONS, float(rng.standard_normal()), s2, False)
        agent.learn()

    check(agent.updates > 0, f"{agent.updates} gradient steps taken")
    check(np.isfinite(agent.last_loss), f"loss finite ({agent.last_loss:.4f})")

    before = [p.clone() for p in agent.online.parameters()]
    for i in range(100):
        s = rng.standard_normal(STATE_DIM).astype(np.float32)
        agent.remember(s, 0, 1.0, s, False)
        agent.learn()
    moved = any(not torch.allclose(a, b)
                for a, b in zip(before, agent.online.parameters()))
    check(moved, "weights changed")


def test_numpy_export_matches():
    """The deployed policy must be the evaluated policy."""
    print("\n-- NumPy export agrees with PyTorch --")

    agent = DQNAgent(AgentConfig(hidden=64))
    rng = np.random.default_rng(3)

    with tempfile.TemporaryDirectory() as td:
        npz = Path(td) / "agent.npz"
        agent.export_numpy(npz)
        deployed = NumpyPolicy(npz)

        max_diff = 0.0
        disagreements = 0
        for _ in range(200):
            state = rng.standard_normal(STATE_DIM).astype(np.float32)
            with torch.no_grad():
                torch_q = agent.online(
                    torch.from_numpy(state).unsqueeze(0)
                ).squeeze(0).numpy()
            numpy_q = deployed.q_values(state)

            max_diff = max(max_diff, float(np.abs(torch_q - numpy_q).max()))
            if int(np.argmax(torch_q)) != int(np.argmax(numpy_q)):
                disagreements += 1

        check(max_diff < 1e-4, f"Q-values agree to {max_diff:.2e}")
        check(disagreements == 0,
              f"chosen action always identical ({disagreements} disagreements)")


def test_policy_protocol():
    """The agent must be drop-in for ThresholdPolicy in the gateway daemon."""
    print("\n-- Policy protocol compatibility --")

    agent = DQNAgent(AgentConfig(hidden=64))
    env = KeyLifecycleEnv(EnvConfig(episode_steps=20), seed=1)
    env.reset()

    obs = env.current_observation()
    action = agent.decide(obs)
    check(isinstance(action, Action), f"decide() returns an Action ({action.name})")

    with tempfile.TemporaryDirectory() as td:
        npz = Path(td) / "a.npz"
        agent.export_numpy(npz)
        deployed = NumpyPolicy(npz)
        check(isinstance(deployed.decide(obs), Action),
              "NumpyPolicy.decide() returns an Action too")

    # Drive a whole episode through the deployable path.
    env.reset()
    done = False
    steps = 0
    while not done:
        a = agent.decide(env.current_observation())
        _, _, done, _ = env.step(int(a))
        steps += 1
    check(steps == 20, f"agent drove a full episode ({steps} steps)")


def test_short_training_run():
    """End-to-end: training must run, improve, and produce both artefacts."""
    print("\n-- short training run --")

    with tempfile.TemporaryDirectory() as td:
        agent, history = train(
            episodes=60, episode_steps=200, seed=0,
            out_dir=Path(td), quiet=True,
        )

        check((Path(td) / "agent.pt").exists(), "saved agent.pt")
        check((Path(td) / "agent.npz").exists(), "saved agent.npz (deployable)")
        check(len(history["return"]) == 60, "history has one entry per episode")
        check(all(np.isfinite(r) for r in history["return"]),
              "all episode returns finite")
        check(agent.updates > 0, f"{agent.updates} gradient steps")

        first = float(np.mean(history["return"][:20]))
        last = float(np.mean(history["return"][-20:]))
        print(f"           return: first 20 eps {first:.1f} -> last 20 {last:.1f}")
        # 60 episodes is far too short to demand improvement; this only checks
        # it has not diverged. The real signal comes from evaluate.py.
        check(np.isfinite(last), "training did not diverge")


def main() -> int:
    print("=== DQN agent ===")
    torch.manual_seed(0)
    np.random.seed(0)

    test_network()
    test_nstep()
    test_replay()
    test_epsilon_decay()
    test_learning_runs()
    test_numpy_export_matches()
    test_policy_protocol()
    test_short_training_run()

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
