"""
train.py — train the key-lifecycle agent.

Domain randomisation is the point
---------------------------------
Every episode draws a different detector quality from the sweep grid. That is
not a regularisation trick, it is the mechanism that makes the policy
transferable: the real LSTM's `(fpr, fnr, delay)` are unknown today, so an
agent trained against one fixed detector would be tuned to a detector that will
not exist.

Training across the distribution forces it to learn the underlying tradeoff —
when to trust an alarm, when to act on the gateway's own local evidence
instead, and what a detector that has gone *quiet* means. The robustness curve
in `evaluate.py` is the evidence that it worked.

Usage:
    python src/ML/dqn/train.py --episodes 1500
    python src/ML/dqn/train.py --episodes 200 --quick    # smoke test
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch

# One thread per process. The network is tiny, so intra-op parallelism buys
# almost nothing, and several seeds training in parallel on one machine would
# otherwise oversubscribe every core and run slower than running them serially.
torch.set_num_threads(1)

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from agent import AgentConfig, DQNAgent  # noqa: E402
from surrogate_detector import sweep_grid  # noqa: E402
from env import EnvConfig, KeyLifecycleEnv  # noqa: E402


# Checkpoint-selection seeds. Three was too few, and it mattered: over three
# episodes one (902) scored about -1090 for EVERY agent and contributed nothing
# to the ranking, while another swung by 700, so "best so far" was decided by
# essentially one episode. Ranking the same three trained seeds on 15 episodes
# instead reversed the winner. A selection signal that noisy cannot distinguish
# a plateau from continued improvement, which is the question this run has to
# answer.
#
# Kept disjoint from evaluate.EVAL_SEEDS (101, 202, ... 1515) so the weights are
# never chosen using the episodes the confidence interval is computed on. The
# obvious range 901..915 is NOT disjoint -- it contains 909.
EVAL_SEEDS = tuple(range(9001, 9016))


def _greedy_eval(agent, episode_steps: int) -> float:
    """Mean greedy return on FIXED seeds and a FIXED detector.

    Fixed on purpose: the selection signal must not move between calls, or
    "best so far" measures which detector was drawn rather than progress.
    """
    from surrogate_detector import SurrogateParams

    total = 0.0
    for seed in EVAL_SEEDS:
        env = KeyLifecycleEnv(
            EnvConfig(episode_steps=episode_steps),
            detector_params=SurrogateParams(),
            seed=seed,
        )
        state = env.reset()
        done = False
        while not done:
            state, reward, done, _ = env.step(agent.act(state, greedy=True))
            total += reward
    return total / len(EVAL_SEEDS)


def train(
    episodes: int = 1500,
    episode_steps: int = 600,
    seed: int = 0,
    resume: bool = False,
    out_dir: Path | None = None,
    log_every: int = 50,
    eval_every: int = 50,
    quiet: bool = False,
) -> tuple[DQNAgent, dict]:
    out_dir = out_dir or (_HERE / "runs")
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(seed)
    grid = sweep_grid()

    agent = DQNAgent(AgentConfig())
    env = KeyLifecycleEnv(EnvConfig(episode_steps=episode_steps), seed=seed)

    history = {"return": [], "compromised": [], "rotations": [],
               "blocked": [], "forced": [], "epsilon": [], "loss": [],
               "eval": []}
    t0 = time.time()
    best_eval = -float('inf')
    best_ep = 0
    start_ep = 0

    # Resume. A full run outlives the harness's background-command limit, so
    # it has to be completable in chunks; see DQNAgent.save_full for what is
    # and is not preserved.
    resume_path = out_dir / "resume.pt"
    if resume and resume_path.exists():
        extra = agent.load_full(resume_path)
        start_ep = int(extra.get("episode", 0))
        best_eval = float(extra.get("best_eval", -float('inf')))
        best_ep = int(extra.get("best_ep", 0))
        history = extra.get("history", history)
        if not quiet:
            print(f"resumed from episode {start_ep} "
                  f"(best eval {best_eval:.1f} at ep {best_ep}, "
                  f"eps {agent.epsilon:.3f})")
        if start_ep >= episodes:
            if not quiet:
                print(f"already at {start_ep}/{episodes} episodes; nothing to do")
            return agent, history

    for ep in range(start_ep, episodes):
        # A fresh detector quality every episode. See the module docstring.
        env.detector_params = grid[int(rng.integers(len(grid)))]
        env.detector.params = env.detector_params

        state = env.reset()
        agent.nstep.reset()
        total = 0.0
        comp = rot = blk = frc = 0
        losses = []
        done = False

        while not done:
            action = agent.act(state)
            next_state, reward, done, info = env.step(action)

            agent.remember(state, action, reward, next_state, done)
            loss = agent.learn()
            if loss is not None:
                losses.append(loss)

            state = next_state
            total += reward
            comp += int(info.compromised)
            rot += int(info.action_taken in (1, 2, 3))
            blk += int(info.blocked)
            frc += int(info.forced)

        history["return"].append(total)
        history["compromised"].append(comp)
        history["rotations"].append(rot)
        history["blocked"].append(blk)
        history["forced"].append(frc)
        history["epsilon"].append(agent.epsilon)
        history["loss"].append(float(np.mean(losses)) if losses else 0.0)

        # Periodic greedy eval on fixed seeds; keep the best weights.
        #
        # Training return cannot serve as the selection signal: every episode
        # draws a different detector quality, so a high score may just mean an
        # easy draw. And without this only the FINAL weights survive -- the
        # first run happened to end near its best, which was luck.
        if (ep + 1) % eval_every == 0:
            score = _greedy_eval(agent, episode_steps)
            history["eval"].append((ep + 1, score))
            improved = score > best_eval
            if improved:
                best_eval, best_ep = score, ep + 1
                agent.save(out_dir / "agent_best.pt")
                agent.export_numpy(out_dir / "agent_best.npz")
            # Checkpoint for resume on the same cadence as selection, so a kill
            # costs at most `eval_every` episodes of work.
            agent.save_full(resume_path, {
                "episode": ep + 1, "best_eval": best_eval,
                "best_ep": best_ep, "history": history,
            })
            if not quiet:
                print(f"    eval {score:9.1f}   best {best_eval:9.1f} "
                      f"(ep {best_ep})" + ("   <-- saved" if improved else ""),
                      flush=True)

        if not quiet and (ep + 1) % log_every == 0:
            w = slice(-log_every, None)
            print(
                f"ep {ep+1:5d}  "
                f"return {np.mean(history['return'][w]):9.1f}  "
                f"compromised {np.mean(history['compromised'][w]):6.1f}  "
                f"rot {np.mean(history['rotations'][w]):5.1f}  "
                f"blocked {np.mean(history['blocked'][w]):5.1f}  "
                f"eps {agent.epsilon:.3f}  "
                f"loss {np.mean(history['loss'][w]):7.3f}",
                flush=True,
            )

    elapsed = time.time() - t0
    if not quiet:
        print(f"\ntrained {episodes} episodes in {elapsed:.1f}s "
              f"({agent.updates} gradient steps)")
        print(f"best greedy eval {best_eval:.1f} at episode {best_ep}")

    agent.save(out_dir / "agent.pt")
    agent.export_numpy(out_dir / "agent.npz")
    (out_dir / "history.json").write_text(json.dumps(history))

    if not quiet:
        print(f"saved: {out_dir / 'agent.pt'}")
        print(f"       {out_dir / 'agent.npz'}  (deployable, NumPy only)")

    return agent, history


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=1500)
    ap.add_argument("--steps", type=int, default=600)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--resume", action="store_true",
                    help="continue from out_dir/resume.pt if present")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--quick", action="store_true",
                    help="short run for a smoke test")
    args = ap.parse_args()

    episodes = 150 if args.quick else args.episodes
    steps = 300 if args.quick else args.steps

    train(episodes=episodes, episode_steps=steps, seed=args.seed,
          resume=args.resume, out_dir=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
