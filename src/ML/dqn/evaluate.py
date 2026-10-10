"""
evaluate.py — the comparison table and the robustness curve.

Two results, and the second matters more.

1. **Baseline comparison.** The agent against all five reference policies on a
   fixed set of evaluation seeds. Same seeds for every policy, so the
   comparison is about the policies and not about who drew an easier episode.

2. **Robustness sweep.** Performance across the 27-point `(fpr, fnr, delay)`
   grid. This is the result that says whether the policy transfers: the real
   LSTM's error rates are unknown, so a policy that only works at one point on
   the grid has learned that detector rather than the problem.

Honest reporting
----------------
If the agent does not beat `threshold`, say so. A negative result with a clean
methodology is publishable and a fabricated positive is not — and the
robustness curve usually shows *where* each policy wins, which is more useful
than a single scalar either way.

Usage:
    python src/ML/dqn/evaluate.py --agent src/ML/dqn/runs/agent.pt
    python src/ML/dqn/evaluate.py --agent ... --sweep
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from agent import DQNAgent  # noqa: E402
from baselines import all_baselines, rollout  # noqa: E402
from surrogate_detector import SurrogateParams, sweep_grid  # noqa: E402
from env import EnvConfig, KeyLifecycleEnv  # noqa: E402

EVAL_SEEDS = (101, 202, 303, 404, 505, 606, 707, 808, 909, 1010,
              1111, 1212, 1313, 1414, 1515)


def evaluate_policy(policy, cfg: EnvConfig, detector_params, seeds=EVAL_SEEDS,
                    episodes_per_seed: int = 4) -> dict:
    """Same seeds for every policy — that is what makes the table comparable."""
    rows = []
    for seed in seeds:
        env = KeyLifecycleEnv(cfg, detector_params=detector_params, seed=seed)
        if hasattr(policy, "reset_stack"):
            policy.reset_stack()
        if hasattr(policy, "env"):
            policy.env = env          # the oracle needs the live env
        rows.append(rollout(env, policy, episodes=episodes_per_seed, seed=seed))

    return {
        "policy": rows[0]["policy"],
        "mean_return": float(np.mean([r["mean_return"] for r in rows])),
        "std_return": float(np.std([r["mean_return"] for r in rows])),
        "compromised_steps": float(np.mean([r["compromised_steps"] for r in rows])),
        "rotations": float(np.mean([r["rotations"] for r in rows])),
        "blocked_actions": float(np.mean([r["blocked_actions"] for r in rows])),
        "forced_actions": float(np.mean([r["forced_actions"] for r in rows])),
        "false_positive_steps": float(np.mean([r["false_positive_steps"] for r in rows])),
    }


def paired_compare(policy_a, policy_b, cfg, detector_params,
                   seeds=EVAL_SEEDS, episodes_per_seed: int = 4) -> dict:
    """Compare two policies on the SAME seeds, and report the difference.

    This is the statistic that matters, and the first evaluation did not use
    it. Comparing two independent means hid the answer: the agent scored -1069
    and `threshold` -1295, a gap of 226 -- but each had a spread of 500-950
    across seeds, so the gap looked like noise.

    Most of that spread is the SEED, not the policy: some episodes contain a
    long intrusion and every policy does badly on them. Differencing per seed
    cancels that shared difficulty, leaving the variation actually caused by
    the choice of policy. The same reason you weigh people before and after
    rather than comparing two groups.
    """
    diffs = []
    for seed in seeds:
        env_a = KeyLifecycleEnv(cfg, detector_params=detector_params, seed=seed)
        env_b = KeyLifecycleEnv(cfg, detector_params=detector_params, seed=seed)
        for pol, env in ((policy_a, env_a), (policy_b, env_b)):
            if hasattr(pol, "reset_stack"):
                pol.reset_stack()
            if hasattr(pol, "env"):
                pol.env = env
        ra = rollout(env_a, policy_a, episodes=episodes_per_seed, seed=seed)
        rb = rollout(env_b, policy_b, episodes=episodes_per_seed, seed=seed)
        diffs.append(ra["mean_return"] - rb["mean_return"])

    d = np.asarray(diffs)
    mean = float(d.mean())
    sem = float(d.std(ddof=1) / np.sqrt(len(d))) if len(d) > 1 else 0.0

    return {
        "a": getattr(policy_a, "name", "a"),
        "b": getattr(policy_b, "name", "b"),
        "mean_diff": mean,
        "sem": sem,
        "ci95_lo": mean - 1.96 * sem,
        "ci95_hi": mean + 1.96 * sem,
        "wins": int((d > 0).sum()),
        "n": len(d),
    }


def compare(agent, cfg: EnvConfig, detector_params) -> dict:
    env_for_oracle = KeyLifecycleEnv(cfg, detector_params=detector_params, seed=0)
    policies = all_baselines(env_for_oracle)
    if agent is not None:
        policies["dqn"] = agent

    results = {}
    for name, pol in policies.items():
        results[name] = evaluate_policy(pol, cfg, detector_params)
    return results


def print_table(results: dict) -> None:
    print(f"{'policy':16s} {'return':>12s} {'+/-':>8s} {'compromised':>12s} "
          f"{'rotations':>10s} {'blocked':>8s} {'forced':>7s} {'false-pos':>10s}")
    print("-" * 92)
    for name, r in sorted(results.items(), key=lambda kv: -kv[1]["mean_return"]):
        print(f"{name:16s} {r['mean_return']:12.1f} {r['std_return']:8.1f} "
              f"{r['compromised_steps']:12.1f} {r['rotations']:10.1f} "
              f"{r['blocked_actions']:8.1f} {r['forced_actions']:7.1f} "
              f"{r['false_positive_steps']:10.1f}")


def print_paired(pc: dict) -> None:
    print()
    print(f"paired comparison, {pc['n']} seeds (same episodes for both):")
    print(f"  {pc['a']} - {pc['b']} = {pc['mean_diff']:+.1f} "
          f"(95% CI {pc['ci95_lo']:+.1f} .. {pc['ci95_hi']:+.1f})")
    print(f"  {pc['a']} wins on {pc['wins']}/{pc['n']} seeds")
    if pc["ci95_lo"] > 0:
        print(f"  -> the interval excludes zero: {pc['a']} is genuinely ahead.")
    elif pc["ci95_hi"] < 0:
        print(f"  -> the interval excludes zero: {pc['b']} is genuinely ahead.")
    else:
        print(f"  -> the interval SPANS ZERO. Not a real difference on this "
              f"evidence; do not report a win.")


def verdict(results: dict) -> None:
    """State plainly whether the agent earned its place."""
    if "dqn" not in results:
        return

    dqn = results["dqn"]["mean_return"]
    thr = results["threshold"]["mean_return"]
    orc = results.get("oracle", {}).get("mean_return")

    print()
    if dqn > thr:
        gain = (dqn - thr) / abs(thr) * 100
        print(f"VERDICT: the agent beats `threshold` by {gain:.1f}%.")
    else:
        loss = (thr - dqn) / abs(thr) * 100
        print(f"VERDICT: the agent does NOT beat `threshold` "
              f"({loss:.1f}% worse). Report this, and use the sweep to show "
              f"where each policy wins -- a clean negative result is a result.")

    # The gap to the oracle measures how much of the remaining loss comes from
    # DETECTOR UNCERTAINTY rather than from policy -- see OraclePolicy, which is
    # a perfect-information reference and explicitly not an upper bound. Once
    # the agent is past it that ratio stops being a fraction of anything, so it
    # must not be printed: an earlier version reported "closes 478% of the gap",
    # which reads as a headline number and means nothing.
    if orc is not None:
        if dqn > orc:
            print(f"         It also exceeds the perfect-information reference "
                  f"({dqn:.1f} vs {orc:.1f}). That is not better information -- "
                  f"the oracle sees the truth and the agent does not. It is a "
                  f"better tradeoff: the oracle escalates on any attacker "
                  f"present, paying a false-positive cost the agent declines to "
                  f"pay. No gap-closed figure is meaningful here.")
        elif orc > thr:
            closed = (dqn - thr) / (orc - thr) * 100
            print(f"         It closes {closed:.0f}% of the threshold-to-oracle "
                  f"gap, i.e. of the loss attributable to detector uncertainty "
                  f"rather than to policy.")
        else:
            print(f"         The oracle does not beat `threshold` here "
                  f"({orc:.1f} vs {thr:.1f}), so the gap is not a usable "
                  f"reference at this setting.")

    # The safety properties must hold regardless of the score. Report what the
    # shield actually did; do not assert it was load-bearing without evidence.
    frc = results["dqn"]["forced_actions"]
    blk = results["dqn"]["blocked_actions"]
    print(f"         Shield forced {frc:.1f} and blocked {blk:.1f} actions per "
          f"episode.")
    if frc == 0.0 and blk == 0.0:
        print(f"         The envelope never bound in this evaluation, so it is "
              f"UNTESTED here -- the policy stayed inside it unaided. Safety "
              f"rests on the shield's own unit tests, not on this run.")
    elif frc == 0.0:
        print(f"         Blocking is load-bearing; the forcing path never "
              f"triggered, so it is untested by this run.")
    else:
        print(f"         Both paths fired: the envelope is load-bearing, not "
              f"decorative.")


def sweep(agent, cfg: EnvConfig, compare_to=("threshold",)) -> list[dict]:
    """Performance across the detector grid. The transferability result."""
    grid = sweep_grid()
    rows = []

    print(f"\n{'fpr':>5s} {'fnr':>5s} {'delay':>6s} {'dqn':>10s} "
          f"{'threshold':>10s} {'winner':>10s}")
    print("-" * 52)

    for params in grid:
        env_oracle = KeyLifecycleEnv(cfg, detector_params=params, seed=0)
        pols = all_baselines(env_oracle)
        row = {"fpr": params.fpr, "fnr": params.fnr, "delay": params.delay}

        row["dqn"] = evaluate_policy(agent, cfg, params, seeds=EVAL_SEEDS[:3],
                                     episodes_per_seed=2)["mean_return"]
        for name in compare_to:
            row[name] = evaluate_policy(pols[name], cfg, params,
                                        seeds=EVAL_SEEDS[:3],
                                        episodes_per_seed=2)["mean_return"]

        winner = "dqn" if row["dqn"] > row["threshold"] else "threshold"
        rows.append(row)
        print(f"{params.fpr:5.2f} {params.fnr:5.2f} {params.delay:6d} "
              f"{row['dqn']:10.1f} {row['threshold']:10.1f} {winner:>10s}")

    wins = sum(1 for r in rows if r["dqn"] > r["threshold"])
    print(f"\nagent wins {wins}/{len(rows)} detector settings")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", type=Path, default=_HERE / "runs" / "agent.pt")
    ap.add_argument("--steps", type=int, default=600)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    cfg = EnvConfig(episode_steps=args.steps)

    agent = None
    if args.agent.exists():
        agent = DQNAgent()
        agent.load(args.agent)
        agent.greedy = True
    else:
        print(f"(no agent at {args.agent} — baselines only)")

    print("=== baseline comparison ===")
    print(f"detector: fpr=0.05 fnr=0.15 delay=3, {args.steps}-step episodes, "
          f"{len(EVAL_SEEDS)} seeds x 4 episodes\n")
    results = compare(agent, cfg, SurrogateParams())
    print_table(results)
    verdict(results)

    if agent is not None:
        env_o = KeyLifecycleEnv(cfg, detector_params=SurrogateParams(), seed=0)
        pc = paired_compare(agent, all_baselines(env_o)["threshold"],
                            cfg, SurrogateParams())
        print_paired(pc)

    sweep_rows = None
    if args.sweep and agent is not None:
        print("\n=== robustness sweep ===")
        sweep_rows = sweep(agent, cfg)

    if args.out:
        args.out.write_text(json.dumps(
            {"comparison": results, "sweep": sweep_rows}, indent=2))
        print(f"\nwrote {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
