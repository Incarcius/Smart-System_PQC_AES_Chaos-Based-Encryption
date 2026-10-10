"""
test_env.py — the environment must be right before anything trains in it.

A bug here does not produce an error; it produces a policy that has learned
the wrong thing, and you find out at the demo. So these check the properties
the environment is supposed to have, not just that it runs.

Usage (from repo root):
    python src/ML/dqn/tests/test_env.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from baselines import all_baselines, rollout  # noqa: E402
from surrogate_detector import SurrogateDetector, SurrogateParams, sweep_grid  # noqa: E402
from env import STATE_DIM, EnvConfig, KeyLifecycleEnv  # noqa: E402
from policy import Action  # noqa: E402
from protocol import Posture, SEQ_MAX  # noqa: E402

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


def test_surrogate_calibration():
    """The surrogate must actually produce the error rates it is asked for."""
    print("\n-- detector surrogate calibration --")

    # These assertions changed when the real detector was measured at M4, and
    # the change is the point.
    #
    # They used to count scores above 0.5 and compare that to `fpr`. That works
    # only while benign scores sit near zero. The real detector is ECDF
    # calibrated, so its benign scores are UNIFORM on [0, 1] -- half of all
    # perfectly normal windows exceed 0.5 no matter what `fpr` is, and the old
    # assertion measured the benign distribution rather than the error rate.
    #
    # `fpr` means what it always meant: the probability that a CLEAN window is
    # drawn from the alarming distribution instead. What changed is that a
    # threshold crossing is no longer evidence of that happening.
    rng = np.random.default_rng(0)
    for fpr, fnr in ((0.05, 0.15), (0.20, 0.30)):
        det = SurrogateDetector(SurrogateParams(fpr=fpr, fnr=fnr, delay=0), rng)

        # Neither distribution is cleanly separated from HI, so a raw count
        # over-reports both rates: some uniform-benign draws land above it and
        # some alarm draws land below. Both are corrected using the two
        # distributions' own crossing rates, measured at fpr=fnr=0.
        HI = 0.99
        pure = SurrogateDetector(
            SurrogateParams(fpr=0.0, fnr=0.0, delay=0),
            np.random.default_rng(99))
        q_alarm = sum(pure.observe(True) > HI for _ in range(40000)) / 40000
        pure.reset()
        q_benign = sum(pure.observe(False) > HI for _ in range(40000)) / 40000

        clean = [det.observe(False) for _ in range(40000)]
        det.reset()
        comp = [det.observe(True) for _ in range(40000)]

        # P(s>HI | clean) = fpr*q_alarm + (1-fpr)*q_benign
        obs_fpr = sum(s > HI for s in clean) / len(clean)
        measured_fpr = (obs_fpr - q_benign) / max(q_alarm - q_benign, 1e-9)

        # P(s>HI | compromised) = (1-fnr)*q_alarm + fnr*q_benign
        obs_hit = sum(s > HI for s in comp) / len(comp)
        measured_fnr = 1.0 - (obs_hit - q_benign) / max(q_alarm - q_benign, 1e-9)

        check(abs(measured_fpr - fpr) < 0.05,
              f"fpr={fpr}: measured {measured_fpr:.3f} (alarm-draw rate)")
        check(abs(measured_fnr - fnr) < 0.06,
              f"fnr={fnr}: measured {measured_fnr:.3f}")

    # The property that now matters more than either: a high score is NOT
    # proof. With uniform benign scores about 10% of untroubled windows clear
    # 0.9, so a policy that treats one alarm as certainty will act on normal
    # traffic roughly every ten steps.
    det = SurrogateDetector(SurrogateParams(fpr=0.0, fnr=0.0, delay=0),
                            np.random.default_rng(5))
    clean = [det.observe(False) for _ in range(20000)]
    over = sum(s > 0.9 for s in clean) / len(clean)
    check(0.05 < over < 0.15,
          f"~10% of clean windows exceed 0.9 even at fpr=0 ({over:.3f}) -- "
          f"a single high score cannot be trusted")


def test_detector_delay():
    """A compromise must not be visible before `delay` steps have passed."""
    print("\n-- detection lag --")

    rng = np.random.default_rng(1)
    det = SurrogateDetector(SurrogateParams(fpr=0.0, fnr=0.0, delay=4), rng)

    early = [det.observe(True) for _ in range(4)]
    later = [det.observe(True) for _ in range(20)]

    # Benign is uniform, so an individual pre-lag sample can be high by chance.
    # What must hold is that the pre-lag scores look like benign noise and the
    # post-lag ones are pinned near 1.0.
    check(float(np.mean(early)) < 0.75,
          f"first 4 steps look like benign noise (mean {np.mean(early):.2f})")
    check(sum(s > 0.99 for s in later) > 15,
          f"alarms once the lag elapses ({sum(s > 0.99 for s in later)}/20)")


def test_env_shape():
    print("\n-- environment shape --")

    env = KeyLifecycleEnv(EnvConfig(episode_steps=50), seed=7)
    obs = env.reset()
    check(obs.shape == (STATE_DIM,), f"observation is {STATE_DIM}-dim (got {obs.shape})")
    check(np.all(np.isfinite(obs)), "observation is finite")

    obs, r, done, info = env.step(int(Action.HOLD))
    check(np.all(np.isfinite(obs)), "observation stays finite after a step")
    check(isinstance(r, float) and np.isfinite(r), f"reward is finite ({r:.3f})")
    check(not done, "episode does not end immediately")

    steps = 1
    while not done:
        obs, r, done, info = env.step(int(Action.HOLD))
        steps += 1
    check(steps == 50, f"episode is exactly 50 steps (got {steps})")


def test_rotation_evicts():
    """Rotation must actually remove the attacker. It is the only lever."""
    print("\n-- rotation evicts the attacker --")

    env = KeyLifecycleEnv(EnvConfig(episode_steps=500), seed=3)
    env.reset()

    evicted = False
    for _ in range(500):
        was = env.compromised
        _, _, done, info = env.step(int(Action.ROTATE_SESSION_KEY))
        if was and not env.compromised:
            evicted = True
        if done:
            break

    check(evicted, "a rotation evicted a live attacker at least once")


def test_attacker_reacquires():
    """One rotation must not be a permanent fix, or there is no tradeoff."""
    print("\n-- attacker re-acquires after eviction --")

    env = KeyLifecycleEnv(
        EnvConfig(episode_steps=2000, attack_prob_per_episode=1.0,
                  attack_min_len=1500, attack_max_len=1900),
        seed=11,
    )
    env.reset()

    compromises = 0
    prev = False
    for _ in range(2000):
        _, _, done, info = env.step(int(Action.ROTATE_SESSION_KEY))
        if info.compromised and not prev:
            compromises += 1
        prev = info.compromised
        if done:
            break

    check(compromises >= 2,
          f"attacker regained the key more than once ({compromises} times)")


def test_shield_is_real():
    """The environment must use the production shield, not a copy of it."""
    print("\n-- the shield is load-bearing in the environment --")

    env = KeyLifecycleEnv(EnvConfig(episode_steps=400), seed=5)
    env.reset()

    blocked = forced = 0
    for _ in range(400):
        _, _, done, info = env.step(int(Action.ROTATE_SESSION_KEY))
        blocked += int(info.blocked)
        forced += int(info.forced)
        if done:
            break

    check(blocked > 0, f"rate limit blocked rotations ({blocked})")

    # Nonce exhaustion must force a rotation even from HOLD.
    env2 = KeyLifecycleEnv(EnvConfig(episode_steps=2000), seed=6)
    env2.reset()
    forced2 = 0
    for _ in range(2000):
        _, _, done, info = env2.step(int(Action.HOLD))
        forced2 += int(info.forced)
        if done:
            break
    check(forced2 > 0,
          f"nonce exhaustion forced rotations despite a HOLD policy ({forced2})")


def test_agent_cannot_see_ground_truth():
    """The observation must not leak `compromised`. It is the whole premise."""
    print("\n-- hidden state stays hidden --")

    env = KeyLifecycleEnv(
        EnvConfig(episode_steps=600, attack_prob_per_episode=1.0,
                  attack_min_len=200, attack_max_len=400),
        detector_params=SurrogateParams(fpr=0.0, fnr=1.0, delay=0),
        seed=13,
    )
    env.reset()

    clean_obs, comp_obs = [], []
    for _ in range(600):
        obs, _, done, info = env.step(int(Action.HOLD))
        (comp_obs if info.compromised else clean_obs).append(obs.copy())
        if done:
            break

    check(len(comp_obs) > 20 and len(clean_obs) > 20,
          f"both states occurred (clean {len(clean_obs)}, compromised {len(comp_obs)})")

    if comp_obs and clean_obs:
        # With fnr=1.0 the detector NEVER reports the compromise, so the score
        # features carry no information about it. Anything left that separates
        # the two classes is either a real side channel (traffic) or a leak.
        c = np.mean(np.stack(comp_obs), axis=0)
        n = np.mean(np.stack(clean_obs), axis=0)
        score_feature_gap = float(abs(c[0] - n[0]))
        check(score_feature_gap < 0.05,
              f"detector score carries no signal when fnr=1.0 (gap {score_feature_gap:.4f})")


def test_baselines_run():
    """All five must run and produce distinguishable behaviour."""
    print("\n-- baselines --")

    # attack_prob=1.0 and enough episodes that the comparison is about the
    # policies rather than about which of them happened to draw a quiet
    # episode. With 3 episodes at p=0.6 every baseline drew attack-free runs
    # and the whole table read 0.0 compromised steps.
    env = KeyLifecycleEnv(
        EnvConfig(episode_steps=400, attack_prob_per_episode=1.0,
                  attack_min_len=150, attack_max_len=350),
        seed=21,
    )
    results = {}
    for name, pol in all_baselines(env).items():
        results[name] = rollout(env, pol, episodes=8, seed=21)

    for name, r in results.items():
        print(f"           {name:16s} return {r['mean_return']:9.1f}  "
              f"compromised {r['compromised_steps']:6.1f}  "
              f"rotations {r['rotations']:6.1f}  "
              f"fp {r['false_positive_steps']:6.1f}")

    check(len(results) == 5, f"all five baselines ran (got {len(results)})")
    check(results["never"]["compromised_steps"] > 5,
          f"'never' leaves the attacker holding the key "
          f"({results['never']['compromised_steps']:.1f} steps)")
    check(results["oracle"]["compromised_steps"] < results["never"]["compromised_steps"],
          "oracle leaves the attacker holding the key less than 'never' does")
    check(results["oracle"]["mean_return"] > results["never"]["mean_return"],
          "oracle outperforms 'never' on return")
    check(results["always-max"]["rotations"] > results["never"]["rotations"],
          "always-max rotates more than never")
    returns = [r["mean_return"] for r in results.values()]
    check(len(set(round(x, 1) for x in returns)) > 1,
          "policies are distinguishable by return")


def test_sweep_grid():
    print("\n-- robustness sweep grid --")
    grid = sweep_grid()
    check(len(grid) == 27, f"27 detector settings (got {len(grid)})")
    check(any(p.fnr >= 0.3 for p in grid), "grid includes a poor detector")
    check(any(p.delay >= 6 for p in grid), "grid includes a slow detector")


def main() -> int:
    print("=== DQN environment ===")
    test_surrogate_calibration()
    test_detector_delay()
    test_env_shape()
    test_rotation_evicts()
    test_attacker_reacquires()
    test_shield_is_real()
    test_agent_cannot_see_ground_truth()
    test_baselines_run()
    test_sweep_grid()

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
