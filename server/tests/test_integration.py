"""
test_integration.py — M5. The demo scenarios, with every stub removed.

`test_server.py` proves the pipe carries bytes correctly using a stub detector
and a fixed-interval policy. This file replaces both with the trained models
and asks a different question: does the *system* behave, with a real detector
that is sometimes wrong and a real policy that must decide what to do about it.

What is real here
-----------------
Real AES-GCM, real ACCM mask, real posture state machine, real lease issuance,
real replay guards, real gateway and server daemons over a loopback socket.
On top of that:

* the **trained LSTM autoencoder** (`server/LSTM/runs_rig`), scoring live
  aggregated batches through the same `score()` the server calls in production;
* the **trained DQN** (`src/ML/dqn/runs/SELECTED_7000_seed6/agent_best.npz`),
  deciding through the deployable NumPy path, not the PyTorch one it trained in.

Which detector, and why not the MSU/ORNL one
--------------------------------------------
The rig speaks 5 channels; the MSU/ORNL model takes 128 PMU features and its
weights cannot transfer (`server/LSTM/README.md`). So the detector in this loop
is rig-shaped and trained on **synthetic** normal, because no rig-normal data
exists yet.

That split must be stated in the paper: **MSU/ORNL supplies the detection
numbers, this file supplies the integration evidence.** Neither substitutes for
the other. What is demonstrated here is that a trained detector and a trained
policy drive the real control loop correctly — not how accurately that detector
detects.

Usage (from repo root):
    python server/tests/test_integration.py
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
import tempfile
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (
    _ROOT / "server" / "python",
    _ROOT / "src" / "hardware" / "Gateway" / "python",
    _ROOT / "src" / "security" / "ACCM" / "python",
    _ROOT / "src" / "security" / "posture" / "python",
):
    sys.path.insert(0, str(_p))

# All three detector modules now have distinct names, so these are ordinary
# imports. They were not always: `server/LSTM/detector.py` and
# `src/ML/dqn/detector.py` both shadowed `server/python/detector.py` depending
# on sys.path order, and this file -- the first thing needing all three at once
# -- had to load each by file path and swap `sys.modules` between stages. The
# symptom was an ImportError naming a symbol that plainly existed in the file
# being imported. Renaming them (P11) deleted that workaround.
for _p in (
    _ROOT / "src" / "ML" / "dqn",
    _ROOT / "server" / "LSTM",
):
    sys.path.insert(0, str(_p))

import numpy as np  # noqa: E402

from aggregator import Sample  # noqa: E402
from agent import NumpyPolicy  # noqa: E402
from daemon import DaemonConfig, GatewayDaemon, now_ms  # noqa: E402
from gateway_state import EpochStore, GatewayState  # noqa: E402
from lstm_detector import LSTMDetector  # noqa: E402
from protocol import Posture  # noqa: E402
from uplink import Uplink  # noqa: E402

import server_daemon  # noqa: E402
from server_state import CounterStore, GatewaySession  # noqa: E402

import os  # noqa: E402

_DEFAULT_DQN = "final_seed22"
DQN_NPZ = (_ROOT / "src" / "ML" / "dqn" / "runs"
           / os.environ.get("DQN_RUN", _DEFAULT_DQN) / "agent_best.npz")

failures = 0
checks = 0
figures: dict = {}

GATEWAY_ID = 1
ENDPOINT = 0x0007
PSK = bytes((i * 23 + 7) & 0xFF for i in range(32))
ROOT_KEY = bytes((i * 3 + 1) & 0xFF for i in range(32))
TRANSCRIPT = bytes((i * 5 + 2) & 0xFF for i in range(32))

RIG_RUN = _ROOT / "server" / "LSTM" / "runs_rig"
import os  # noqa: E402

_DEFAULT_DQN = "final_seed22"
DQN_NPZ = (_ROOT / "src" / "ML" / "dqn" / "runs"
           / os.environ.get("DQN_RUN", _DEFAULT_DQN) / "agent_best.npz")


def check(ok: bool, label: str, detail: str = "") -> None:
    global failures, checks
    checks += 1
    if ok:
        print(f"  ok       {label}")
    else:
        failures += 1
        print(f"  FAIL     {label}")
        if detail:
            print(f"           {detail}")


# ── build ───────────────────────────────────────────────────────────────────

def build(tmp: Path, detector, policy, gw_detector=None):
    """Two detector instances, one per tier, and that is the design.

    `_observe` reads a GATEWAY-LOCAL detector (DQN_SPEC 3.4, "local fast-path
    detection"); the server runs its own and answers with a posture directive,
    not a raw score. Leaving the gateway's slot empty -- as the first version of
    this file did -- feeds the policy `lstm_score = 0.0` forever, so the single
    most important input it was trained on is permanently absent. It still runs,
    still looks plausible, and proposes ROTATE on 52% of calm ticks.

    They must be separate objects: each keeps its own rolling window, and
    sharing one would interleave two tiers' samples into a single sequence.
    """
    t = now_ms()

    gw_state = GatewayState(
        gateway_id=GATEWAY_ID,
        epoch_store=EpochStore(tmp / "gw_epochs.json"),
        leaf_psks={ENDPOINT: PSK},
        now_ms=t,
    )
    gw_state.install_root_key(ROOT_KEY, TRANSCRIPT)

    gw = GatewayDaemon(
        gw_state, policy,
        DaemonConfig(gateway_node_id=GATEWAY_ID, lease_grace_ms=10_000),
        detector=gw_detector,
    )
    gw._running = True

    session = GatewaySession(
        gateway_id=GATEWAY_ID,
        root_key=ROOT_KEY,
        transcript=TRANSCRIPT,
        counters=CounterStore(tmp / "srv_counters.json"),
        echo_window_frames=3,
    )
    session.adopt_key_epoch(gw_state.key_epoch)

    srv = server_daemon.MainServer(
        sessions={GATEWAY_ID: session},
        detector=detector,
        config=server_daemon.ServerConfig(port=0),
    )
    return gw, srv, session


async def connect(gw, srv):
    server = await asyncio.start_server(srv.handle_connection, "127.0.0.1", 0)
    gw.uplink = await Uplink.connect(
        "127.0.0.1", server.sockets[0].getsockname()[1])
    return server


def feed(gw, values) -> None:
    for cid, v in enumerate(values):
        gw.aggregator.add(Sample(ENDPOINT, cid, v, 0, now_ms()))


def calm(step: int, n=5):
    """Ordinary operation: the signal shape the detector was trained on."""
    return [math.sin(step * 0.2 + c) for c in range(n)]


def attacked(step: int, n=5):
    """A sustained offset plus a frozen channel — the shape the detector
    learned to find unusual."""
    v = calm(step, n)
    v[1] += 0.9
    v[3] = 0.4
    return v


def channel2_bad(step: int, n=5):
    """A single badly corrupted channel, for attribution and quarantine."""
    v = calm(step, n)
    v[2] = 6.0
    return v


async def drive(gw, steps: int, shape=calm, collect=None):
    """Run N 1 Hz cycles. One tick per window, as the daemon does."""
    for s in range(steps):
        feed(gw, shape(s))
        await gw.tick()
        if collect is not None:
            collect.append({"step": s,
                            "posture": int(gw.state.posture.posture),
                            "key_epoch": int(gw.state.key_epoch)})


async def prime(gw, steps: int = 62) -> None:
    """Fill the detector window, then clear the posture it provoked.

    The detector returns 0.0 -- "no evidence" -- until it has `window` rows,
    and the DQN responds to a detector telling it nothing by escalating. That
    is *correct*: a blind detector is exactly the Ukraine phase-5 condition the
    policy was trained to distrust, and failing open at cold start would be the
    bug. But it means a freshly started system sits at SUSPICIOUS for the first
    minute, which is a property of start-up rather than of the scenario under
    test.

    So: warm up, then reset to NORMAL and measure from there. The cold-start
    behaviour is recorded in `figures["cold_start"]` rather than discarded,
    because it is a real and defensible result.
    """
    await drive(gw, steps, calm)
    figures.setdefault("cold_start", {
        "posture_after_warmup": gw.state.posture.posture.name,
        "note": "blind detector at start-up -> policy escalates. Fail-secure.",
    })
    gw.state.posture.posture = Posture.NORMAL
    gw.state.posture.directive_floor = Posture.NORMAL


# ── scenarios ───────────────────────────────────────────────────────────────

async def scenario_1_normal(tmp: Path, detector, policy, gw_detector) -> None:
    """Sensors -> gateway -> server, posture NORMAL, lease renewing."""
    print("\n-- 1. normal operation --")
    gw, srv, session = build(tmp, detector, policy, gw_detector)
    server = await connect(gw, srv)
    try:
        await prime(gw)
        await drive(gw, 70, calm)

        check(gw.state.posture.posture == Posture.NORMAL,
              f"posture held NORMAL across 70 calm cycles "
              f"({gw.state.posture.posture.name})")
        check(gw.state.posture.lease_expires_ms - now_ms() > 2000,
              "lease still being renewed after 70 cycles")
        check(srv.stats.batches_received == 132,
              f"server received every batch ({srv.stats.batches_received}/132)")
        check(srv.stats.frames_rejected == 0,
              f"no frames rejected ({srv.stats.frames_rejected})")
        check(0.0 <= srv.last_score <= 1.0,
              f"detector produced a calibrated score ({srv.last_score:.3f})")
        check(detector.ready, "detector window filled")

        figures["normal"] = {
            "cycles": 70,
            "batches": int(srv.stats.batches_received),
            "rejected": int(srv.stats.frames_rejected),
            "final_score": float(srv.last_score),
            "posture": gw.state.posture.posture.name,
        }
    finally:
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def scenario_2_attack(tmp: Path, detector, policy, gw_detector) -> None:
    """Injected attack: detector scores, server escalates, gateway echoes."""
    print("\n-- 2. injected attack --")
    gw, srv, session = build(tmp, detector, policy, gw_detector)
    server = await connect(gw, srv)
    try:
        await prime(gw)
        quiet_score = float(srv.last_score)
        quiet_posture = gw.state.posture.posture
        epoch_before = int(gw.state.key_epoch)

        await drive(gw, 40, attacked)

        check(srv.last_score > quiet_score,
              f"score rose under attack ({quiet_score:.3f} -> "
              f"{srv.last_score:.3f})")
        responded = (gw.state.posture.posture > quiet_posture
                     or gw.state.key_epoch > epoch_before)
        check(responded,
              f"system responded: posture {quiet_posture.name} -> "
              f"{gw.state.posture.posture.name}, epoch {epoch_before} -> "
              f"{gw.state.key_epoch}")
        check(srv.stats.echo_violations == 0,
              f"posture echo stayed consistent ({srv.stats.echo_violations})")
        check(srv.stats.frames_rejected == 0, "no frames rejected under load")

        figures["attack"] = {
            "score_quiet": quiet_score,
            "score_attacked": float(srv.last_score),
            "posture_before": quiet_posture.name,
            "posture_after": gw.state.posture.posture.name,
            "rotations": int(gw.state.key_epoch) - epoch_before,
            "echo_violations": int(srv.stats.echo_violations),
        }
    finally:
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def scenario_3_control_cut(tmp: Path, detector, policy, gw_detector) -> None:
    """The strongest result: the link dies and the gateway escalates alone.

    No server-side threshold rule can do this, because the server is the part
    that has gone away. The lease is what makes it work: it is fail-secure, so
    silence is evidence rather than the absence of evidence.
    """
    print("\n-- 3. control channel cut --")
    gw, srv, session = build(tmp, detector, policy, gw_detector)
    server = await connect(gw, srv)
    try:
        await prime(gw)
        before = gw.state.posture.posture
        check(before == Posture.NORMAL, f"NORMAL before the cut ({before.name})")

        # Cut the uplink. Telemetry keeps being produced; nothing answers.
        await gw.uplink.close()
        gw.uplink = None

        t0 = now_ms()
        gw.state.posture.grace(1000, t0)

        gw.state.posture.tick(t0 + 1500)
        one = gw.state.posture.posture
        check(one == Posture.SUSPICIOUS,
              f"one missed lease -> SUSPICIOUS ({one.name})")

        gw.state.posture.tick(t0 + 3000)
        two = gw.state.posture.posture
        check(two == Posture.ANOMALY,
              f"two missed leases -> ANOMALY ({two.name})")

        # Telemetry must keep flowing while blind: escalate, do not stop.
        feed(gw, calm(70))
        pending = gw.aggregator.pending
        check(pending == 5, f"telemetry still collected while blind ({pending})")

        check(gw.state.posture.node_mask == 0,
              "lease expiry never auto-quarantines (no remote DoS)")

        figures["control_cut"] = {
            "posture_before": before.name,
            "after_one_lapse": one.name,
            "after_two_lapses": two.name,
            "auto_quarantined": int(gw.state.posture.node_mask),
            "telemetry_still_collected": int(pending),
        }
    finally:
        if gw.uplink:
            await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def scenario_4_quarantine(tmp: Path, detector, policy, gw_detector) -> None:
    """One channel isolated by the real detector, four keep flowing, release."""
    print("\n-- 4. quarantine and release --")
    gw, srv, session = build(tmp, detector, policy, gw_detector)
    server = await connect(gw, srv)
    try:
        await prime(gw)
        await drive(gw, 10, channel2_bad)

        check(gw.state.posture.is_quarantined(2),
              f"the REAL detector drove a quarantine of channel 2 "
              f"(score {srv.last_score:.3f})")
        check(not gw.state.posture.is_quarantined(0), "channel 0 untouched")

        feed(gw, channel2_bad(80))
        await gw.tick()
        batch = srv.last_batch
        untrusted = sorted(s.channel_id for s in batch.untrusted)
        trusted = sorted(s.channel_id for s in batch.trusted)
        check(untrusted == [2],
              f"channel 2 arrives tagged untrusted ({untrusted})")
        check(len(trusted) == 4, f"the other four keep flowing ({trusted})")

        # Triage clears it. The detector window still holds 60 rows of the
        # corrupted channel, so it must be flushed with clean data first --
        # otherwise the release is immediately undone by a correct re-detection,
        # which is the detector working, not a failure.
        # The channel recovers while still isolated. This only works because
        # the detector ingests untrusted samples too: reading `batch.trusted`
        # alone would carry the last bad value forward for ever, so a
        # quarantined channel could never be observed to recover and release
        # would be unreachable in practice.
        await drive(gw, 62, calm)
        recovered = float(srv.last_score)
        check(recovered < 0.9,
              f"the isolated channel is seen to recover ({recovered:.3f})")

        # Only now does triage release it. Release is explicit at BOTH ends,
        # deliberately: the gateway accumulates quarantine masks
        # (`node_mask |= ctrl.node_mask`) so two overlapping detections cannot
        # clear each other's channels, and `tick()` never touches the mask, so
        # a jammed control channel cannot be turned into a remote denial of
        # service. Nothing clears a quarantine implicitly.
        srv.issuer.release(2)
        gw.state.posture.release(2)
        check(not gw.state.posture.is_quarantined(2),
              "channel 2 released by triage")

        await drive(gw, 20, calm)
        check(not gw.state.posture.is_quarantined(2),
              f"and stays released on clean data "
              f"(score {srv.last_score:.3f})")

        feed(gw, calm(200))
        await gw.tick()
        batch_after = srv.last_batch
        check(len(batch_after.trusted) == 5,
              f"all five channels trusted again "
              f"({sorted(s.channel_id for s in batch_after.trusted)})")

        figures["quarantine"] = {
            "score_at_quarantine": float(srv.last_score),
            "untrusted": untrusted,
            "trusted": trusted,
            "released": not gw.state.posture.is_quarantined(2),
        }
    finally:
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def scenario_5_latency(tmp: Path, detector, policy, gw_detector) -> None:
    """End-to-end latency budget — the M6 artefact this run produces."""
    print("\n-- 5. end-to-end latency budget --")
    gw, srv, session = build(tmp, detector, policy, gw_detector)
    server = await connect(gw, srv)
    try:
        await prime(gw)

        times = []
        for s in range(40):
            feed(gw, calm(65 + s))
            a = time.perf_counter()
            await gw.tick()
            times.append((time.perf_counter() - a) * 1000.0)

        med = float(np.median(times))
        p95 = float(np.quantile(times, 0.95))
        check(p95 < 1000.0,
              f"a full cycle fits the 1 s window (p95 {p95:.1f} ms)")
        print(f"           median {med:.1f} ms, p95 {p95:.1f} ms, "
              f"detector {detector.latency_ms:.2f} ms")

        figures["latency"] = {
            "cycle_median_ms": med,
            "cycle_p95_ms": p95,
            "detector_ms": float(detector.latency_ms),
            "budget_ms": 1000.0,
            "fraction_of_budget": p95 / 1000.0,
        }
    finally:
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


# ── main ────────────────────────────────────────────────────────────────────

async def main_async() -> None:
    print("=== M5 integration: trained detector + trained policy ===")

    if not RIG_RUN.exists():
        raise SystemExit(
            f"no rig detector at {RIG_RUN}. Build it with:\n"
            f"  python server/LSTM/train.py --synthetic --features 5 "
            f"--window 60 --epochs 50 --out server/LSTM/runs_rig")
    if not DQN_NPZ.exists():
        raise SystemExit(f"no deployable DQN at {DQN_NPZ}")

    det = LSTMDetector.from_dir(RIG_RUN, channel_ids=[0, 1, 2, 3, 4])
    gw_det = LSTMDetector.from_dir(RIG_RUN, channel_ids=[0, 1, 2, 3, 4])
    policy = NumpyPolicy(DQN_NPZ)
    print(f"detector: {det.n_features} channels, window {det.window}")
    print(f"policy:   {DQN_NPZ.name} (NumPy, no torch)")

    for fn in (scenario_1_normal, scenario_2_attack, scenario_3_control_cut,
               scenario_4_quarantine, scenario_5_latency):
        det.reset()
        gw_det.reset()
        policy.reset_stack()
        with tempfile.TemporaryDirectory() as td:
            await fn(Path(td), det, policy, gw_det)


def main() -> int:
    asyncio.run(main_async())

    out = _ROOT / "server" / "tests" / "integration_figures.json"
    out.write_text(json.dumps(figures, indent=2, default=float))

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print(f"figures written to {out.relative_to(_ROOT)}")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
