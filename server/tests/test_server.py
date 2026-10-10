"""
test_server.py — the whole pipe, end to end.

Runs the REAL gateway daemon against the REAL server daemon over a loopback
TCP socket, with a simulated ESP32 feeding the gateway. Nothing between the
two daemons is faked: real AES-GCM, real ACCM mask, real posture state machine,
real lease issuance, real replay guards.

This is the test that says the system works, as opposed to that its parts do.

Usage (from repo root):
    python server/tests/test_server.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (
    _ROOT / "server" / "python",
    _ROOT / "src" / "hardware" / "Gateway" / "python",
    _ROOT / "src" / "security" / "ACCM" / "python",
    _ROOT / "src" / "security" / "posture" / "python",
):
    sys.path.insert(0, str(_p))

import leaf_link as ll  # noqa: E402
from aggregator import Sample  # noqa: E402
from daemon import DaemonConfig, GatewayDaemon  # noqa: E402
from daemon import now_ms  # noqa: E402
from detector import StubDetector  # noqa: E402
from gateway_state import EpochStore, GatewayState  # noqa: E402
from lease import LeasePolicy  # noqa: E402
from policy import FixedIntervalPolicy, ThresholdPolicy  # noqa: E402
from protocol import Posture  # noqa: E402
from uplink import Uplink  # noqa: E402

# The gateway and the server each have a daemon; the server's module is named
# server_daemon.py so a plain import is unambiguous with both on sys.path.
import server_daemon  # noqa: E402
from server_state import CounterStore, GatewaySession  # noqa: E402

failures = 0
checks = 0

GATEWAY_ID = 1
ENDPOINT = 0x0007
PSK = bytes((i * 23 + 7) & 0xFF for i in range(32))
ROOT_KEY = bytes((i * 3 + 1) & 0xFF for i in range(32))
TRANSCRIPT = bytes((i * 5 + 2) & 0xFF for i in range(32))


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


class FixedScoreDetector:
    """Forces a chosen score, so posture transitions can be driven on demand."""

    def __init__(self, score: float = 0.0, mask: int = 0):
        self.next_score = score
        self.next_mask = mask
        self.latency_ms = 0.0

    def score(self, batch) -> float:
        return self.next_score

    def attribute(self, batch) -> int:
        return self.next_mask


def build(tmp: Path, detector=None, lease_policy=None, policy=None):
    t = now_ms()

    gw_state = GatewayState(
        gateway_id=GATEWAY_ID,
        epoch_store=EpochStore(tmp / "gw_epochs.json"),
        leaf_psks={ENDPOINT: PSK},
        now_ms=t,
    )
    gw_state.install_root_key(ROOT_KEY, TRANSCRIPT)

    gw = GatewayDaemon(
        gw_state,
        policy or FixedIntervalPolicy(interval_ticks=10**9),
        DaemonConfig(gateway_node_id=GATEWAY_ID, lease_grace_ms=10_000),
    )
    gw._running = True

    session = GatewaySession(
        gateway_id=GATEWAY_ID,
        root_key=ROOT_KEY,
        transcript=TRANSCRIPT,
        counters=CounterStore(tmp / "srv_counters.json"),
        echo_window_frames=3,
    )
    # Follow whatever epoch the gateway landed on after install_root_key().
    session.adopt_key_epoch(gw_state.key_epoch)

    srv = server_daemon.MainServer(
        sessions={GATEWAY_ID: session},
        detector=detector or StubDetector(),
        lease_policy=lease_policy,
        config=server_daemon.ServerConfig(port=0),
    )
    return gw, srv, session


async def connect(gw: GatewayDaemon, srv) -> asyncio.AbstractServer:
    server = await asyncio.start_server(
        srv.handle_connection, "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    gw.uplink = await Uplink.connect("127.0.0.1", port)
    return server


def feed_window(gw: GatewayDaemon, values, t=None) -> None:
    t = t or now_ms()
    for cid, v in enumerate(values):
        gw.aggregator.add(Sample(ENDPOINT, cid, v, 0, t))


# ── tests ───────────────────────────────────────────────────────────────────


async def test_pipe(tmp: Path) -> None:
    """Telemetry out, lease back, over a real socket."""
    print("\n-- end-to-end over a real socket --")

    gw, srv, session = build(tmp)
    server = await connect(gw, srv)

    try:
        for i in range(5):
            feed_window(gw, [230.0, 5.0, 35.0, 50.0, 1.0])
            await gw.tick()

        check(srv.stats.batches_received == 5,
              f"server received 5 batches (got {srv.stats.batches_received})")
        check(srv.stats.samples_received == 25,
              f"25 samples arrived (got {srv.stats.samples_received})")
        check(srv.stats.frames_rejected == 0,
              f"no frames rejected (got {srv.stats.frames_rejected})")
        check(session.stats.frames_auth_failed == 0, "no authentication failures")

        lease_left = gw.state.posture.lease_expires_ms - now_ms()
        check(lease_left > 2000, f"lease renewed by the response ({lease_left} ms)")
        check(srv.stats.controls_sent == 5, "one control frame per batch")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def test_posture_round_trip(tmp: Path) -> None:
    """A detector alarm must reach the gateway and come back in the header."""
    print("\n-- posture command round trip + echo verification --")

    det = FixedScoreDetector(0.0)
    gw, srv, session = build(tmp, detector=det, policy=ThresholdPolicy())
    server = await connect(gw, srv)

    try:
        feed_window(gw, [230.0, 5.0, 35.0, 50.0, 1.0])
        await gw.tick()
        check(gw.state.posture.posture == Posture.NORMAL, "starts NORMAL")

        # Alarm: the server should command ENFORCE ANOMALY.
        # 0.995 not 0.85. `lease.py`'s thresholds were re-derived at M5 for an
        # ECDF-calibrated score, which is UNIFORM on normal data: a threshold
        # is literally its false-alarm rate, so the anomaly level moved from
        # 0.75 to 0.99. Under the old value 0.85 this fixture was asking the
        # server to escalate on a score that 15% of healthy windows produce.
        det.next_score = 0.995
        feed_window(gw, [999.0, 5.0, 35.0, 50.0, 1.0])
        await gw.tick()

        check(gw.state.posture.posture == Posture.ANOMALY,
              f"gateway escalated to ANOMALY (is {gw.state.posture.posture.name})")
        check(gw.state.posture.directive_floor == Posture.ANOMALY,
              "ENFORCE set the floor")

        # The next frame must carry the new posture in its header, and the
        # server must see it. That is the echo closing the loop.
        # 0.995 not 0.85. `lease.py`'s thresholds were re-derived at M5 for an
        # ECDF-calibrated score, which is UNIFORM on normal data: a threshold
        # is literally its false-alarm rate, so the anomaly level moved from
        # 0.75 to 0.99. Under the old value 0.85 this fixture was asking the
        # server to escalate on a score that 15% of healthy windows produce.
        det.next_score = 0.995
        feed_window(gw, [999.0, 5.0, 35.0, 50.0, 1.0])
        await gw.tick()

        check(srv.stats.echo_violations == 0,
              "posture echo verified — no violation raised")
        check(srv.stats.alerts == [], f"no SOC alerts ({srv.stats.alerts})")

        # The agent must not be able to undercut the ENFORCE floor.
        granted = gw.state.posture.request(Posture.NORMAL, now_ms())
        check(granted == Posture.ANOMALY,
              f"agent cannot drop below the ENFORCE floor (got {granted.name})")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def test_quarantine_round_trip(tmp: Path) -> None:
    """A QUARANTINE directive must isolate the named channel end to end."""
    print("\n-- quarantine round trip --")

    # 0.9995: quarantine_score is now 0.999 (see lease.py). Quarantine
    # isolates a channel, so it demands the strictest evidence of all.
    det = FixedScoreDetector(0.9995, mask=0b00100)   # channel 2
    gw, srv, session = build(tmp, detector=det)
    server = await connect(gw, srv)

    try:
        feed_window(gw, [230.0, 5.0, 35.0, 50.0, 1.0])
        await gw.tick()

        check(gw.state.posture.is_quarantined(2), "channel 2 quarantined at the gateway")
        check(not gw.state.posture.is_quarantined(1), "channel 1 untouched")

        # Next window: the quarantined channel must still arrive, but tagged.
        feed_window(gw, [230.0, 5.0, 35.0, 50.0, 1.0])
        await gw.tick()

        batch = srv.last_batch
        check(len(batch.untrusted) == 1,
              f"1 sample arrived untrusted (got {len(batch.untrusted)})")
        check(batch.untrusted[0].channel_id == 2, "the quarantined channel is the flagged one")
        check(len(batch.trusted) == 4,
              f"4 channels still trusted (got {len(batch.trusted)})")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def test_echo_violation(tmp: Path) -> None:
    """A gateway that ignores a command must be detected within K frames."""
    print("\n-- non-compliant gateway detected --")

    det = FixedScoreDetector(0.0)
    gw, srv, session = build(tmp, detector=det)
    server = await connect(gw, srv)

    try:
        feed_window(gw, [1.0] * 5)
        await gw.tick()

        # Command ANOMALY, then pin the gateway at NORMAL so it cannot comply —
        # standing in for a wedged or hostile gateway.
        # 0.995 not 0.85. `lease.py`'s thresholds were re-derived at M5 for an
        # ECDF-calibrated score, which is UNIFORM on normal data: a threshold
        # is literally its false-alarm rate, so the anomaly level moved from
        # 0.75 to 0.99. Under the old value 0.85 this fixture was asking the
        # server to escalate on a score that 15% of healthy windows produce.
        det.next_score = 0.995
        feed_window(gw, [1.0] * 5)
        await gw.tick()

        gw.state.posture.posture = Posture.NORMAL
        gw.state.posture.directive_floor = Posture.NORMAL

        for _ in range(4):
            det.next_score = 0.995      # see the note above
            feed_window(gw, [1.0] * 5)
            await gw.tick()
            gw.state.posture.posture = Posture.NORMAL
            gw.state.posture.directive_floor = Posture.NORMAL

        check(srv.stats.echo_violations >= 1,
              f"echo violation raised (count {srv.stats.echo_violations})")
        check(len(srv.stats.alerts) >= 1, "SOC alert emitted")
        if srv.stats.alerts:
            print(f"           alert: {srv.stats.alerts[0]}")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def test_replay_rejected(tmp: Path) -> None:
    """A replayed telemetry frame must be dropped, not counted twice."""
    print("\n-- replayed telemetry frame rejected --")

    gw, srv, session = build(tmp)

    feed_window(gw, [230.0, 5.0, 35.0, 50.0, 1.0])
    batch = gw.aggregator.drain(now_ms(), 0)

    from uplink import build_frame
    from protocol import Header

    header = Header(
        node_id=GATEWAY_ID,
        key_epoch=gw.state.key_epoch,
        seq=gw.state.next_seq(),
        timestamp_ms=now_ms(),
        posture=Posture.NORMAL,
    )
    wire, _ = build_frame(bytes(gw.state.telemetry_key), header, batch.encode(), bytes(8))

    first = srv.handle_frame(wire)
    check(first is not None, "first delivery accepted")

    # A fresh session, so the ACCM chain matches; only the replay guard differs.
    second = srv.handle_frame(wire)
    check(second is None, "replayed frame rejected")
    check(session.stats.frames_replayed == 1, "replay counted")


async def test_rotation_followed(tmp: Path) -> None:
    """When the gateway rotates its key, the server must follow."""
    print("\n-- key rotation followed across the link --")

    gw, srv, session = build(tmp)
    server = await connect(gw, srv)

    try:
        feed_window(gw, [1.0] * 5)
        await gw.tick()
        epoch_before = session.key_epoch

        gw.state.rotate_uplink_keys()

        feed_window(gw, [1.0] * 5)
        await gw.tick()

        check(session.key_epoch > epoch_before,
              f"server adopted the new epoch ({epoch_before} -> {session.key_epoch})")
        check(srv.stats.frames_rejected == 0,
              "no frames lost across the rotation")
        check(session.stats.frames_auth_failed == 0,
              "the re-derived key opens the new frames")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def test_silent_server_escalates(tmp: Path) -> None:
    """The fail-secure path: no server, and the gateway escalates anyway."""
    print("\n-- silent server: gateway escalates on its own --")

    gw, srv, session = build(tmp)
    t0 = now_ms()
    gw.state.posture.grace(1000, t0)

    # No uplink at all — the server never answers.
    gw.uplink = None

    gw.state.posture.tick(t0 + 1500)
    check(gw.state.posture.posture == Posture.SUSPICIOUS, "one lapse -> SUSPICIOUS")

    gw.state.posture.tick(t0 + 3000)
    check(gw.state.posture.posture == Posture.ANOMALY, "two lapses -> ANOMALY")

    check(gw.state.posture.node_mask == 0,
          "lease expiry never auto-quarantines (no remote DoS)")


async def test_soak(tmp: Path) -> None:
    """60 ticks with a real detector, checking for drift and leaks."""
    print("\n-- 60-tick soak --")

    gw, srv, session = build(tmp, policy=ThresholdPolicy())
    server = await connect(gw, srv)

    try:
        for i in range(60):
            feed_window(gw, [230.0 + (i % 3) * 0.1, 5.0, 35.0, 50.0, 1.0])
            await gw.tick()

        check(srv.stats.batches_received == 60,
              f"all 60 batches arrived (got {srv.stats.batches_received})")
        check(srv.stats.frames_rejected == 0, "zero rejects across the soak")
        check(session.stats.frames_auth_failed == 0, "zero auth failures")
        check(gw.state.nonce_guard.next_seq == 60,
              f"exactly 60 sequence numbers consumed (got {gw.state.nonce_guard.next_seq})")
        check(srv.stats.echo_violations == 0, "no spurious echo violations")
        print(f"           last score {srv.last_score:.3f}, "
              f"detector latency {srv.detector.latency_ms:.3f} ms")
    finally:
        # Client first. server.wait_closed() waits for live handlers, and the
        # handler is blocked in readexactly() until the client gives it EOF.
        await gw.uplink.close()
        server.close()
        await server.wait_closed()


async def main_async(tmp: Path) -> None:
    await test_pipe(tmp / "a")
    await test_posture_round_trip(tmp / "b")
    await test_quarantine_round_trip(tmp / "c")
    await test_echo_violation(tmp / "d")
    await test_replay_rejected(tmp / "e")
    await test_rotation_followed(tmp / "f")
    await test_silent_server_escalates(tmp / "g")
    await test_soak(tmp / "h")


def main() -> int:
    print("=== server daemon: full pipe end-to-end ===")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for sub in "abcdefgh":
            (root / sub).mkdir()
        asyncio.run(main_async(root))

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
