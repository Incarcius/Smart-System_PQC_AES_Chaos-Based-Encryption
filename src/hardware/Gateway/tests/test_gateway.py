"""
test_gateway.py — end-to-end gateway daemon tests.

Runs the real daemon against a simulated ESP32 and a simulated server, both
over in-memory asyncio pipes. No UART, no socket, no board — but every layer
in between is the production code: the real handshake, the real AES-GCM, the
real ACCM mask, the real posture state machine, the real shield.

What is simulated: only the two peers.
What is real: everything the gateway itself does.

Usage (from repo root):
    python src/hardware/Gateway/tests/test_gateway.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_ROOT / "src" / "hardware" / "Gateway" / "python"))
sys.path.insert(0, str(_ROOT / "src" / "security" / "ACCM" / "python"))
sys.path.insert(0, str(_ROOT / "src" / "security" / "posture" / "python"))

import leaf_link as ll  # noqa: E402
import posture_frame  # noqa: E402
from aggregator import Batch  # noqa: E402
from daemon import DaemonConfig, GatewayDaemon, now_ms  # noqa: E402
from gateway_state import EpochStore, GatewayState  # noqa: E402
from policy import (  # noqa: E402
    Action,
    FixedIntervalPolicy,
    Observation,
    Shield,
    ThresholdPolicy,
)
from protocol import Control, Directive, Posture, SEQ_MAX  # noqa: E402
from uplink import Uplink, open_frame  # noqa: E402

failures = 0
checks = 0

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


def make_state(tmp: Path, now: int) -> GatewayState:
    state = GatewayState(
        gateway_id=1,
        epoch_store=EpochStore(tmp / "epochs.json"),
        leaf_psks={ENDPOINT: PSK},
        now_ms=now,
    )
    state.install_root_key(ROOT_KEY, TRANSCRIPT)
    return state


# ── a simulated ESP32, using the same Python leaf-link module ───────────────


class SimulatedLeaf:
    """Plays the leaf role. The C firmware does this for real; here the same
    wire format is driven from Python so the test needs no board."""

    def __init__(self, endpoint_id: int, psk: bytes, key_epoch: int = 1):
        from cryptography.hazmat.primitives.asymmetric import x25519

        self.endpoint_id = endpoint_id
        self.psk = psk
        self.key_epoch = key_epoch
        self.seq = 0
        self.session = None
        self._x25519 = x25519

    def hello(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self._sk = self._x25519.X25519PrivateKey.generate()
        pub = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        h = bytearray(ll.HELLO_LEN)
        h[0] = ll.LEAF_PROTO_VERSION
        h[1] = ll.MSG_HELLO
        h[2:4] = self.endpoint_id.to_bytes(2, "big")
        h[4:8] = self.key_epoch.to_bytes(4, "big")
        h[8:40] = pub
        h[40:72] = os.urandom(32)
        self._hello = bytes(h)
        return self._hello

    def finish(self, ack: bytes) -> bytes:
        gw_pub = self._x25519.X25519PublicKey.from_public_bytes(ack[8:40])
        dh = self._sk.exchange(gw_pub)
        self.session = ll._derive_session(self._hello, ack, dh, self.psk)

        c = bytearray(ll.CONFIRM_LEN)
        c[0] = ll.LEAF_PROTO_VERSION
        c[1] = ll.MSG_CONFIRM
        c[2:4] = self.endpoint_id.to_bytes(2, "big")
        c[8:24] = ll.confirm_tag(self.session)
        return bytes(c)

    def telemetry(self, values: list[float], ts: int) -> bytes:
        hdr = ll.LeafHeader(
            endpoint_id=self.endpoint_id,
            key_epoch=self.key_epoch,
            seq=self.seq,
            channel_count=len(values),
        )
        self.seq += 1
        readings = [ll.ChannelReading(v, 0) for v in values]
        return ll.seal_frame(self.session.session_key, hdr, ts, readings)


def framed(payload: bytes) -> bytes:
    return ll.cobs_encode(payload) + b"\x00"


# ── tests ───────────────────────────────────────────────────────────────────


async def test_leaf_to_gateway(tmp: Path) -> None:
    """Handshake, then telemetry, ending up in the aggregator."""
    print("\n-- leaf -> gateway --")

    state = make_state(tmp, now_ms())
    daemon = GatewayDaemon(state, FixedIntervalPolicy(interval_ticks=10**9))
    daemon._running = True

    leaf = SimulatedLeaf(ENDPOINT, PSK)

    # A writer that just records what the gateway sends back.
    sent: list[bytes] = []

    class FakeWriter:
        def write(self, b):
            sent.append(b)

        async def drain(self):
            pass

    writer = FakeWriter()

    await daemon._handle_leaf_frame(leaf.hello(), writer)
    check(daemon.stats.handshakes == 1, "gateway answered HELLO")
    check(len(sent) == 1, "gateway sent a HELLO_ACK")

    ack = ll.cobs_decode(sent[0][:-1])
    confirm = leaf.finish(ack)
    await daemon._handle_leaf_frame(confirm, writer)

    gw_key = bytes(state.leaf(ENDPOINT).session_key)
    check(
        gw_key == leaf.session.session_key,
        "gateway and leaf derived the same session key",
    )

    ts = now_ms()
    for i in range(10):
        await daemon._handle_leaf_frame(leaf.telemetry([230.0, 5.0, 35.0, 50.0, 1.0], ts + i * 100), writer)

    check(daemon.stats.leaf_frames_ok == 10, f"10 telemetry frames accepted (got {daemon.stats.leaf_frames_ok})")
    check(daemon.aggregator.pending == 50, f"50 samples buffered (got {daemon.aggregator.pending})")

    # A replayed frame must be rejected, not double-counted.
    replay = leaf.telemetry([230.0, 5.0, 35.0, 50.0, 1.0], ts)
    leaf.seq -= 1
    replay2 = leaf.telemetry([230.0, 5.0, 35.0, 50.0, 1.0], ts)
    await daemon._handle_leaf_frame(replay, writer)
    before = daemon.stats.leaf_frames_ok
    await daemon._handle_leaf_frame(replay2, writer)
    check(daemon.stats.leaf_frames_ok == before, "replayed leaf frame rejected")

    # A tampered frame must fail authentication and be counted.
    bad = bytearray(leaf.telemetry([1.0] * 5, ts))
    bad[30] ^= 0x01
    before_bad = state.window_auth_failures
    await daemon._handle_leaf_frame(bytes(bad), writer)
    check(
        state.window_auth_failures == before_bad + 1,
        "tampered leaf frame counted as an auth failure",
    )


async def test_gateway_to_server(tmp: Path) -> None:
    """A full uplink round trip: batch out, lease back."""
    print("\n-- gateway -> server, with the piggybacked lease --")

    state = make_state(tmp, now_ms())
    daemon = GatewayDaemon(state, FixedIntervalPolicy(interval_ticks=10**9))
    daemon._running = True

    gw_reader, srv_writer = _pipe()
    srv_reader, gw_writer = _pipe()
    daemon.uplink = Uplink(gw_reader, gw_writer)

    # Feed a window of samples.
    from aggregator import Sample

    t = now_ms()
    for c in range(5):
        daemon.aggregator.add(Sample(ENDPOINT, c, 100.0 + c, 0, t))

    server_tail = bytes(8)
    ctrl_seq = 1

    async def server():
        nonlocal server_tail, ctrl_seq
        import struct

        raw_len = await srv_reader.readexactly(4)
        (n,) = struct.unpack(">I", raw_len)
        wire = await srv_reader.readexactly(n)

        header, payload, server_tail = open_frame(
            bytes(state.telemetry_key), wire, server_tail
        )
        batch = Batch.decode(payload)

        ctrl = Control(
            min_hold_ms=1000,
            ctrl_seq=ctrl_seq,
            issued_ms=now_ms(),
            lease_ms=3000,
            posture=Posture.NORMAL,
            directive=Directive.ADVISE,
        )
        ctrl_seq += 1
        frame = posture_frame.seal(bytes(state.control_key), 1, ctrl)
        srv_writer.write(struct.pack(">I", len(frame)) + frame)
        await srv_writer.drain()
        return header, batch

    task = asyncio.create_task(server())
    await daemon.tick()
    header, batch = await task

    check(header.node_id == 1, "server received the gateway's frame")
    check(header.posture == Posture.NORMAL, "posture carried in the header")
    check(len(batch.trusted) == 5, f"5 trusted samples arrived (got {len(batch.trusted)})")
    check(batch.silent_channels == [], "no channels reported silent")
    check(daemon.stats.batches_sent == 1, "one batch sent")

    lease_left = state.posture.lease_expires_ms - now_ms()
    check(lease_left > 2000, f"lease renewed by the response ({lease_left} ms left)")


async def test_quarantine_isolates(tmp: Path) -> None:
    """A quarantined channel keeps flowing, but into the untrusted buffer."""
    print("\n-- quarantine isolates without stopping the link --")

    from aggregator import Sample

    state = make_state(tmp, now_ms())
    daemon = GatewayDaemon(state, FixedIntervalPolicy(interval_ticks=10**9))

    t = now_ms()
    ctrl = Control(
        min_hold_ms=0,
        ctrl_seq=1,
        issued_ms=t,
        lease_ms=3000,
        posture=Posture.ANOMALY,
        directive=Directive.QUARANTINE,
        node_mask=0b00100,          # channel 2
    )
    state.posture.apply(ctrl, t, 3_600_000)

    for c in range(5):
        daemon.aggregator.add(Sample(ENDPOINT, c, 10.0 * c, 0, t))

    batch = daemon.aggregator.drain(t, state.posture.node_mask)

    check(len(batch.trusted) == 4, f"4 channels stay trusted (got {len(batch.trusted)})")
    check(len(batch.untrusted) == 1, f"1 channel quarantined (got {len(batch.untrusted)})")
    check(
        batch.untrusted[0].channel_id == 2,
        "the quarantined channel is the flagged one",
    )
    check(
        state.posture.is_quarantined(2) and not state.posture.is_quarantined(1),
        "quarantine applies to the named channel only",
    )


def test_shield() -> None:
    """The shield must override the policy, not merely advise it."""
    print("\n-- shield --")

    shield = Shield()
    t = now_ms()

    obs = Observation(seq_used=int(0.95 * SEQ_MAX), n_channels=5)
    d = shield.apply(Action.HOLD, obs, t)
    check(
        d.action == Action.ROTATE_SESSION_KEY and d.forced,
        "nonce exhaustion forces a rotation over the policy's HOLD",
    )

    shield2 = Shield()
    obs2 = Observation(n_channels=5)
    blocked = 0
    for i in range(12):
        d = shield2.apply(Action.ROTATE_SESSION_KEY, obs2, t + i)
        if d.blocked:
            blocked += 1
    check(blocked > 0, f"rotation rate limit engages ({blocked} blocked of 12)")

    shield3 = Shield()
    obs3 = Observation(posture=int(Posture.NORMAL), n_channels=5)
    d = shield3.apply(Action.QUARANTINE_WORST_CHANNEL, obs3, t)
    check(d.blocked, "quarantine blocked below ANOMALY posture")

    obs4 = Observation(posture=int(Posture.ANOMALY), n_channels=5)
    d = shield3.apply(Action.QUARANTINE_WORST_CHANNEL, obs4, t)
    check(not d.blocked, "quarantine allowed at ANOMALY posture")

    shield5 = Shield()
    obs5 = Observation(key_age_ms=25 * 3_600_000, n_channels=5)
    d = shield5.apply(Action.HOLD, obs5, t)
    check(d.forced and d.action == Action.ROTATE_SESSION_KEY, "crypto period forces rotation")


def test_threshold_policy() -> None:
    print("\n-- threshold baseline --")

    p = ThresholdPolicy()
    check(
        p.decide(Observation(lstm_score=0.9, posture=int(Posture.NORMAL)))
        == Action.ROTATE_SESSION_KEY,
        "rotates on entering an alarm state",
    )
    check(
        p.decide(Observation(lstm_score=0.9, posture=int(Posture.SUSPICIOUS)))
        == Action.ESCALATE_POSTURE,
        "escalates once already alarmed",
    )
    check(
        p.decide(Observation(lstm_score=0.1, posture=int(Posture.ANOMALY)))
        == Action.DEESCALATE_POSTURE,
        "de-escalates when the score falls",
    )
    check(
        p.decide(Observation(gcm_auth_fail_rate=0.5, posture=int(Posture.NORMAL)))
        == Action.ESCALATE_POSTURE,
        "acts on GCM auth failures with no detector at all",
    )


async def test_lease_expiry_escalates(tmp: Path) -> None:
    """The fail-secure path: a silent server escalates the gateway on its own."""
    print("\n-- lease expiry escalates (fail-secure) --")

    state = make_state(tmp, now_ms())
    daemon = GatewayDaemon(
        state, FixedIntervalPolicy(interval_ticks=10**9),
        DaemonConfig(lease_grace_ms=1000),
    )
    daemon._running = True

    t0 = now_ms()
    state.posture.grace(1000, t0)
    check(state.posture.posture == Posture.NORMAL, "starts at NORMAL")

    state.posture.tick(t0 + 1500)
    check(state.posture.posture == Posture.SUSPICIOUS, "one lapse -> SUSPICIOUS")

    state.posture.tick(t0 + 3000)
    check(state.posture.posture == Posture.ANOMALY, "two lapses -> ANOMALY")

    check(state.posture.node_mask == 0, "lease expiry never auto-quarantines")


# ── in-memory asyncio pipe ──────────────────────────────────────────────────


def _pipe() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A connected reader/writer pair with no socket underneath."""
    reader = asyncio.StreamReader()

    class _Transport(asyncio.Transport):
        def __init__(self):
            super().__init__()
            self._closing = False

        def write(self, data):
            reader.feed_data(data)

        def close(self):
            self._closing = True
            reader.feed_eof()

        def is_closing(self):
            return self._closing

    class _Proto(asyncio.streams.FlowControlMixin, asyncio.Protocol):
        pass

    writer = asyncio.StreamWriter(
        _Transport(), _Proto(), reader, asyncio.get_event_loop()
    )
    return reader, writer


async def main_async(tmp: Path) -> None:
    await test_leaf_to_gateway(tmp)
    await test_gateway_to_server(tmp)
    await test_quarantine_isolates(tmp)
    await test_lease_expiry_escalates(tmp)


def main() -> int:
    print("=== gateway daemon: end-to-end ===")
    with tempfile.TemporaryDirectory() as td:
        asyncio.run(main_async(Path(td)))
    test_shield()
    test_threshold_policy()

    print()
    print(f"{checks - failures}/{checks} checks passed")
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
