"""
daemon.py — the gateway application layer.

This is the process that was missing: it reads sensors, holds the session
pool, opens a socket, and runs the policy. Everything below it (crypto,
protocol, posture) already existed and was tested; this is what finally calls
any of it.

Concurrency
-----------
asyncio, with two tasks:

  * `leaf_task` — continuous. COBS-deframes the UART, opens leaf frames,
    replay-checks them, feeds the aggregator. Runs at the leaf's 10 Hz.
  * `tick_task` — 1 Hz. Closes the aggregation window, sends the batch,
    reads the lease response, then runs the policy.

The DQN forward pass belongs in a thread executor when it lands — it is
CPU-bound and would otherwise stall the event loop. The hook is marked below.

Transports are injected as asyncio stream pairs rather than opened here, so
the whole daemon runs against in-memory pipes in the tests with no UART and no
socket. That is what makes an end-to-end test possible before any hardware.
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

_REPO = _HERE.parents[3]
_ACCM = _REPO / "src" / "security" / "ACCM" / "python"
if str(_ACCM) not in sys.path:
    sys.path.insert(0, str(_ACCM))

import leaf_link as ll  # noqa: E402
from aggregator import Aggregator  # noqa: E402
from gateway_state import GatewayState, GatewayStateError  # noqa: E402
from policy import Action, Observation, Shield  # noqa: E402
from protocol import Directive, Posture, TAIL_LEN  # noqa: E402
from uplink import Uplink  # noqa: E402


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class DaemonConfig:
    gateway_node_id: int = 1
    tick_ms: int = 1000
    lease_grace_ms: int = 5000      # startup window before the first renewal
    control_timeout_s: float = 2.0
    n_channels: int = 5
    # Generous: SCADA gateways are not always NTP-tight, and the monotonic
    # ctrl_seq is the real replay defence. This is a secondary sanity bound.
    max_clock_skew_ms: int = 3_600_000


@dataclass
class DaemonStats:
    ticks: int = 0
    batches_sent: int = 0
    leaf_frames_ok: int = 0
    leaf_frames_bad: int = 0
    handshakes: int = 0
    rotations: int = 0
    actions_blocked: int = 0
    actions_forced: int = 0
    last_action: str = "none"
    posture_changes: list[tuple[int, int]] = field(default_factory=list)


class GatewayDaemon:
    """Wires the components together. One instance per gateway process."""

    def __init__(
        self,
        state: GatewayState,
        policy,
        config: DaemonConfig | None = None,
        detector=None,
    ) -> None:
        self.state = state
        self.policy = policy
        self.config = config or DaemonConfig()
        self.detector = detector          # None until the LSTM lands
        self.shield = Shield()
        self.aggregator = Aggregator(expected_channels=set(range(self.config.n_channels)))
        self.stats = DaemonStats()

        self.uplink: Uplink | None = None
        self._running = False
        self._key_installed_ms = now_ms()
        self._last_root_ms = now_ms()
        self._bytes_under_key = 0
        self._rotations_this_window = 0
        self._ewma_fast = 0.0
        self._ewma_slow = 0.0

        # A gateway holds no lease at startup, so the very first tick would
        # escalate it. Grant a grace window for the server's first renewal.
        self.state.posture.grace(self.config.lease_grace_ms, now_ms())

    # ── leaf side ────────────────────────────────────────────────────────

    async def serve_leaf(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle one ESP32: handshake, then telemetry until it goes away."""
        buf = bytearray()

        while self._running:
            try:
                chunk = await reader.read(256)
            except (ConnectionError, OSError):
                break
            if not chunk:
                break

            buf.extend(chunk)

            # COBS frames are 0x00-delimited.
            while True:
                idx = buf.find(0)
                if idx < 0:
                    break
                raw, buf = bytes(buf[:idx]), buf[idx + 1 :]
                if not raw:
                    continue
                try:
                    frame = ll.cobs_decode(raw)
                except ll.LeafLinkError:
                    # Corrupted on the wire. Drop it; the next delimiter
                    # resynchronises us. This is why COBS was chosen.
                    self.stats.leaf_frames_bad += 1
                    continue

                await self._handle_leaf_frame(frame, writer)

    async def _handle_leaf_frame(self, frame: bytes, writer) -> None:
        # HELLO starts a handshake; anything else is telemetry.
        if len(frame) == ll.HELLO_LEN and frame[1] == ll.MSG_HELLO:
            await self._handle_hello(frame, writer)
            return

        if len(frame) == ll.CONFIRM_LEN and frame[1] == ll.MSG_CONFIRM:
            self._handle_confirm(frame)
            return

        self._handle_telemetry(frame)

    async def _handle_hello(self, hello: bytes, writer) -> None:
        endpoint_id = int.from_bytes(hello[2:4], "big")
        try:
            psk = self.state.psk_for(endpoint_id)
        except GatewayStateError:
            # No PSK provisioned. Refusing is correct: answering would mean an
            # unauthenticated session that a MITM could own.
            self.stats.leaf_frames_bad += 1
            return

        try:
            session, ack = ll.respond(psk, hello)
        except ll.LeafLinkError:
            self.stats.leaf_frames_bad += 1
            return

        leaf = self.state.leaf(endpoint_id)
        leaf.install(session.session_key)
        self._pending_session = session
        self.stats.handshakes += 1

        writer.write(ll.cobs_encode(ack) + b"\x00")
        await writer.drain()

    def _handle_confirm(self, confirm: bytes) -> None:
        session = getattr(self, "_pending_session", None)
        if session is None:
            return
        try:
            ll.verify_confirm(session, confirm)
        except ll.LeafLinkError:
            # The leaf derived a different key: a MITM, or a PSK mismatch.
            # Tear the session down rather than accept frames we cannot trust.
            self.state.leaf(session.endpoint_id).wipe()
            self.stats.leaf_frames_bad += 1

    def _handle_telemetry(self, frame: bytes) -> None:
        if len(frame) < ll.LEAF_HEADER_LEN:
            self.stats.leaf_frames_bad += 1
            return

        endpoint_id = int.from_bytes(frame[2:4], "big")
        leaf = self.state.leaf(endpoint_id)
        if not leaf.established:
            self.stats.leaf_frames_bad += 1
            return

        try:
            header, ts, readings = ll.open_frame(bytes(leaf.session_key), frame)
        except ll.LeafLinkError:
            # Authentication failure. The single best free intrusion signal the
            # gateway has: normal operation produces exactly zero of these.
            leaf.auth_failures += 1
            self.state.window_auth_failures += 1
            self.stats.leaf_frames_bad += 1
            return

        from protocol import Header as UplinkHeader  # local: name clash
        if not leaf.replay.check(
            UplinkHeader(
                node_id=header.endpoint_id,
                key_epoch=header.key_epoch,
                seq=header.seq,
                timestamp_ms=ts,
            )
        ):
            leaf.frames_ok += 0
            self.state.window_replay_rejects += 1
            self.stats.leaf_frames_bad += 1
            return

        leaf.frames_ok += 1
        leaf.last_seen_ms = ts
        self.stats.leaf_frames_ok += 1
        self.aggregator.add_frame(endpoint_id, ts, readings)

    # ── uplink side ──────────────────────────────────────────────────────

    async def tick(self) -> None:
        """One 1 Hz cycle: aggregate, send, take the lease, run the policy."""
        t = now_ms()
        self.stats.ticks += 1

        # Lease expiry escalates on its own, whatever the policy thinks.
        if self.state.posture.tick(t):
            self.stats.posture_changes.append((t, int(self.state.posture.posture)))

        batch = self.aggregator.drain(t, self.state.posture.node_mask)

        if self.uplink is not None and self.state.telemetry_key is not None:
            await self._send_and_receive(batch, t)

        obs = self._observe(batch, t)
        self._run_policy(obs, t)

        self.state.reset_window_counters()
        self._rotations_this_window = 0

    async def _send_and_receive(self, batch, t: int) -> None:
        payload = batch.encode()
        try:
            seq = self.state.next_seq()
        except Exception:
            # Sequence space exhausted. The shield forces a rotation next tick;
            # skipping this batch is far better than reusing a nonce.
            return

        await self.uplink.send_batch(
            bytes(self.state.telemetry_key),
            self.config.gateway_node_id,
            self.state.key_epoch,
            seq,
            Posture(self.state.posture.posture),
            payload,
        )
        self._bytes_under_key += len(payload)
        self.stats.batches_sent += 1

        ctrl = await self.uplink.recv_control(
            bytes(self.state.control_key), self.config.control_timeout_s
        )
        if ctrl is None:
            return
        if not self.state.accept_ctrl_seq(ctrl.ctrl_seq):
            return

        before = int(self.state.posture.posture)
        self.state.posture.apply(ctrl, t, self.config.max_clock_skew_ms)
        if int(self.state.posture.posture) != before:
            self.stats.posture_changes.append((t, int(self.state.posture.posture)))

    # ── policy ───────────────────────────────────────────────────────────

    def _observe(self, batch, t: int) -> Observation:
        score = 0.0
        if self.detector is not None:
            score = float(self.detector.score(batch))

        self._ewma_fast = 0.3 * score + 0.7 * self._ewma_fast
        self._ewma_slow = 0.05 * score + 0.95 * self._ewma_slow

        frames = max(self.stats.leaf_frames_ok + self.stats.leaf_frames_bad, 1)
        p = self.state.posture

        return Observation(
            lstm_score=score,
            lstm_ewma_fast=self._ewma_fast,
            lstm_ewma_slow=self._ewma_slow,
            posture=int(p.posture),
            time_in_posture_ms=t - p.posture_since_ms,
            lease_remaining_ms=max(0, p.lease_expires_ms - t),
            lease_ms=p.lease_ms,
            time_since_ctrl_ms=t - p.posture_since_ms,
            directive_floor=int(p.directive_floor),
            quarantined_channels=bin(p.node_mask).count("1"),
            ctrl_reject_rate=self.state.window_ctrl_rejects / frames,
            seq_used=self.state.nonce_guard.next_seq if self.state.nonce_guard else 0,
            key_age_ms=t - self._key_installed_ms,
            bytes_under_key=self._bytes_under_key,
            time_since_root_ms=t - self._last_root_ms,
            rotations_in_window=self._rotations_this_window,
            gcm_auth_fail_rate=self.state.window_auth_failures / frames,
            replay_reject_rate=self.state.window_replay_rejects / frames,
            silent_channels=len(batch.silent_channels),
            queue_depth=self.aggregator.pending,
            n_channels=self.config.n_channels,
        )

    def _run_policy(self, obs: Observation, t: int) -> None:
        # DQN hook: when the agent lands, run its forward pass in a thread
        # executor. It is CPU-bound and would otherwise stall the event loop.
        proposed = self.policy.decide(obs)
        decision = self.shield.apply(proposed, obs, t)

        if decision.blocked:
            self.stats.actions_blocked += 1
        if decision.forced:
            self.stats.actions_forced += 1
        self.stats.last_action = decision.action.name

        self._execute(decision.action, t)

    def _execute(self, action: Action, t: int) -> None:
        p = self.state.posture

        if action in (Action.ROTATE_SESSION_KEY, Action.REFRESH_POOL):
            self.state.rotate_uplink_keys()

            self._key_installed_ms = t
            self._bytes_under_key = 0
            self._rotations_this_window += 1
            self.stats.rotations += 1

        elif action == Action.ESCALATE_POSTURE:
            p.request(min(int(p.posture) + 1, int(Posture.ANOMALY)), t)

        elif action == Action.DEESCALATE_POSTURE:
            p.request(max(int(p.posture) - 1, int(Posture.NORMAL)), t)

        elif action == Action.REQUEST_ROOT_KEY:
            # Wired when the server daemon exists (Phase E); the shield already
            # rate-limits it at the measured 91 ms cost.
            self._last_root_ms = t

        # QUARANTINE and FORCE_FLUSH act through the control plane and the
        # aggregator respectively; both are no-ops until Phase E answers.

    # ── lifecycle ────────────────────────────────────────────────────────

    async def run(self, leaf_streams=None, uplink: Uplink | None = None) -> None:
        self._running = True
        self.uplink = uplink
        tasks = [asyncio.create_task(self._tick_loop())]

        if leaf_streams is not None:
            reader, writer = leaf_streams
            tasks.append(asyncio.create_task(self.serve_leaf(reader, writer)))

        try:
            await asyncio.gather(*tasks)
        finally:
            self._running = False

    async def _tick_loop(self) -> None:
        period = self.config.tick_ms / 1000.0
        while self._running:
            await asyncio.sleep(period)
            await self.tick()

    def stop(self) -> None:
        self._running = False


__all__ = ["GatewayDaemon", "DaemonConfig", "DaemonStats", "now_ms"]
