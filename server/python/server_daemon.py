"""
server_daemon.py — the main server.

Closes the pipe. Accepts gateway connections, opens telemetry frames, runs the
detector, and answers each batch with a sealed control frame that renews the
lease.

Receive path
------------
    parse 24-byte header
      -> replay check                  reject replay or reorder
      -> adopt key_epoch if rotated    the gateway owns the epoch
      -> ACCM unmask                   header + prev_tail derive the keystream
      -> AES-GCM decrypt, AAD=header   posture and epoch authenticated here
      -> decode batch
      -> posture echo check            did the gateway do what it was told?

Response path
-------------
    detector score + attribution
      -> LeaseIssuer.decide
      -> seal under gw-ctrl
      -> write as the response to that batch

Frame opening is imported from the gateway's `uplink` module rather than
reimplemented. There is exactly one implementation of the frame format on the
Python side, so the two ends cannot drift apart — the same reasoning that put
the leaf link behind a cross-language KAT.
"""

from __future__ import annotations

import asyncio
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[2]
for _p in (
    _HERE,
    _REPO / "src" / "hardware" / "Gateway" / "python",
    _REPO / "src" / "security" / "ACCM" / "python",
    _REPO / "src" / "security" / "posture" / "python",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import posture_frame  # noqa: E402
from aggregator import Batch  # noqa: E402
from detector import Detector, StubDetector  # noqa: E402
from lease import LeaseIssuer, LeasePolicy  # noqa: E402
from protocol import Directive, Header, HEADER_LEN  # noqa: E402
from server_state import (  # noqa: E402
    CounterStore,
    EchoStatus,
    GatewaySession,
    ServerStateError,
)
from uplink import UplinkError, open_frame  # noqa: E402

MAX_FRAME = 1 << 20


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 9099
    echo_window_frames: int = 5
    max_clock_skew_ms: int = 3_600_000


@dataclass
class ServerStats:
    connections: int = 0
    batches_received: int = 0
    samples_received: int = 0
    frames_rejected: int = 0
    controls_sent: int = 0
    echo_violations: int = 0
    alerts: list[str] = field(default_factory=list)


class MainServer:
    """One instance per server process. Handles many gateways."""

    def __init__(
        self,
        sessions: dict[int, GatewaySession],
        detector: Detector | None = None,
        lease_policy: LeasePolicy | None = None,
        config: ServerConfig | None = None,
    ) -> None:
        self.sessions = sessions
        self.detector = detector or StubDetector()
        self.issuer = LeaseIssuer(lease_policy)
        self.config = config or ServerConfig()
        self.stats = ServerStats()
        self._server: asyncio.AbstractServer | None = None
        self.last_batch: Batch | None = None
        self.last_score: float = 0.0

    # ── framing ──────────────────────────────────────────────────────────

    @staticmethod
    async def _read_framed(reader: asyncio.StreamReader) -> bytes:
        raw_len = await reader.readexactly(4)
        (n,) = struct.unpack(">I", raw_len)
        if n > MAX_FRAME:
            raise UplinkError(f"frame length {n} exceeds sanity bound")
        return await reader.readexactly(n)

    @staticmethod
    async def _write_framed(writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(struct.pack(">I", len(payload)) + payload)
        await writer.drain()

    # ── one batch ────────────────────────────────────────────────────────

    def handle_frame(self, wire: bytes) -> tuple[GatewaySession, Batch] | None:
        """Open one telemetry frame. Returns None if it must be discarded."""
        if len(wire) < HEADER_LEN:
            self.stats.frames_rejected += 1
            return None

        try:
            header = Header.parse(wire[:HEADER_LEN])
        except Exception:
            self.stats.frames_rejected += 1
            return None

        session = self.sessions.get(header.node_id)
        if session is None:
            # An unknown gateway. Nothing to derive a key from, so there is
            # nothing to verify against either — drop it.
            self.stats.frames_rejected += 1
            return None

        if not session.replay.check(header):
            session.stats.frames_replayed += 1
            self.stats.frames_rejected += 1
            return None

        # The gateway owns key_epoch: it rotates, then sends under the new one.
        # Following is safe because the epoch is inside the AAD, so an attacker
        # cannot walk the server backwards onto a retired key.
        if header.key_epoch != session.key_epoch:
            session.adopt_key_epoch(header.key_epoch)

        try:
            _hdr, payload, session.accm_tail = open_frame(
                bytes(session.telemetry_key), wire, session.accm_tail
            )
        except UplinkError:
            session.stats.frames_auth_failed += 1
            self.stats.frames_rejected += 1
            return None

        try:
            batch = Batch.decode(payload)
        except Exception:
            # Authenticated but unparseable: a version skew, not an attack.
            session.stats.frames_auth_failed += 1
            self.stats.frames_rejected += 1
            return None

        status = session.check_echo(header)
        if status is EchoStatus.VIOLATED:
            self.stats.echo_violations += 1
            msg = (
                f"gateway {session.gateway_id:#06x} did not adopt the commanded "
                f"posture within {session.echo_window_frames} frames "
                f"(reports {header.posture.name})"
            )
            self.stats.alerts.append(msg)

        session.stats.frames_ok += 1
        self.stats.batches_received += 1
        self.stats.samples_received += batch.sample_count
        self.last_batch = batch
        return session, batch

    def build_response(self, session: GatewaySession, batch: Batch) -> bytes:
        """Score the batch and seal the control frame that answers it."""
        score = self.detector.score(batch)
        mask = self.detector.attribute(batch) if score > 0.0 else 0
        self.last_score = score

        ctrl = self.issuer.decide(score, mask, session, now_ms())

        # Only ENFORCE and QUARANTINE are commands the gateway must obey, so
        # only those start an echo window. ADVISE is an observation.
        if ctrl.directive in (Directive.ENFORCE, Directive.QUARANTINE):
            session.record_command(ctrl.posture)

        self.stats.controls_sent += 1
        return posture_frame.seal(
            bytes(session.control_key), session.ctrl_epoch, ctrl
        )

    # ── connection handling ──────────────────────────────────────────────

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.stats.connections += 1
        try:
            while True:
                try:
                    wire = await self._read_framed(reader)
                except (asyncio.IncompleteReadError, ConnectionError, UplinkError):
                    break

                opened = self.handle_frame(wire)
                if opened is None:
                    # Nothing to answer. Staying silent is correct: the lease
                    # decays, and the gateway escalates on its own. That is
                    # the fail-secure path, not a missing feature.
                    continue

                session, batch = opened
                await self._write_framed(writer, self.build_response(session, batch))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def serve_forever(self) -> None:
        self._server = await asyncio.start_server(
            self.handle_connection, self.config.host, self.config.port
        )
        async with self._server:
            await self._server.serve_forever()

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(
            self.handle_connection, self.config.host, self.config.port
        )
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for session in self.sessions.values():
            session.shutdown()


__all__ = ["MainServer", "ServerConfig", "ServerStats", "now_ms"]
