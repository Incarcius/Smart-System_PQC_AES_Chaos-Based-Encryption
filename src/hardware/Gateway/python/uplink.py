"""
uplink.py — the gateway -> server telemetry link and its control response.

Layer order, confirmed design: **ACCM sits OUTSIDE AES-GCM.**

    batch JSON
      -> AES-256-GCM   key = gw-telemetry, nonce = key_epoch||seq,
                       AAD = the 24-byte frame header
      -> ct || tag
      -> ACCM mask     XOR keystream over the complete ciphertext
      -> length-prefixed on TCP

TCP framing
-----------
A 4-byte big-endian length prefix, not COBS. TCP is reliable and ordered, so
there is nothing to resynchronise to: if the stream desynchronises, the
connection is already broken and reconnecting is the only correct response.
COBS earns its overhead on the UART, where a corrupted byte must not kill the
link; here it would buy nothing.

The piggybacked lease
---------------------
Every batch gets a response, and that response **is** the lease renewal. No
separate timer, no second connection — and a server that stops *responding*
decays the lease exactly like one that stops *renewing*, which is the property
that makes the fail-secure design work.
"""

from __future__ import annotations

import asyncio
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[4]
for _p in (
    _REPO / "src" / "security" / "ACCM" / "python",
    _REPO / "src" / "security" / "posture" / "python",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from accm import AccmContext  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from protocol import GCM_TAG_LEN, HEADER_LEN, Header, Posture, TAIL_LEN  # noqa: E402

import posture_frame  # noqa: E402

MAX_FRAME = 1 << 20  # 1 MiB; a batch that large means something is wrong


class UplinkError(Exception):
    """Link or authentication failure. The caller reconnects; it does not retry
    a frame, because the sequence number has already been consumed."""


@dataclass
class UplinkStats:
    frames_sent: int = 0
    frames_acked: int = 0
    control_accepted: int = 0
    control_rejected: int = 0
    bytes_sent: int = 0


def build_frame(
    telemetry_key: bytes,
    header: Header,
    payload: bytes,
    prev_tail: bytes,
) -> tuple[bytes, bytes]:
    """Seal one telemetry frame. Returns (wire bytes, new prev_tail).

    The header is cleartext but passed as AAD, which is what makes the posture
    and epoch fields unforgeable despite being readable — the receiver needs
    them to reproduce the ACCM keystream before it can unmask anything.
    """
    hdr = header.serialize()
    sealed = AESGCM(bytes(telemetry_key)).encrypt(header.nonce(), payload, hdr)

    ctx = AccmContext(bytes(telemetry_key), header, prev_tail)
    masked = ctx.mask(sealed)
    ctx.chain_update(masked)

    return hdr + masked, ctx.prev_tail


def open_frame(
    telemetry_key: bytes, wire: bytes, prev_tail: bytes
) -> tuple[Header, bytes, bytes]:
    """Inverse of build_frame. Returns (header, payload, new prev_tail).

    Used by the server, and by the tests to close the loop without one.
    """
    if len(wire) < HEADER_LEN + GCM_TAG_LEN:
        raise UplinkError("frame too short")

    header = Header.parse(wire[:HEADER_LEN])
    masked = wire[HEADER_LEN:]

    ctx = AccmContext(bytes(telemetry_key), header, prev_tail)
    sealed = ctx.unmask(masked)
    ctx.chain_update(masked)

    try:
        payload = AESGCM(bytes(telemetry_key)).decrypt(
            header.nonce(), sealed, wire[:HEADER_LEN]
        )
    except InvalidTag as exc:
        raise UplinkError("authentication failed") from exc

    return header, payload, ctx.prev_tail


class Uplink:
    """Owns the TCP connection and the ACCM chaining state for it."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.prev_tail = bytes(TAIL_LEN)
        self.stats = UplinkStats()
        self._last_key_epoch: int | None = None

    @classmethod
    async def connect(cls, host: str, port: int) -> "Uplink":
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def _write_framed(self, payload: bytes) -> None:
        self.writer.write(struct.pack(">I", len(payload)) + payload)
        await self.writer.drain()

    async def _read_framed(self, timeout: float | None = None) -> bytes:
        async def _read() -> bytes:
            raw_len = await self.reader.readexactly(4)
            (n,) = struct.unpack(">I", raw_len)
            if n > MAX_FRAME:
                raise UplinkError(f"frame length {n} exceeds sanity bound")
            return await self.reader.readexactly(n)

        try:
            if timeout is None:
                return await _read()
            return await asyncio.wait_for(_read(), timeout)
        except asyncio.IncompleteReadError as exc:
            raise UplinkError("connection closed mid-frame") from exc

    async def send_batch(
        self,
        telemetry_key: bytes,
        node_id: int,
        key_epoch: int,
        seq: int,
        posture: Posture,
        payload: bytes,
    ) -> None:
        """Seal and send one aggregation window."""
        # A key rotation is a re-synchronisation point for the ACCM chain, and
        # both ends must treat it as one: the server resets prev_tail when it
        # adopts a new key_epoch, so the gateway must too. Doing it here rather
        # than in the rotation handler means it holds however the rotation was
        # triggered -- policy action, forced by the shield, or directly on the
        # state object. Carrying the chain over would make the first frame
        # under the new key unmask to garbage and fail the GCM tag.
        if self._last_key_epoch is not None and key_epoch != self._last_key_epoch:
            self.prev_tail = bytes(TAIL_LEN)
        self._last_key_epoch = key_epoch

        header = Header(
            node_id=node_id,
            key_epoch=key_epoch,
            seq=seq,
            timestamp_ms=int(time.time() * 1000),
            posture=posture,
        )
        wire, self.prev_tail = build_frame(
            telemetry_key, header, payload, self.prev_tail
        )
        await self._write_framed(wire)
        self.stats.frames_sent += 1
        self.stats.bytes_sent += len(wire)

    async def recv_control(
        self, control_key: bytes, timeout: float = 2.0
    ):
        """Read the server's response: a sealed posture-control frame.

        Returns the parsed control message, or None if nothing arrived in time.
        A timeout is NOT an error — it is the lease decaying, which
        `PostureState.tick()` turns into an escalation on its own. That is the
        fail-secure path, so it must not raise.
        """
        try:
            wire = await self._read_framed(timeout)
        except (UplinkError, asyncio.TimeoutError):
            return None

        try:
            ctrl, _epoch = posture_frame.open_frame(bytes(control_key), wire)
        except Exception:
            # A forged or corrupt control frame. Count it and carry on — the
            # lease will lapse if the real server is genuinely unreachable.
            self.stats.control_rejected += 1
            return None

        self.stats.control_accepted += 1
        self.stats.frames_acked += 1
        return ctrl


__all__ = ["Uplink", "UplinkError", "UplinkStats", "build_frame", "open_frame"]
