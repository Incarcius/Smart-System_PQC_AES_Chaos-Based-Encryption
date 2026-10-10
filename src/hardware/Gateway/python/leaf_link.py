"""
leaf_link.py — the gateway's view of the ESP32 link.

Python mirror of the C leaf firmware: COBS framing, telemetry frame opening,
and the gateway half of the PSK+DHE handshake. The ESP32 runs the C
implementation in `src/hardware/ESP32/`; this must agree with it byte for byte,
which `tests/test_leaf_link.py` pins.

Why the gateway is Python while the leaf is C
---------------------------------------------
The leaf has a 100 ms sampling budget on a 240 MHz microcontroller, so it runs
C. The gateway has a 1 s aggregation window on a Raspberry Pi, where the
measured Python cost is ~3% of budget (docs/REMAINING_WORK.md §0c) and the DQN
and LSTM live in the same process. Different constraints, different answers.

Interop is not assumed, it is tested: the cross-language KAT compares C output
against this module on every build.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

_REPO = Path(__file__).resolve().parents[4]
for _p in (
    _REPO / "temp_codes" / "RXCR-KMAC-KDF",
    _REPO / "temp_codes" / "pqcrypto_project" / "pqcrypto_project",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from python.kdf import rxcr_kdf  # noqa: E402
from python.kmac import kmacxof256  # noqa: E402
from python.rxcr import rxcr_extract  # noqa: E402

# ── constants, mirroring node_frame.h / node_session.h ──────────────────────

LEAF_PROTO_VERSION = 0x01
LEAF_HEADER_LEN = 16
LEAF_NONCE_LEN = 12
LEAF_TAG_LEN = 16
LEAF_KEY_LEN = 32

NODE_MAX_CHANNELS = 32
NODE_PSK_LEN = 32
NODE_PUBKEY_LEN = 32
NODE_HS_NONCE_LEN = 32

MSG_HELLO = 0x01
MSG_HELLO_ACK = 0x02
MSG_CONFIRM = 0x03

HELLO_LEN = 72
HELLO_ACK_LEN = 72
CONFIRM_LEN = 24

KDF_INFO = b"leaf-session/v1"
KDF_ALGO = b"AES-GCM"
CONFIRM_CTX = b"leaf-confirm/v1"


class LeafLinkError(Exception):
    """Frame or handshake failure. Never leaks which check failed to the peer."""


# ── COBS ────────────────────────────────────────────────────────────────────


def cobs_encode(data: bytes) -> bytes:
    """Mirror of cobs_encode(). Output contains no 0x00; caller adds the
    delimiter."""
    out = bytearray()
    code_i = 0
    out.append(0)  # placeholder for the first code byte
    code = 1

    for b in data:
        if b == 0:
            out[code_i] = code
            code_i = len(out)
            out.append(0)
            code = 1
            continue
        out.append(b)
        code += 1
        if code == 0xFF:
            out[code_i] = code
            code_i = len(out)
            out.append(0)
            code = 1

    out[code_i] = code
    return bytes(out)


def cobs_decode(data: bytes) -> bytes:
    """Mirror of cobs_decode(). Raises on a malformed frame rather than
    returning partial output — a corrupted frame must be dropped, not guessed
    at."""
    out = bytearray()
    i = 0
    n = len(data)

    while i < n:
        code = data[i]
        if code == 0:
            raise LeafLinkError("COBS: zero code byte")
        if i + code > n:
            raise LeafLinkError("COBS: code runs past end of frame")
        i += 1
        out.extend(data[i : i + code - 1])
        i += code - 1
        if code != 0xFF and i < n:
            out.append(0)

    return bytes(out)


# ── telemetry frame ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LeafHeader:
    endpoint_id: int
    key_epoch: int
    seq: int
    channel_count: int
    version: int = LEAF_PROTO_VERSION

    def serialize(self) -> bytes:
        return struct.pack(
            ">BBHIQ",
            self.version,
            self.channel_count,
            self.endpoint_id,
            self.key_epoch,
            self.seq,
        )

    @classmethod
    def parse(cls, raw: bytes) -> "LeafHeader":
        if len(raw) != LEAF_HEADER_LEN:
            raise LeafLinkError(f"header must be {LEAF_HEADER_LEN} bytes")
        version, count, endpoint_id, epoch, seq = struct.unpack(">BBHIQ", raw)
        if version != LEAF_PROTO_VERSION:
            raise LeafLinkError(f"unsupported leaf version {version:#x}")
        if count == 0 or count > NODE_MAX_CHANNELS:
            raise LeafLinkError(f"channel count out of range: {count}")
        return cls(endpoint_id, epoch, seq, count, version)

    def nonce(self) -> bytes:
        """key_epoch(4 BE) || seq(8 BE) — same construction as the uplink."""
        return struct.pack(">IQ", self.key_epoch, self.seq)


@dataclass(frozen=True)
class ChannelReading:
    value: float
    quality: int


def frame_len(channel_count: int) -> int:
    return LEAF_HEADER_LEN + 8 + 8 * channel_count + LEAF_TAG_LEN


def open_frame(
    key: bytes, frame: bytes
) -> tuple[LeafHeader, int, list[ChannelReading]]:
    """Verify and unpack a leaf telemetry frame.

    Mirror of tg_leaf_frame_open(). The 16-byte header is the AES-GCM AAD, so
    a flipped bit in endpoint_id, key_epoch or seq fails the tag rather than
    silently steering the decryption.
    """
    if len(frame) < frame_len(1):
        raise LeafLinkError("frame too short")

    header = LeafHeader.parse(frame[:LEAF_HEADER_LEN])

    expected = frame_len(header.channel_count)
    if len(frame) != expected:
        # Checked before decrypting so a forged header cannot steer the
        # payload length. The count is authenticated anyway, via the AAD.
        raise LeafLinkError(
            f"length {len(frame)} does not match channel_count {header.channel_count}"
        )

    payload_len = 8 + 8 * header.channel_count
    ct = frame[LEAF_HEADER_LEN : LEAF_HEADER_LEN + payload_len]
    tag = frame[LEAF_HEADER_LEN + payload_len :]

    try:
        payload = AESGCM(key).decrypt(
            header.nonce(), ct + tag, frame[:LEAF_HEADER_LEN]
        )
    except InvalidTag as exc:
        # Tampering, a forged frame, or a sender whose key schedule has
        # desynchronised. The gateway counts these: a burst is the cheapest
        # intrusion signal it has, and feeds gcm_auth_fail_rate in the DQN
        # state vector.
        raise LeafLinkError("authentication failed") from exc

    timestamp_ms = struct.unpack(">Q", payload[:8])[0]
    readings = []
    for i in range(header.channel_count):
        slot = payload[8 + 8 * i : 16 + 8 * i]
        quality = slot[1]
        (value,) = struct.unpack(">f", slot[4:8])
        readings.append(ChannelReading(value, quality))

    return header, timestamp_ms, readings


def seal_frame(
    key: bytes,
    header: LeafHeader,
    timestamp_ms: int,
    readings: list[ChannelReading],
) -> bytes:
    """Build a frame. Only the tests need this — the leaf seals in production —
    but having it here lets the gateway generate traffic for soak runs without
    a board attached."""
    if header.channel_count != len(readings):
        raise LeafLinkError("channel_count does not match readings")

    hdr = header.serialize()
    payload = bytearray(struct.pack(">Q", timestamp_ms))
    for i, r in enumerate(readings):
        payload += bytes([i, r.quality, 0, 0]) + struct.pack(">f", r.value)

    return hdr + AESGCM(key).encrypt(header.nonce(), bytes(payload), hdr)


# ── handshake, gateway role ─────────────────────────────────────────────────


@dataclass
class LeafSession:
    session_key: bytes
    transcript: bytes
    endpoint_id: int
    key_epoch: int


def _derive_session(
    hello: bytes, ack: bytes, dh: bytes, psk: bytes
) -> LeafSession:
    """Mirror of derive_session() in node_session.c.

    transcript = SHA3-256(HELLO || HELLO_ACK)   — both fixed length
    ikm        = dh || psk                      — DH first
    """
    transcript = hashlib.sha3_256(hello + ack).digest()
    ikm = dh + psk
    endpoint_id = struct.unpack(">H", hello[2:4])[0]
    node_id = struct.pack(">H", endpoint_id)

    pool = rxcr_kdf(
        ikm,
        transcript,
        KDF_INFO,
        [{"node_id": node_id, "algo": KDF_ALGO, "key_len": LEAF_KEY_LEN}],
    )

    return LeafSession(
        session_key=pool[node_id],
        transcript=transcript,
        endpoint_id=endpoint_id,
        key_epoch=struct.unpack(">I", hello[4:8])[0],
    )


def confirm_tag(session: LeafSession) -> bytes:
    return kmacxof256(session.session_key, session.transcript, 16, CONFIRM_CTX)


def respond(psk: bytes, hello: bytes) -> tuple[LeafSession, bytes]:
    """Consume HELLO, produce HELLO_ACK, derive the session key.

    Mirror of node_handshake_respond(). The gateway's DH keypair is ephemeral
    per handshake — it holds no long-lived DH key, which is what keeps past
    sessions safe if the PSK is later compromised.
    """
    if len(hello) != HELLO_LEN:
        raise LeafLinkError("HELLO wrong length")
    if hello[0] != LEAF_PROTO_VERSION or hello[1] != MSG_HELLO:
        raise LeafLinkError("not a HELLO")
    if len(psk) != NODE_PSK_LEN:
        raise LeafLinkError("PSK must be 32 bytes")

    import os

    gw_sk = x25519.X25519PrivateKey.generate()
    gw_pub = gw_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    ack = bytearray(HELLO_ACK_LEN)
    ack[0] = LEAF_PROTO_VERSION
    ack[1] = MSG_HELLO_ACK
    ack[2:4] = hello[2:4]  # echo the endpoint id
    ack[4:8] = b"\x00\x00\x00\x00"
    ack[8:40] = gw_pub
    ack[40:72] = os.urandom(NODE_HS_NONCE_LEN)

    leaf_pub = x25519.X25519PublicKey.from_public_bytes(hello[8:40])
    try:
        dh = gw_sk.exchange(leaf_pub)
    except ValueError as exc:
        # All-zero output: the leaf sent a low-order point, so the "shared
        # secret" carries no secret at all. Abort, as the C side does.
        raise LeafLinkError("low-order peer public key") from exc

    if dh == bytes(32):
        raise LeafLinkError("low-order peer public key")

    return _derive_session(hello, bytes(ack), dh, psk), bytes(ack)


def verify_confirm(session: LeafSession, confirm: bytes) -> None:
    """Check the leaf's CONFIRM. Raises if the two ends did not derive the same
    key — which is what a MITM without the PSK looks like."""
    if len(confirm) != CONFIRM_LEN:
        raise LeafLinkError("CONFIRM wrong length")
    if confirm[0] != LEAF_PROTO_VERSION or confirm[1] != MSG_CONFIRM:
        raise LeafLinkError("not a CONFIRM")
    if struct.unpack(">H", confirm[2:4])[0] != session.endpoint_id:
        raise LeafLinkError("CONFIRM endpoint id mismatch")

    import hmac as _hmac

    if not _hmac.compare_digest(confirm_tag(session), confirm[8:24]):
        raise LeafLinkError("CONFIRM tag mismatch - no shared key")


__all__ = [
    "LeafLinkError",
    "LeafHeader",
    "ChannelReading",
    "LeafSession",
    "cobs_encode",
    "cobs_decode",
    "open_frame",
    "seal_frame",
    "frame_len",
    "respond",
    "verify_confirm",
    "confirm_tag",
]
