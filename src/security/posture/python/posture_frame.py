"""
posture_frame.py — Python mirror of src/security/posture/src/posture_frame.c.

The server (Python) seals control frames; the gateway (C) opens them. Both
directions are exercised by tests/test_posture.py, so a divergence in framing
shows up as a test failure rather than as a gateway that silently stops
accepting posture commands.

See posture_frame.h for the wire layout and why the payload is encrypted
rather than merely authenticated.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ACCM" / "python"))

from protocol import CONTROL_LEN, PROTO_VERSION, Control, ProtocolError  # noqa: E402

FRAME_LEN = 64
FRAME_TYPE = 0x01
AAD_LEN = 16
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

_OFF_NONCE = 4
_OFF_CT = 16
_OFF_TAG = 48


class FrameError(Exception):
    """Raised when a control frame is malformed or fails authentication."""


def derive_nonce(ctrl_epoch: int, ctrl_seq: int) -> bytes:
    """nonce = ctrl_epoch(4 BE) || ctrl_seq(8 BE).

    Both halves are owned by the server. ctrl_epoch is persisted and bumped on
    every control-key install and every server restart, so a restart cannot
    replay a (key, nonce) pair even if the same gw-ctrl key is reloaded.
    """
    return struct.pack(">IQ", ctrl_epoch, ctrl_seq)


def seal(key: bytes, ctrl_epoch: int, ctrl: Control) -> bytes:
    """Encrypt and authenticate a control message into a 64-byte frame."""
    if len(key) != KEY_LEN:
        raise FrameError(f"control key must be {KEY_LEN} bytes")

    nonce = derive_nonce(ctrl_epoch, ctrl.ctrl_seq)
    header = bytes([PROTO_VERSION, FRAME_TYPE, 0, 0]) + nonce
    assert len(header) == AAD_LEN

    blob = AESGCM(key).encrypt(nonce, ctrl.serialize(), header)
    ciphertext, tag = blob[:-TAG_LEN], blob[-TAG_LEN:]

    frame = header + ciphertext + tag
    assert len(frame) == FRAME_LEN
    return frame


def peek_seq(frame: bytes) -> int:
    """Read ctrl_seq from the cleartext nonce without decrypting.

    Lets the gateway drop an obvious replay before paying for a GCM open. The
    value is UNAUTHENTICATED here: use it only to skip work, never to accept
    anything. open() re-checks it against the authenticated payload.
    """
    if len(frame) != FRAME_LEN:
        raise FrameError(f"frame must be {FRAME_LEN} bytes, got {len(frame)}")
    if frame[0] != PROTO_VERSION or frame[1] != FRAME_TYPE:
        raise FrameError("bad frame version or type")
    return struct.unpack(">Q", frame[_OFF_NONCE + 4 : _OFF_NONCE + 12])[0]


def open_frame(key: bytes, frame: bytes) -> tuple[Control, int]:
    """Verify and decrypt. Returns (control, ctrl_epoch).

    Cryptographic verification only — this does NOT apply the message. Feed the
    result to PostureState.apply(), which enforces freshness and ordering.
    """
    if len(key) != KEY_LEN:
        raise FrameError(f"control key must be {KEY_LEN} bytes")
    if len(frame) != FRAME_LEN:
        raise FrameError(f"frame must be {FRAME_LEN} bytes, got {len(frame)}")
    if frame[0] != PROTO_VERSION:
        raise FrameError(f"unsupported version {frame[0]:#x}")
    if frame[1] != FRAME_TYPE:
        raise FrameError(f"unsupported frame type {frame[1]:#x}")
    if frame[2] != 0 or frame[3] != 0:
        raise FrameError("reserved bytes must be zero")

    header = frame[:AAD_LEN]
    nonce = frame[_OFF_NONCE:_OFF_CT]
    ciphertext = frame[_OFF_CT:_OFF_TAG]
    tag = frame[_OFF_TAG:]

    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext + tag, header)
    except InvalidTag as error:
        raise FrameError("control frame authentication failed") from error

    if len(plain) != CONTROL_LEN:
        raise FrameError("decrypted control has the wrong length")

    try:
        ctrl = Control.parse(plain)
    except ProtocolError as error:
        raise FrameError(str(error)) from error

    # The nonce carried ctrl_seq in the clear for the cheap replay check.
    # Confirm it matches the authenticated copy: rewriting the cleartext half
    # would already fail the GCM tag (the nonce is AAD), but checking here
    # means the two can never silently diverge, and turns any such attempt
    # into a distinct, loggable error.
    nonce_epoch, nonce_seq = struct.unpack(">IQ", nonce)
    if nonce_seq != ctrl.ctrl_seq:
        raise FrameError("ctrl_seq in nonce does not match the payload")

    return ctrl, nonce_epoch
