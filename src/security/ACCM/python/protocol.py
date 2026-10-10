"""
protocol.py — Python mirror of include/protocol.h.

The gateway (C) writes these frames; the main server (Python) reads them, so
the two must agree byte for byte. Everything is big-endian and explicit --
never use struct's native '@' formats here.

See include/protocol.h for the design rationale (why the header is cleartext
but authenticated, and why the nonce is deterministic).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

PROTO_VERSION = 0x02

HEADER_LEN = 24
NONCE_LEN = 12
GCM_TAG_LEN = 16
TAIL_LEN = 8
CONTROL_LEN = 32

# Hard ceiling on packets per key_epoch; matches TG_SEQ_MAX in protocol.h.
SEQ_MAX = 1 << 30


class Posture(IntEnum):
    """Mirrors tg_posture_t and the three terminal states of the workflow."""

    NORMAL = 0
    SUSPICIOUS = 1
    ANOMALY = 2


_HEADER_FMT = ">BBHIQQ"
_CONTROL_FMT = ">BBBBIIIQQ"


class ProtocolError(Exception):
    """Raised when a frame fails structural validation."""


@dataclass(frozen=True)
class Header:
    """The 24-byte telemetry frame header. Also the AES-GCM AAD."""

    node_id: int
    key_epoch: int
    seq: int
    timestamp_ms: int
    posture: Posture = Posture.NORMAL
    version: int = PROTO_VERSION

    def serialize(self) -> bytes:
        return struct.pack(
            _HEADER_FMT,
            self.version,
            int(self.posture),
            self.node_id,
            self.key_epoch,
            self.seq,
            self.timestamp_ms,
        )

    @classmethod
    def parse(cls, raw: bytes) -> "Header":
        if len(raw) != HEADER_LEN:
            raise ProtocolError(f"header must be {HEADER_LEN} bytes, got {len(raw)}")
        version, posture, node_id, key_epoch, seq, ts = struct.unpack(_HEADER_FMT, raw)
        if version != PROTO_VERSION:
            raise ProtocolError(f"unsupported protocol version {version:#x}")
        if posture not in tuple(Posture):
            raise ProtocolError(f"posture out of range: {posture}")
        return cls(
            node_id=node_id,
            key_epoch=key_epoch,
            seq=seq,
            timestamp_ms=ts,
            posture=Posture(posture),
            version=version,
        )

    def nonce(self) -> bytes:
        """nonce = key_epoch(4 BE) || seq(8 BE) — see tg_nonce_derive()."""
        return struct.pack(">IQ", self.key_epoch, self.seq)


class NonceGuard:
    """Send-side counter. The only sanctioned source of a sequence number.

    The 'never reuse (key, nonce)' invariant lives here, below the policy
    layer, so the DQN can decide *when* to rotate but cannot decide to emit a
    duplicate nonce.
    """

    def __init__(self, key_epoch: int) -> None:
        self.key_epoch = key_epoch
        self.next_seq = 0
        self.exhausted = False

    def next(self) -> int:
        if self.exhausted or self.next_seq >= SEQ_MAX:
            self.exhausted = True
            raise ProtocolError("key_epoch exhausted — rekey before sending")
        seq = self.next_seq
        self.next_seq += 1
        if self.next_seq >= SEQ_MAX:
            self.exhausted = True
        return seq


class ReplayGuard:
    """Receive-side strict-ordering guard; mirrors tg_replay_guard_t.

    Suitable for the TCP gateway->server link. A lossy transport would need a
    sliding bitmap window instead.
    """

    def __init__(self) -> None:
        self.key_epoch = 0
        self.last_seq = 0
        self.seen = False

    def check(self, header: Header) -> bool:
        if not self.seen:
            self.key_epoch = header.key_epoch
            self.last_seq = header.seq
            self.seen = True
            return True
        if header.key_epoch < self.key_epoch:
            return False
        if header.key_epoch > self.key_epoch:
            self.key_epoch = header.key_epoch
            self.last_seq = header.seq
            return True
        if header.seq <= self.last_seq:
            return False
        self.last_seq = header.seq
        return True


class Directive(IntEnum):
    """How much authority a control message carries. Mirrors tg_directive_t.

    The server detects; the DQN decides. This ladder keeps the agent in charge
    of the ordinary tradeoff while leaving a hard override for a live
    intrusion.
    """

    ADVISE = 0  # observation; agent chooses the response
    ENFORCE = 1  # floor; agent may go higher, never lower
    QUARANTINE = 2  # mandatory; quarantines node_mask and forces ANOMALY


class CtrlStatus(IntEnum):
    """Mirrors tg_ctrl_status_t."""

    OK = 0
    ERR_PARSE = -1
    ERR_REPLAY = -2
    ERR_STALE = -3


@dataclass(frozen=True)
class Control:
    """Server -> gateway posture command; mirrors tg_control_t (32 bytes).

    Sent inside its own AES-GCM envelope under a separate derived key, with a
    monotonic ctrl_seq. That is what stops a captured 'NORMAL' from being
    replayed to suppress a live response, and a captured 'ANOMALY' from being
    replayed as a rekey-storm denial of service.

    ``lease_ms`` is the load-bearing field: the gateway holds its posture only
    while the lease is unexpired, so losing this channel escalates rather than
    suppresses. See include/protocol.h for the full rationale.
    """

    ctrl_seq: int
    issued_ms: int
    lease_ms: int
    min_hold_ms: int = 0
    node_mask: int = 0
    posture: Posture = Posture.NORMAL
    directive: Directive = Directive.ADVISE
    version: int = PROTO_VERSION
    reserved: int = 0

    def serialize(self) -> bytes:
        return struct.pack(
            _CONTROL_FMT,
            self.version,
            int(self.posture),
            int(self.directive),
            self.reserved,
            self.node_mask,
            self.lease_ms,
            self.min_hold_ms,
            self.ctrl_seq,
            self.issued_ms,
        )

    @classmethod
    def parse(cls, raw: bytes) -> "Control":
        if len(raw) != CONTROL_LEN:
            raise ProtocolError(f"control must be {CONTROL_LEN} bytes, got {len(raw)}")
        (
            version,
            posture,
            directive,
            reserved,
            node_mask,
            lease_ms,
            min_hold_ms,
            ctrl_seq,
            issued_ms,
        ) = struct.unpack(_CONTROL_FMT, raw)

        if version != PROTO_VERSION:
            raise ProtocolError(f"unsupported protocol version {version:#x}")
        if posture not in tuple(Posture):
            raise ProtocolError(f"posture out of range: {posture}")
        if directive not in tuple(Directive):
            raise ProtocolError(f"directive out of range: {directive}")
        # Reject rather than ignore: a future version may give this meaning,
        # and silently accepting it would let an old gateway apply a message
        # whose semantics it does not understand.
        if reserved != 0:
            raise ProtocolError("reserved byte must be zero")

        return cls(
            ctrl_seq=ctrl_seq,
            issued_ms=issued_ms,
            lease_ms=lease_ms,
            min_hold_ms=min_hold_ms,
            node_mask=node_mask,
            posture=Posture(posture),
            directive=Directive(directive),
            version=version,
            reserved=reserved,
        )


class PostureState:
    """Gateway-side posture state machine. Mirrors tg_posture_state_t.

    Drive it with apply()/tick()/request(). The DQN reads the attributes as
    state features but must never assign to ``posture`` directly -- request()
    is the only path from policy to posture, and it is where the shielding
    lives.
    """

    def __init__(self, now_ms: int) -> None:
        self.posture = Posture.NORMAL
        self.directive_floor = Posture.NORMAL
        self.advised_posture = Posture.NORMAL
        self.seen_ctrl = False
        self.node_mask = 0
        self.lease_ms = 0
        self.min_hold_ms = 0
        self.lease_expires_ms = 0
        self.posture_since_ms = now_ms
        self.last_ctrl_seq = 0

    def grace(self, grace_ms: int, now_ms: int) -> None:
        """Grant a startup lease window before the first control message."""
        self.lease_ms = grace_ms
        self.lease_expires_ms = now_ms + grace_ms

    def _set_posture(self, posture: Posture, now_ms: int) -> None:
        if self.posture != posture:
            self.posture = posture
            self.posture_since_ms = now_ms

    def apply(self, ctrl: Control, now_ms: int, max_skew_ms: int) -> CtrlStatus:
        """Apply an ALREADY-decrypted, ALREADY-authenticated control message.

        Verifies nothing cryptographic -- do that first with posture_frame.
        Enforces freshness and ordering, then applies the directive.
        """
        # Strictly increasing. Equality is a replay, not a tolerable duplicate:
        # the server never reuses a ctrl_seq.
        if self.seen_ctrl and ctrl.ctrl_seq <= self.last_ctrl_seq:
            return CtrlStatus.ERR_REPLAY

        if abs(now_ms - ctrl.issued_ms) > max_skew_ms:
            return CtrlStatus.ERR_STALE

        self.last_ctrl_seq = ctrl.ctrl_seq
        self.seen_ctrl = True

        # Every valid message renews the lease, whatever its directive: the
        # lease proves the server is alive, independently of what it asks for.
        self.lease_ms = ctrl.lease_ms
        self.lease_expires_ms = now_ms + ctrl.lease_ms
        self.min_hold_ms = ctrl.min_hold_ms

        if ctrl.directive is Directive.ADVISE:
            self.advised_posture = ctrl.posture

        elif ctrl.directive is Directive.ENFORCE:
            self.directive_floor = ctrl.posture
            self.advised_posture = ctrl.posture
            if self.posture < ctrl.posture:
                self._set_posture(ctrl.posture, now_ms)

        elif ctrl.directive is Directive.QUARANTINE:
            # Accumulate rather than replace: two overlapping detections must
            # not clear each other's nodes. Release is explicit, after triage.
            self.node_mask |= ctrl.node_mask
            self.directive_floor = Posture.ANOMALY
            self.advised_posture = Posture.ANOMALY
            self._set_posture(Posture.ANOMALY, now_ms)

        else:
            return CtrlStatus.ERR_PARSE

        return CtrlStatus.OK

    def tick(self, now_ms: int) -> bool:
        """Advance time. Returns True if the posture changed.

        On lease expiry escalates ONE level and re-arms, so a dead control
        channel walks NORMAL -> SUSPICIOUS -> ANOMALY over two lease periods
        rather than slamming to ANOMALY on one lost packet.

        Deliberately does not touch node_mask: auto-quarantine on lease expiry
        would turn "jam the control channel" into a remote denial of service.
        """
        if self.lease_expires_ms == 0 or now_ms < self.lease_expires_ms:
            return False

        if self.posture >= Posture.ANOMALY:
            self.lease_expires_ms = now_ms + self.lease_ms
            return False

        self._set_posture(Posture(int(self.posture) + 1), now_ms)
        self.lease_expires_ms = (now_ms + self.lease_ms) if self.lease_ms else 0
        return True

    def request(self, desired: Posture, now_ms: int) -> Posture:
        """The DQN proposes; this grants or clamps. THE SHIELD.

        Escalation is always immediate. De-escalation is refused below an
        ENFORCE floor, and before min_hold_ms has elapsed. The agent is not
        told 'no' -- it observes the result, which is the correct signal for a
        policy to learn from.
        """
        desired = Posture(desired)

        if desired > self.posture:
            self._set_posture(desired, now_ms)
            return self.posture
        if desired == self.posture:
            return self.posture

        if desired < self.directive_floor:
            desired = self.directive_floor

        if now_ms - self.posture_since_ms < self.min_hold_ms:
            return self.posture

        if desired < self.posture:
            self._set_posture(desired, now_ms)
        return self.posture

    def is_quarantined(self, node_id: int) -> bool:
        """Quarantine is a TRUST state, not a crypto state: the node keeps a
        valid session key and keeps being ingested, but its data is isolated
        and marked untrusted for triage."""
        return node_id < 32 and bool(self.node_mask & (1 << node_id))

    def release(self, node_id: int) -> None:
        if node_id < 32:
            self.node_mask &= ~(1 << node_id)
