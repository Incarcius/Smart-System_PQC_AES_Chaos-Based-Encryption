"""
server_state.py — per-gateway state on the main server.

The server is the mirror of `gateway_state.py`: it holds the ROOT_KEY it
issued, derives the same uplink pool, and tracks the counters that make replay
detection and posture verification possible.

Posture echo — verifying the gateway actually complied
------------------------------------------------------
Issuing a posture command is not the same as it taking effect. The gateway
could be unreachable, wedged, or compromised. The system already carries the
evidence for free: `posture` is a field in every telemetry frame header, and
the header is the AES-GCM AAD, so it is a *signed statement* of the gateway's
current posture that nobody else can forge.

So after commanding ENFORCE or QUARANTINE at `ctrl_seq = N`, the next K frames
must report at least the commanded posture. If they do not, the gateway is not
doing what it was told — drop the link and alert, rather than continuing to
trust its data.

Control nonce discipline
------------------------
`ctrl_epoch` is persisted and bumped on every restart and every control-key
install, exactly as the gateway does for telemetry. `ctrl_seq` is monotonic
within an epoch. Together they are the control channel's 96-bit nonce, so a
server restart cannot replay a (key, nonce) pair even if the same `gw-ctrl`
key is reloaded.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
for _p in (
    _REPO / "src" / "security" / "ACCM" / "python",
    _REPO / "temp_codes" / "pqcrypto_project" / "pqcrypto_project",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from protocol import Header, Posture, ReplayGuard, TAIL_LEN  # noqa: E402
from keyschedule import (  # noqa: E402
    NODE_CONTROL,
    NODE_TELEMETRY,
    derive_session_pool,
    telemetry_contexts,
)

PROTOCOL_TAG = b"pqc-rootkey/v2"


class ServerStateError(Exception):
    """Configuration or key-material failure. Fatal — never degrade."""


class EchoStatus(Enum):
    OK = "ok"                      # complied, or nothing pending
    PENDING = "pending"            # commanded, still inside the grace window
    VIOLATED = "violated"          # K frames elapsed without compliance


class CounterStore:
    """Durable monotonic counters. Mirror of the gateway's EpochStore.

    Commits before returning, so a crash can only skip a value, never reuse
    one. Skipping costs nothing; reusing a control nonce is fatal.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            self._values = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self._values = {}

    def get(self, key: str) -> int:
        return int(self._values.get(key, 0))

    def bump(self, key: str) -> int:
        nxt = self.get(key) + 1
        self._values[key] = nxt
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._values))
        tmp.replace(self.path)
        return nxt


@dataclass
class SessionStats:
    frames_ok: int = 0
    frames_auth_failed: int = 0
    frames_replayed: int = 0
    controls_sent: int = 0
    echo_violations: int = 0


class GatewaySession:
    """Everything the server knows about one connected gateway."""

    def __init__(
        self,
        gateway_id: int,
        root_key: bytes,
        transcript: bytes,
        counters: CounterStore,
        echo_window_frames: int = 5,
    ) -> None:
        if len(root_key) != 32 or len(transcript) != 32:
            raise ServerStateError("root_key and transcript must be 32 bytes")

        self.gateway_id = gateway_id
        self._root_key = bytearray(root_key)
        self._transcript = transcript
        self.counters = counters
        self.echo_window_frames = echo_window_frames

        self.key_epoch = 0
        self.telemetry_key: bytearray | None = None
        self.control_key: bytearray | None = None

        self.replay = ReplayGuard()
        self.accm_tail = bytes(TAIL_LEN)
        self.stats = SessionStats()

        self.ctrl_epoch = counters.bump(f"ctrl_epoch_{gateway_id}")
        self.ctrl_seq = 0

        self._pending_posture: Posture | None = None
        self._frames_since_command = 0

        self.adopt_key_epoch(1)

    # ── key material ─────────────────────────────────────────────────────

    def adopt_key_epoch(self, key_epoch: int) -> None:
        """Re-derive the uplink pool for a key_epoch the gateway has rotated to.

        The gateway owns the epoch: it bumps its persisted counter and starts
        sending under the new one. The server follows, because the epoch is in
        the frame header and the header is authenticated — so the server cannot
        be walked backwards onto an old key by an attacker.
        """
        if key_epoch == self.key_epoch:
            return

        pool = derive_session_pool(
            bytes(self._root_key),
            self._transcript,
            PROTOCOL_TAG,
            key_epoch,
            telemetry_contexts(),
        )

        self._wipe_pool()
        self.telemetry_key = bytearray(pool[NODE_TELEMETRY])
        self.control_key = bytearray(pool[NODE_CONTROL])
        self.key_epoch = key_epoch

        # A new key means a new nonce space and a fresh ACCM chain. Carrying
        # the old tail over would desynchronise the mask on the first frame.
        self.accm_tail = bytes(TAIL_LEN)

    def next_ctrl_seq(self) -> int:
        self.ctrl_seq += 1
        return self.ctrl_seq

    # ── posture echo ─────────────────────────────────────────────────────

    def record_command(self, posture: Posture) -> None:
        """Note a posture we have just commanded, and start the echo window.

        Re-issuing the SAME posture does not restart the clock. The server
        keeps commanding while the condition persists, so restarting on every
        repeat would mean a gateway that never complies is never detected --
        the counter would reset faster than it could expire. The window
        measures "how long have I been asking for this", not "when did I last
        ask".
        """
        self.stats.controls_sent += 1
        if self._pending_posture == posture:
            return
        self._pending_posture = posture
        self._frames_since_command = 0

    def check_echo(self, header: Header) -> EchoStatus:
        """Verify the gateway's compliance from its own authenticated header."""
        if self._pending_posture is None:
            return EchoStatus.OK

        self._frames_since_command += 1

        if int(header.posture) >= int(self._pending_posture):
            self._pending_posture = None
            return EchoStatus.OK

        if self._frames_since_command >= self.echo_window_frames:
            # K frames and still not complying. Either the gateway never got
            # the command, or it is not the gateway any more.
            self._pending_posture = None
            self.stats.echo_violations += 1
            return EchoStatus.VIOLATED

        return EchoStatus.PENDING

    # ── housekeeping ─────────────────────────────────────────────────────

    def _wipe_pool(self) -> None:
        for buf in (self.telemetry_key, self.control_key):
            if buf is not None:
                for i in range(len(buf)):
                    buf[i] = 0
        self.telemetry_key = None
        self.control_key = None

    def shutdown(self) -> None:
        self._wipe_pool()
        for i in range(len(self._root_key)):
            self._root_key[i] = 0


__all__ = [
    "CounterStore",
    "EchoStatus",
    "GatewaySession",
    "ServerStateError",
    "SessionStats",
    "PROTOCOL_TAG",
]
