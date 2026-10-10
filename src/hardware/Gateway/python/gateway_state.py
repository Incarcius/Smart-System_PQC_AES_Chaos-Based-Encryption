"""
gateway_state.py — the security state a gateway owns.

Three separate key hierarchies meet here, and keeping them straight is the
whole job of this module:

  1. **ROOT_KEY** — delivered by the server over ML-KEM + ML-DSA. Never leaves
     the gateway. Feeds RXCR-KMAC-KDF.
  2. **Uplink pool** — `gw-telemetry` and `gw-ctrl`, derived from ROOT_KEY.
     Separated by the KDF's customisation string, so the control channel has
     its own key and therefore its own nonce space.
  3. **Leaf session keys** — one per ESP32, from the PSK+DHE handshake. These
     are NOT derived from ROOT_KEY: a leaf never holds it, so a compromised
     sensor node cannot derive anything for the rest of the system.

Epoch persistence
-----------------
Both the uplink and every leaf link use `nonce = key_epoch || seq`, with `seq`
restarting at zero on every boot. So `key_epoch` must be persisted and
incremented *before* the first encryption, exactly as the leaf does in
node_session.c. A gateway that restarted its epoch while reloading a session
key would re-emit nonces it had already used, and GCM nonce reuse is total
failure rather than degradation.

Key material lives in `bytearray` rather than `bytes` so it can be zeroed on
rotation. That is weaker than C's `hal_secure_wipe()` — Python may retain
copies from intermediate operations — and the limitation is documented in
docs/REMAINING_WORK.md §0c rather than papered over.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path(__file__).resolve().parents[4]
for _p in (
    _REPO / "src" / "security" / "ACCM" / "python",
    _REPO / "temp_codes" / "pqcrypto_project" / "pqcrypto_project",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from protocol import NonceGuard, PostureState, ProtocolError, ReplayGuard  # noqa: E402
from keyschedule import (  # noqa: E402
    NODE_CONTROL,
    NODE_TELEMETRY,
    derive_session_pool,
    telemetry_contexts,
)

PROTOCOL_TAG = b"pqc-rootkey/v2"


class GatewayStateError(Exception):
    """Configuration or key-material failure. Fatal — never degrade."""


# ── persisted counters ──────────────────────────────────────────────────────


class EpochStore:
    """Durable monotonic counters, the gateway's equivalent of node_storage.c.

    Writes are committed before the caller sees the value, so a crash can only
    skip an epoch, never reuse one.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._values: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        try:
            self._values = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self._values = {}

    def _flush(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._values))
        tmp.replace(self.path)  # atomic on POSIX and Windows

    def get(self, key: str) -> int:
        return int(self._values.get(key, 0))

    def bump(self, key: str) -> int:
        """Increment, commit, then return. Order matters — see the module docstring."""
        nxt = self.get(key) + 1
        self._values[key] = nxt
        self._flush()
        return nxt


# ── per-leaf link state ─────────────────────────────────────────────────────


@dataclass
class LeafLinkState:
    """Everything the gateway knows about one ESP32."""

    endpoint_id: int
    session_key: bytearray | None = None
    replay: ReplayGuard = field(default_factory=ReplayGuard)
    frames_ok: int = 0
    auth_failures: int = 0
    last_seen_ms: int = 0

    @property
    def established(self) -> bool:
        return self.session_key is not None

    def install(self, key: bytes) -> None:
        self.wipe()
        self.session_key = bytearray(key)
        # A new handshake means a new key, so the old replay window is
        # meaningless — and keeping it would reject the new link's seq 0.
        self.replay = ReplayGuard()

    def wipe(self) -> None:
        if self.session_key is not None:
            for i in range(len(self.session_key)):
                self.session_key[i] = 0
            self.session_key = None


# ── the gateway's whole security state ──────────────────────────────────────


class GatewayState:
    """ROOT_KEY, the derived uplink pool, per-leaf links, and posture."""

    def __init__(
        self,
        gateway_id: int,
        epoch_store: EpochStore,
        leaf_psks: dict[int, bytes],
        now_ms: int | None = None,
    ) -> None:
        self.gateway_id = gateway_id
        self.epochs = epoch_store
        self.leaf_psks = dict(leaf_psks)

        self._root_key: bytearray | None = None
        self._transcript: bytes | None = None

        self.telemetry_key: bytearray | None = None
        self.control_key: bytearray | None = None

        self.key_epoch = 0
        self.nonce_guard: NonceGuard | None = None
        self.ctrl_replay_seq = 0

        self.posture = PostureState(now_ms if now_ms is not None else int(time.time() * 1000))
        self.leaves: dict[int, LeafLinkState] = {}

        # Local fast-path detector counters, read by the policy each tick and
        # reset. Cheap, and zero under normal operation — a burst of GCM
        # failures is the best free intrusion signal the gateway has.
        self.window_auth_failures = 0
        self.window_replay_rejects = 0
        self.window_ctrl_rejects = 0

    # ── root key and the uplink pool ────────────────────────────────────

    def install_root_key(self, root_key: bytes, transcript: bytes) -> None:
        """Adopt a ROOT_KEY from the PQC transfer and derive the uplink pool.

        Bumps key_epoch first, so the new pool starts on a nonce space that has
        provably never been used.
        """
        if len(root_key) != 32:
            raise GatewayStateError("ROOT_KEY must be 32 bytes")
        if len(transcript) != 32:
            raise GatewayStateError("transcript must be 32 bytes")

        self._wipe_uplink()
        self._root_key = bytearray(root_key)
        self._transcript = transcript
        self.rotate_uplink_keys()

    def rotate_uplink_keys(self) -> None:
        """Bump the epoch and re-derive the telemetry and control keys.

        Rotation and nonce-space reset are one indivisible step. The DQN can
        choose *when* this happens; it cannot choose to rotate the key without
        resetting the nonce space, or vice versa.
        """
        if self._root_key is None or self._transcript is None:
            raise GatewayStateError("no ROOT_KEY installed")

        self.key_epoch = self.epochs.bump("uplink_key_epoch")

        pool = derive_session_pool(
            bytes(self._root_key),
            self._transcript,
            PROTOCOL_TAG,
            self.key_epoch,
            telemetry_contexts(),
        )

        self._wipe_pool()
        self.telemetry_key = bytearray(pool[NODE_TELEMETRY])
        self.control_key = bytearray(pool[NODE_CONTROL])
        self.nonce_guard = NonceGuard(self.key_epoch)

    def next_seq(self) -> int:
        """The only sanctioned source of an uplink sequence number."""
        if self.nonce_guard is None:
            raise GatewayStateError("no session key installed")
        return self.nonce_guard.next()

    # ── leaf links ───────────────────────────────────────────────────────

    def leaf(self, endpoint_id: int) -> LeafLinkState:
        if endpoint_id not in self.leaves:
            self.leaves[endpoint_id] = LeafLinkState(endpoint_id)
        return self.leaves[endpoint_id]

    def psk_for(self, endpoint_id: int) -> bytes:
        try:
            return self.leaf_psks[endpoint_id]
        except KeyError:
            # No PSK means no authenticated handshake is possible. Refuse
            # rather than falling back to bare ECDHE, which a MITM defeats.
            raise GatewayStateError(
                f"no PSK provisioned for endpoint {endpoint_id:#06x}"
            ) from None

    # ── control-channel replay ───────────────────────────────────────────

    def accept_ctrl_seq(self, ctrl_seq: int) -> bool:
        """Strictly increasing. Equality is a replay, not a tolerable duplicate."""
        if ctrl_seq <= self.ctrl_replay_seq:
            self.window_ctrl_rejects += 1
            return False
        self.ctrl_replay_seq = ctrl_seq
        return True

    # ── housekeeping ─────────────────────────────────────────────────────

    def reset_window_counters(self) -> None:
        self.window_auth_failures = 0
        self.window_replay_rejects = 0
        self.window_ctrl_rejects = 0

    def _wipe_pool(self) -> None:
        for buf in (self.telemetry_key, self.control_key):
            if buf is not None:
                for i in range(len(buf)):
                    buf[i] = 0
        self.telemetry_key = None
        self.control_key = None

    def _wipe_uplink(self) -> None:
        self._wipe_pool()
        if self._root_key is not None:
            for i in range(len(self._root_key)):
                self._root_key[i] = 0
            self._root_key = None

    def shutdown(self) -> None:
        self._wipe_uplink()
        for leaf in self.leaves.values():
            leaf.wipe()


__all__ = [
    "EpochStore",
    "GatewayState",
    "GatewayStateError",
    "LeafLinkState",
    "PROTOCOL_TAG",
]
