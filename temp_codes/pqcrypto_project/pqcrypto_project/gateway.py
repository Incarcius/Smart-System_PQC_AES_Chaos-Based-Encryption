"""Gateway-side ROOT_KEY reception for the local PQC transfer subsystem."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_44
from kyber_py.ml_kem import ML_KEM_512

from config import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AuthenticationError,
    GATEWAY_DSA_PRIVATE_KEY_PATH,
    GATEWAY_DSA_PUBLIC_KEY_PATH,
    GATEWAY_ID,
    GATEWAY_KEM_PRIVATE_KEY_PATH,
    GATEWAY_KEM_PUBLIC_KEY_PATH,
    GATEWAY_ROOT_EPOCH_PATH,
    KeyMaterialError,
    MAX_CLOCK_SKEW_MS,
    PROTOCOL_TAG,
    PacketValidationError,
    ROOT_KEY_BYTES,
    ReplayError,
    RootKeyPacket,
    SERVER_DSA_PUBLIC_KEY_PATH,
)
from server import _signature_payload, derive_transport_key, transfer_context

_REQUIRED_BYTES_FIELDS = (
    "protocol_tag",
    "gateway_id",
    "kem_ciphertext",
    "encrypted_root_key",
    "nonce",
    "tag",
    "signature",
)
_REQUIRED_INT_FIELDS = ("root_epoch", "issued_ms")


def _read_key(path: Path) -> bytes:
    """Read non-empty local key material or raise a configuration error."""
    try:
        value = path.read_bytes()
    except OSError as error:
        raise KeyMaterialError(f"cannot read key material: {path.name}") from error
    if not value:
        raise KeyMaterialError(f"key material is empty: {path.name}")
    return value


def _write_key_once(path: Path, value: bytes) -> None:
    """Persist generated gateway key material without overwriting existing keys."""
    if path.exists():
        return
    try:
        path.write_bytes(value)
    except OSError as error:
        raise KeyMaterialError(f"cannot write key material: {path.name}") from error


def initialize_gateway_keys() -> None:
    """Generate and store the gateway ML-KEM-512 and ML-DSA-44 keypairs.

    The ML-KEM private key receives this one-way transfer. The stored gateway
    ML-DSA keypair is the gateway identity material and is reserved for later
    gateway-to-server authentication; this flow verifies the server with the
    separately provisioned server ML-DSA public key.

    Open issue: the server currently reads ``gateway_kem_pk.bin`` from local
    disk and trusts it implicitly. In deployment the gateway must sign its own
    KEM public key with this ML-DSA key, and the server must hold a trusted
    copy of ``gateway_dsa_pk.bin``. Tracked in docs/PROJECT_STATUS.md.
    """
    kem_paths = (GATEWAY_KEM_PUBLIC_KEY_PATH, GATEWAY_KEM_PRIVATE_KEY_PATH)
    dsa_paths = (GATEWAY_DSA_PUBLIC_KEY_PATH, GATEWAY_DSA_PRIVATE_KEY_PATH)
    if any(path.exists() for path in kem_paths) and not all(path.exists() for path in kem_paths):
        raise KeyMaterialError("gateway ML-KEM keypair is incomplete")
    if any(path.exists() for path in dsa_paths) and not all(path.exists() for path in dsa_paths):
        raise KeyMaterialError("gateway ML-DSA keypair is incomplete")
    if not all(path.exists() for path in kem_paths):
        public_key, private_key = ML_KEM_512.keygen()
        _write_key_once(GATEWAY_KEM_PUBLIC_KEY_PATH, public_key)
        _write_key_once(GATEWAY_KEM_PRIVATE_KEY_PATH, private_key)
    if not all(path.exists() for path in dsa_paths):
        public_key, private_key = ML_DSA_44.keygen()
        _write_key_once(GATEWAY_DSA_PUBLIC_KEY_PATH, public_key)
        _write_key_once(GATEWAY_DSA_PRIVATE_KEY_PATH, private_key)


def last_accepted_epoch() -> int:
    """Highest ROOT_KEY epoch this gateway has accepted, 0 if none."""
    try:
        return int(GATEWAY_ROOT_EPOCH_PATH.read_text().strip())
    except (OSError, ValueError):
        return 0


def _record_epoch(epoch: int) -> None:
    GATEWAY_ROOT_EPOCH_PATH.write_text(str(epoch))


def _validate_packet(packet: Any) -> RootKeyPacket:
    """Validate packet shape before any cryptographic processing."""
    required = set(_REQUIRED_BYTES_FIELDS) | set(_REQUIRED_INT_FIELDS)
    if not isinstance(packet, dict) or set(packet) != required:
        raise PacketValidationError("packet has missing or unexpected fields")
    if not all(isinstance(packet[name], bytes) for name in _REQUIRED_BYTES_FIELDS):
        raise PacketValidationError("byte fields must be bytes")
    if not all(isinstance(packet[name], int) for name in _REQUIRED_INT_FIELDS):
        raise PacketValidationError("root_epoch and issued_ms must be ints")
    if len(packet["nonce"]) != AES_GCM_NONCE_BYTES:
        raise PacketValidationError("invalid AES-GCM nonce length")
    if len(packet["tag"]) != AES_GCM_TAG_BYTES:
        raise PacketValidationError("invalid AES-GCM tag length")
    if len(packet["encrypted_root_key"]) != ROOT_KEY_BYTES:
        raise PacketValidationError("encrypted ROOT_KEY has an unexpected length")
    return packet


def _check_context(packet: RootKeyPacket, now_ms: int, enforce_epoch: bool) -> None:
    """Reject packets addressed elsewhere, stale, or replaying an epoch.

    Runs after signature verification, so an attacker cannot use the distinction
    between these errors to probe the gateway with unsigned packets.
    """
    if packet["protocol_tag"] != PROTOCOL_TAG:
        raise ReplayError("protocol tag mismatch")
    if packet["gateway_id"] != GATEWAY_ID:
        raise ReplayError("packet is addressed to a different gateway")

    skew = abs(now_ms - packet["issued_ms"])
    if skew > MAX_CLOCK_SKEW_MS:
        raise ReplayError(f"issued_ms outside the accepted window ({skew} ms)")

    if enforce_epoch and packet["root_epoch"] <= last_accepted_epoch():
        raise ReplayError(
            f"root_epoch {packet['root_epoch']} is not newer than "
            f"{last_accepted_epoch()} - replayed or rolled back"
        )


def receive_root_key(
    packet: RootKeyPacket,
    enforce_epoch: bool = True,
    now_ms: int | None = None,
) -> bytes:
    """Verify, decapsulate, and decrypt a transferred 256-bit ROOT_KEY.

    Order matters: the ML-DSA signature is checked before ML-KEM decapsulation
    and before any context check, so unauthenticated packets are rejected
    before their confidential contents are processed and before the gateway
    reveals anything about its epoch state.

    ``enforce_epoch=False`` skips the monotonic replay check. It exists only
    for benchmarking the cryptographic cost in a loop; never use it on a live
    link.
    """
    checked_packet = _validate_packet(packet)
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    server_public_key = _read_key(SERVER_DSA_PUBLIC_KEY_PATH)
    gateway_private_key = _read_key(GATEWAY_KEM_PRIVATE_KEY_PATH)

    try:
        is_valid = ML_DSA_44.verify(
            server_public_key,
            _signature_payload(checked_packet),
            checked_packet["signature"],
        )
    except (ValueError, TypeError) as error:
        raise KeyMaterialError("invalid server ML-DSA public key") from error
    if not is_valid:
        raise AuthenticationError("ML-DSA signature verification failed")

    _check_context(checked_packet, now_ms, enforce_epoch)

    context = transfer_context(
        checked_packet["gateway_id"],
        checked_packet["root_epoch"],
        checked_packet["issued_ms"],
    )

    try:
        shared_secret = ML_KEM_512.decaps(gateway_private_key, checked_packet["kem_ciphertext"])
        transport_key = derive_transport_key(shared_secret, context)
        root_key = AESGCM(transport_key).decrypt(
            checked_packet["nonce"],
            checked_packet["encrypted_root_key"] + checked_packet["tag"],
            context,
        )
    except InvalidTag as error:
        raise AuthenticationError("AES-GCM authentication failed") from error
    except (ValueError, TypeError) as error:
        raise KeyMaterialError("invalid gateway ML-KEM private key or ciphertext") from error

    if len(root_key) != ROOT_KEY_BYTES:
        raise AuthenticationError("decrypted ROOT_KEY has an unexpected length")

    # Only commit the epoch once the packet has fully verified, so a failed
    # transfer cannot burn an epoch and lock out the real one.
    if enforce_epoch:
        _record_epoch(checked_packet["root_epoch"])

    return root_key
