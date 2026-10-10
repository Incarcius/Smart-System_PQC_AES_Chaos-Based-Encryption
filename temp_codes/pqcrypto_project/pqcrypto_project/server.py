"""Server-side ROOT_KEY transfer using ML-KEM-512, ML-DSA-44, and AES-256-GCM."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_44
from kyber_py.ml_kem import ML_KEM_512

from config import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    GATEWAY_ID,
    GATEWAY_KEM_PUBLIC_KEY_PATH,
    KeyMaterialError,
    PROTOCOL_TAG,
    ROOT_KEY_BYTES,
    RootKeyPacket,
    SERVER_DSA_PRIVATE_KEY_PATH,
    SERVER_DSA_PUBLIC_KEY_PATH,
    SERVER_ROOT_EPOCH_PATH,
)
from wire import lv, u64


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
    """Persist generated long-term signing material without overwriting existing keys."""
    if path.exists():
        return
    try:
        path.write_bytes(value)
    except OSError as error:
        raise KeyMaterialError(f"cannot write key material: {path.name}") from error


def initialize_server_signing_keys() -> None:
    """Create the server ML-DSA-44 signing keypair if it is not yet provisioned.

    This function never creates a ROOT_KEY. In a deployed system, provision the
    server private key securely and copy only ``server_dsa_pk.bin`` to gateways.
    """
    public_exists = SERVER_DSA_PUBLIC_KEY_PATH.exists()
    private_exists = SERVER_DSA_PRIVATE_KEY_PATH.exists()
    if public_exists != private_exists:
        raise KeyMaterialError("server ML-DSA keypair is incomplete")
    if not public_exists:
        public_key, private_key = ML_DSA_44.keygen()
        _write_key_once(SERVER_DSA_PUBLIC_KEY_PATH, public_key)
        _write_key_once(SERVER_DSA_PRIVATE_KEY_PATH, private_key)


def next_root_epoch() -> int:
    """Claim the next monotonic ROOT_KEY epoch, persisting it before use.

    Written before the packet is built so a crash mid-transfer can only skip
    an epoch, never reuse one. Reuse is the failure that matters: it would let
    a later packet carry an epoch the gateway has already accepted, which the
    gateway would then reject -- or worse, if the gateway had not yet seen it,
    accept as fresh.
    """
    try:
        current = int(SERVER_ROOT_EPOCH_PATH.read_text().strip())
    except (OSError, ValueError):
        current = 0
    nxt = current + 1
    SERVER_ROOT_EPOCH_PATH.write_text(str(nxt))
    return nxt


def derive_transport_key(shared_secret: bytes, context: bytes = b"") -> bytes:
    """Derive the AES-256 transport key from the ML-KEM shared secret.

    Context-bound: the same shared secret under a different protocol tag,
    recipient, or epoch yields a different transport key, so a packet cannot be
    reinterpreted in another context. Fields are length-prefixed to keep the
    hash input unambiguous.
    """
    if not isinstance(shared_secret, bytes) or not shared_secret:
        raise ValueError("ML-KEM shared secret must be non-empty bytes")
    return hashlib.sha3_256(
        lv(PROTOCOL_TAG + b"/transport") + lv(shared_secret) + lv(context)
    ).digest()


def transfer_context(gateway_id: bytes, root_epoch: int, issued_ms: int) -> bytes:
    """The context bytes bound into both the transport key and the GCM AAD."""
    return lv(PROTOCOL_TAG) + lv(gateway_id) + u64(root_epoch) + u64(issued_ms)


def _signature_payload(packet: RootKeyPacket) -> bytes:
    """Build the exact signed byte sequence for a transfer packet.

    Covers every field except the signature itself, each length-prefixed. The
    recipient identity, epoch, and timestamp are in here specifically so that a
    captured packet cannot be replayed to a different gateway or at a later
    time -- the v1 payload covered only the ciphertext fields and was replayable
    forever.
    """
    return (
        lv(packet["protocol_tag"])
        + lv(packet["gateway_id"])
        + u64(packet["root_epoch"])
        + u64(packet["issued_ms"])
        + lv(packet["kem_ciphertext"])
        + lv(packet["encrypted_root_key"])
        + lv(packet["nonce"])
        + lv(packet["tag"])
    )


def transfer_root_key(
    root_key: bytes,
    gateway_id: bytes = GATEWAY_ID,
    root_epoch: int | None = None,
    issued_ms: int | None = None,
) -> RootKeyPacket:
    """Encrypt and sign an externally supplied 256-bit ROOT_KEY for the gateway.

    The server does not generate, derive, log, or persist ``root_key``. ML-KEM
    establishes a fresh shared secret, SHA3-256 derives a context-bound
    transport key, AES-256-GCM encrypts the ROOT_KEY with the context as AAD,
    and ML-DSA-44 authenticates the whole packet.

    ``root_epoch`` defaults to the next value from the persisted counter.
    """
    if not isinstance(root_key, bytes) or len(root_key) != ROOT_KEY_BYTES:
        raise ValueError("root_key must be exactly 32 bytes")

    if root_epoch is None:
        root_epoch = next_root_epoch()
    if issued_ms is None:
        issued_ms = int(time.time() * 1000)

    gateway_public_key = _read_key(GATEWAY_KEM_PUBLIC_KEY_PATH)
    server_private_key = _read_key(SERVER_DSA_PRIVATE_KEY_PATH)
    context = transfer_context(gateway_id, root_epoch, issued_ms)

    try:
        shared_secret, kem_ciphertext = ML_KEM_512.encaps(gateway_public_key)
        transport_key = derive_transport_key(shared_secret, context)
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        ciphertext_and_tag = AESGCM(transport_key).encrypt(nonce, root_key, context)
    except (ValueError, TypeError) as error:
        raise KeyMaterialError("invalid gateway ML-KEM public key") from error

    encrypted_root_key = ciphertext_and_tag[:-AES_GCM_TAG_BYTES]
    tag = ciphertext_and_tag[-AES_GCM_TAG_BYTES:]

    packet: RootKeyPacket = {
        "protocol_tag": PROTOCOL_TAG,
        "gateway_id": gateway_id,
        "root_epoch": root_epoch,
        "issued_ms": issued_ms,
        "kem_ciphertext": kem_ciphertext,
        "encrypted_root_key": encrypted_root_key,
        "nonce": nonce,
        "tag": tag,
        "signature": b"",
    }
    try:
        packet["signature"] = ML_DSA_44.sign(server_private_key, _signature_payload(packet))
    except (ValueError, TypeError) as error:
        raise KeyMaterialError("invalid server ML-DSA private key") from error
    return packet


def main() -> None:
    """Local demonstration. Never generates the ROOT_KEY itself."""
    from gateway import initialize_gateway_keys, receive_root_key

    initialize_server_signing_keys()
    initialize_gateway_keys()

    root_key = b"12345678901234567890123456789012"
    packet = transfer_root_key(root_key)
    recovered = receive_root_key(packet)

    print(f"epoch      : {packet['root_epoch']}")
    print(f"sent       : {root_key.hex()}")
    print(f"recovered  : {recovered.hex()}")
    print(f"match      : {root_key == recovered}")

    # Replaying the same packet must now fail: the gateway has recorded this
    # epoch and will not accept it again.
    from config import ReplayError

    try:
        receive_root_key(packet)
        print("replay     : ACCEPTED  <-- this would be a bug")
    except ReplayError as error:
        print(f"replay     : rejected ({error})")


if __name__ == "__main__":
    main()
