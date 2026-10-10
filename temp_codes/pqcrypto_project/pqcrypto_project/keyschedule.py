"""Canonical RXCR-KDF inputs for the gateway's session-key pool.

This module answers "what should RXCR-Extract actually take as IKM and salt?"
-- previously unspecified, so the demo passed an ad-hoc string.

    IKM  = ROOT_KEY || transcript_hash
    salt = lv(protocol_tag) || lv(node_id) || u32(key_epoch)
    info = b"rxcr-kmac-kdf/v2|pq-iot-telemetry"

Why bind the transcript
-----------------------
``transcript_hash`` commits to the exact handshake that delivered this
ROOT_KEY: the protocol tag, the recipient, the epoch, the KEM ciphertext, and
both long-term public keys. Two consequences:

  * session keys derived under different handshakes are unrelated even if the
    same ROOT_KEY were somehow installed twice, so a replayed or re-injected
    root key cannot resurrect previously-used session keys;
  * key material is bound to the identities it was negotiated between, which
    is what stops a packet meant for one gateway being made to derive usable
    keys on another.

The ROOT_KEY stays first in the IKM so that the extractor's security rests on
it; the transcript is context, not entropy, and is assumed public.

Note on forward secrecy
-----------------------
The gateway's ML-KEM keypair is long-term and stored on disk, so this exchange
is NOT forward secret: an attacker who later recovers ``gateway_kem_sk.bin``
can decapsulate recorded transfers and recover past ROOT_KEYs. Rotating the
gateway KEM keypair per epoch (and having the server re-fetch the public key
over an authenticated channel) is the fix; it is not implemented yet and is
tracked in docs/PROJECT_STATUS.md.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from wire import lv, u32, u64

# The RXCR-KMAC-KDF reference implementation lives outside this package.
_KDF_ROOT = Path(__file__).resolve().parents[2] / "RXCR-KMAC-KDF"
if str(_KDF_ROOT) not in sys.path:
    sys.path.insert(0, str(_KDF_ROOT))

from python.kdf import rxcr_kdf  # noqa: E402

KDF_INFO = b"rxcr-kmac-kdf/v2|pq-iot-telemetry"

# Node identifiers used by the gateway's pool. "ctrl" is deliberately separate
# from telemetry so that a posture-control key can never collide with a data
# key -- the KDF's customisation string keeps them apart.
NODE_TELEMETRY = b"gw-telemetry"
NODE_CONTROL = b"gw-ctrl"


def transcript_hash(
    protocol_tag: bytes,
    gateway_id: bytes,
    root_epoch: int,
    kem_ciphertext: bytes,
    gateway_kem_pk: bytes,
    server_dsa_pk: bytes,
) -> bytes:
    """SHA3-256 commitment to the handshake that delivered a ROOT_KEY."""
    return hashlib.sha3_256(
        lv(b"rxcr-kmac-kdf/v2/transcript")
        + lv(protocol_tag)
        + lv(gateway_id)
        + u64(root_epoch)
        + lv(kem_ciphertext)
        + lv(gateway_kem_pk)
        + lv(server_dsa_pk)
    ).digest()


def kdf_ikm(root_key: bytes, transcript: bytes) -> bytes:
    """IKM = ROOT_KEY || transcript_hash (64 bytes)."""
    if len(root_key) != 32:
        raise ValueError("root_key must be 32 bytes")
    if len(transcript) != 32:
        raise ValueError("transcript must be 32 bytes")
    return root_key + transcript


def kdf_salt(protocol_tag: bytes, node_id: bytes, key_epoch: int) -> bytes:
    """Salt binds the derivation to a node and a session-key generation.

    ``key_epoch`` is the same counter that appears in the telemetry frame
    header and in the AES-GCM nonce, so rotating it re-derives the pool and
    simultaneously resets the nonce space. That coupling is intentional: it
    makes "new key" and "new nonce space" a single indivisible step.
    """
    return lv(protocol_tag) + lv(node_id) + u32(key_epoch)


def derive_session_pool(
    root_key: bytes,
    transcript: bytes,
    protocol_tag: bytes,
    key_epoch: int,
    node_contexts: list[dict],
) -> dict[bytes, bytes]:
    """Derive the per-node session-key pool for one key_epoch.

    ``node_contexts`` entries are {node_id, algo, key_len}, as rxcr_kdf expects.
    Each node gets its own salt, so one node's keys are independent of another's.
    """
    ikm = kdf_ikm(root_key, transcript)
    pool: dict[bytes, bytes] = {}

    for ctx in node_contexts:
        salt = kdf_salt(protocol_tag, ctx["node_id"], key_epoch)
        derived = rxcr_kdf(ikm, salt, KDF_INFO, [ctx])
        pool.update(derived)

    return pool


def telemetry_contexts(key_len: int = 32) -> list[dict]:
    """The standard two-key pool for a gateway: telemetry data and control."""
    return [
        {"node_id": NODE_TELEMETRY, "algo": "AES-GCM", "key_len": key_len},
        {"node_id": NODE_CONTROL, "algo": "AES-GCM", "key_len": key_len},
    ]
