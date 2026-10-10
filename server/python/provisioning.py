"""
provisioning.py — delivering a ROOT_KEY, and agreeing on the transcript.

Wraps the ML-KEM + ML-DSA transfer in `temp_codes/pqcrypto_project` and closes
a gap that was open until now: `GatewayState.install_root_key()` takes a
`transcript`, and nothing said where it came from.

The transcript is what binds derived session keys to the exact handshake that
delivered the ROOT_KEY — protocol tag, recipient, epoch, KEM ciphertext, and
both long-term public keys. Two consequences:

  * session keys from different transfers are unrelated, so a replayed or
    re-injected ROOT_KEY cannot resurrect previously-used session keys;
  * key material is bound to the identities it was negotiated between.

Both ends compute it from the packet, independently. It is never transmitted,
so there is nothing to forge: a gateway that computed a different transcript
simply derives different keys and its first frame fails to open.

This runs over a provisioning channel, not the telemetry link — physical
access, a commissioning laptop, or a separate authenticated session. It happens
once per ROOT_KEY, not per batch.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PQC = _REPO / "temp_codes" / "pqcrypto_project" / "pqcrypto_project"
if str(_PQC) not in sys.path:
    sys.path.insert(0, str(_PQC))

from config import (  # noqa: E402
    GATEWAY_KEM_PUBLIC_KEY_PATH,
    PROTOCOL_TAG,
    SERVER_DSA_PUBLIC_KEY_PATH,
    RootKeyPacket,
)
from keyschedule import transcript_hash  # noqa: E402


def packet_transcript(packet: RootKeyPacket) -> bytes:
    """Compute the transcript both ends must agree on, from the packet alone.

    Reads the two long-term public keys from disk, which is what makes this a
    commitment to *identities* rather than just to bytes on the wire.
    """
    return transcript_hash(
        packet["protocol_tag"],
        packet["gateway_id"],
        packet["root_epoch"],
        packet["kem_ciphertext"],
        GATEWAY_KEM_PUBLIC_KEY_PATH.read_bytes(),
        SERVER_DSA_PUBLIC_KEY_PATH.read_bytes(),
    )


def issue_root_key(root_key: bytes, gateway_id: bytes | None = None):
    """Server side: seal a ROOT_KEY and return (packet, transcript).

    The server does not generate the ROOT_KEY — it is supplied externally, as
    `transfer_root_key` requires. Key generation is a provisioning decision,
    not something a daemon should do on its own.
    """
    from server import transfer_root_key

    packet = (
        transfer_root_key(root_key, gateway_id)
        if gateway_id is not None
        else transfer_root_key(root_key)
    )
    return packet, packet_transcript(packet)


def accept_root_key(packet: RootKeyPacket, enforce_epoch: bool = True):
    """Gateway side: verify and open a packet, returning (root_key, transcript).

    `receive_root_key` does the real work: ML-DSA verification before ML-KEM
    decapsulation, recipient and epoch checks, then AES-GCM with the context as
    AAD. It raises on replay, which is the behaviour you want — a rolled-back
    ROOT_KEY would silently take every session key with it.
    """
    from gateway import receive_root_key

    root_key = receive_root_key(packet, enforce_epoch=enforce_epoch)
    return root_key, packet_transcript(packet)


__all__ = ["accept_root_key", "issue_root_key", "packet_transcript", "PROTOCOL_TAG"]
