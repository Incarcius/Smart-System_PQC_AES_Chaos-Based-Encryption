"""Configuration and shared types for the ROOT_KEY transfer subsystem.

v2 changes
----------
The v1 packet signed only (kem_ciphertext || ct || nonce || tag). Nothing in
those bytes said *who* the packet was for or *when* it was issued, so a
recorded packet verified forever: an attacker who captured one could replay it
at any later time and roll the gateway back onto an older ROOT_KEY -- and with
it, every session key derived from that root. v2 adds a recipient identity, a
monotonic epoch, and an issue timestamp, all covered by the signature and by
the AES-GCM AAD.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict


BASE_DIR = Path(__file__).resolve().parent
ROOT_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16

# Domain separation for everything in this subsystem. Bump the version suffix
# if any framing below changes, so old and new packets can never be confused.
PROTOCOL_TAG = b"pqc-rootkey/v2"

# Identity of this gateway. In deployment this is provisioned per device and
# must match the `gateway_id` the server addresses the packet to.
GATEWAY_ID = b"gw-substation-01"

# How far in the past or future an issued_ms may be before the gateway rejects
# it. Generous because SCADA gateways are not always NTP-tight; the monotonic
# epoch is the real replay defence, this is a secondary sanity bound.
MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000

# Gateway key material required by the startup flow.
GATEWAY_KEM_PUBLIC_KEY_PATH = BASE_DIR / "gateway_kem_pk.bin"
GATEWAY_KEM_PRIVATE_KEY_PATH = BASE_DIR / "gateway_kem_sk.bin"
GATEWAY_DSA_PUBLIC_KEY_PATH = BASE_DIR / "gateway_dsa_pk.bin"
GATEWAY_DSA_PRIVATE_KEY_PATH = BASE_DIR / "gateway_dsa_sk.bin"

# The server signs the transfer; the gateway verifies with this public key.
SERVER_DSA_PUBLIC_KEY_PATH = BASE_DIR / "server_dsa_pk.bin"
SERVER_DSA_PRIVATE_KEY_PATH = BASE_DIR / "server_dsa_sk.bin"

# Monotonic epoch counters. Persisted so that a reboot cannot reset them --
# a reset would reopen the replay window these files exist to close.
SERVER_ROOT_EPOCH_PATH = BASE_DIR / "server_root_epoch.txt"
GATEWAY_ROOT_EPOCH_PATH = BASE_DIR / "gateway_root_epoch.txt"


class RootKeyPacket(TypedDict):
    """The byte packet that carries an encrypted, externally supplied ROOT_KEY.

    Every field except ``signature`` is covered by the ML-DSA signature, and
    the context fields are additionally bound into the AES-GCM AAD.
    """

    protocol_tag: bytes
    gateway_id: bytes
    root_epoch: int
    issued_ms: int
    kem_ciphertext: bytes
    encrypted_root_key: bytes
    nonce: bytes
    tag: bytes
    signature: bytes


class RootKeyTransferError(Exception):
    """Base exception for ROOT_KEY transfer failures."""


class KeyMaterialError(RootKeyTransferError):
    """Raised when required ML-KEM or ML-DSA key material is absent or malformed."""


class PacketValidationError(RootKeyTransferError):
    """Raised when a received packet does not have the expected byte structure."""


class AuthenticationError(RootKeyTransferError):
    """Raised when ML-DSA verification or AES-GCM authentication fails."""


class ReplayError(RootKeyTransferError):
    """Raised when a packet is addressed elsewhere, stale, or replays an epoch."""
