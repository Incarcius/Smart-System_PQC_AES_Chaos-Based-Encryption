"""Canonical, unambiguous byte framing shared by the server and the gateway.

Everything that gets signed or hashed in this subsystem goes through ``lv()``.

Why length-prefixing matters
----------------------------
Plain concatenation is ambiguous: ``a || b`` with a=b"AB", b=b"C" produces the
same bytes as a=b"A", b=b"BC". If a signature or a key-derivation input is
built by concatenating variable-length fields, an attacker who can influence
two adjacent fields can sometimes shift the boundary between them and get a
different logical message to hash identically. Prefixing each field with its
length makes the encoding injective, so that class of attack disappears.

The same issue exists today in RXCR-Extract's finalizer, which hashes
``state || ikm || salt`` with no length prefixes -- see docs/PROJECT_STATUS.md.
"""

from __future__ import annotations

import struct


def lv(value: bytes) -> bytes:
    """Length-prefixed value: uint32 big-endian length, then the bytes."""
    if len(value) > 0xFFFFFFFF:
        raise ValueError("value too long to length-prefix")
    return struct.pack(">I", len(value)) + value


def u64(value: int) -> bytes:
    """Unsigned 64-bit big-endian."""
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"value out of uint64 range: {value}")
    return struct.pack(">Q", value)


def u32(value: int) -> bytes:
    """Unsigned 32-bit big-endian."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"value out of uint32 range: {value}")
    return struct.pack(">I", value)
