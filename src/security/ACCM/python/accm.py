"""
accm.py — ACCM v2, Python mirror of src/security/ACCM/src/accm.c.

The gateway masks in C; this side unmasks in Python. Both are integer-only, so
they agree bit-for-bit without depending on IEEE-754 corner cases. See accm.h
for the full rationale; the short version:

  * every map parameter is derived with KMACXOF256 keyed on all 32 bytes of
    the session key (v1 used 64 bits of it and ignored the rest);
  * arithmetic is Q32 for the coupled logistic pair and Q16 for Lorenz, so
    there is no float anywhere in the keystream path;
  * epsilon comes from the authenticated `posture` header field, so the two
    ends cannot silently disagree about which attractor is live.

Python's >> floors for negative ints, which is what C's arithmetic shift does
on every compiler this targets; tests/test_accm_kat.py pins the agreement.
"""

from __future__ import annotations

import sys
from pathlib import Path

from protocol import HEADER_LEN, TAIL_LEN, Header, Posture

# The KMAC reference lives in the RXCR-KMAC-KDF tree; no packaging in this
# repo yet, so wire it onto sys.path explicitly.
_KDF_ROOT = Path(__file__).resolve().parents[4] / "temp_codes" / "RXCR-KMAC-KDF"
if str(_KDF_ROOT) not in sys.path:
    sys.path.insert(0, str(_KDF_ROOT))

from python.kmac import kmacxof256  # noqa: E402

KEY_LEN = 32

# ── Q32 fixed point ─────────────────────────────────────────────────────────
Q32_ONE = 1 << 32
Q32_MARGIN = 1 << 20  # keep ~0.00024 away from the 0 and 1 fixed points

# ── Q30 rate parameters, r in [3.57, 3.999] ────────────────────────────────
R_MIN_Q30 = 3833258313  # round(3.570 * 2**30)
R_SPAN_Q30 = 460635243  # round(0.429 * 2**30)

# ── Q16 Lorenz constants ────────────────────────────────────────────────────
L_SHIFT = 16
L_ONE = 1 << L_SHIFT
L_CLAMP = 64 << L_SHIFT
L_SIGMA_DT = 6554  # round(0.1      * 2**16)
L_RHO = 28 * L_ONE
L_BETA_DT = 1748  # round(8/3*0.01 * 2**16)
L_DT = 655  # round(0.01     * 2**16)
L_STEPS = 500

_CUSTOM_SEED = b"ACCM-v2/lorenz-seed"
_CUSTOM_PARAMS = b"ACCM-v2/params"
_CUSTOM_STREAM = b"ACCM-v2/stream"

# Base-stream block size; mirrors ACCM_CHUNK in accm.c.
CHUNK = 256

# NORMAL 0.10, SUSPICIOUS 0.25, ANOMALY 0.40 — as exact Q32 integers.
_EPSILON_Q32 = {
    Posture.NORMAL: 429496729,
    Posture.SUSPICIOUS: 1073741824,
    Posture.ANOMALY: 1717986918,
}


def epsilon_q32(posture: Posture) -> int:
    """Coupling strength for a posture. Mirrors accm_epsilon_q32()."""
    return _EPSILON_Q32.get(Posture(posture), _EPSILON_Q32[Posture.NORMAL])


def _mul_q32(a: int, b: int) -> int:
    return (a * b) >> 32


def _logistic_q32(r_q30: int, x: int) -> int:
    """r * x * (1 - x); x is Q32, r is Q30, result is Q32."""
    t = _mul_q32(x, Q32_ONE - x)
    return (r_q30 * t) >> 30


def _extract(x: int, y: int) -> int:
    """Fold both states into one byte. Mirrors accm_extract().

    The two states are sampled at different bit offsets on purpose: v1 XORed
    the same slice of each, so strong coupling driving x toward y collapsed
    the output to zero.
    """
    v = (x ^ (y << 7) ^ (x >> 13) ^ (y >> 19)) & 0xFFFFFFFFFFFFFFFF
    return (v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24)) & 0xFF


def _clamp_state(x: int) -> int:
    if x < Q32_MARGIN:
        return Q32_MARGIN
    if x > Q32_ONE - Q32_MARGIN:
        return Q32_ONE - Q32_MARGIN
    return x


def _rate_from_u16(v: int) -> int:
    return R_MIN_Q30 + (v * R_SPAN_Q30) // 65535


def _l_clamp(v: int) -> int:
    if v > L_CLAMP:
        return L_CLAMP
    if v < -L_CLAMP:
        return -L_CLAMP
    return v


def _lorenz_q16(seed: bytes) -> tuple[int, int, int]:
    """Euler-integrate Lorenz in Q16. Mirrors lorenz_q16() exactly."""
    rx = int.from_bytes(seed[0:4], "big")
    ry = int.from_bytes(seed[4:8], "big")
    rz = int.from_bytes(seed[8:12], "big")

    x = (rx % (20 * L_ONE)) - 10 * L_ONE
    y = (ry % (20 * L_ONE)) - 10 * L_ONE
    z = rz % (30 * L_ONE)

    for _ in range(L_STEPS):
        dx = (L_SIGMA_DT * (y - x)) >> L_SHIFT
        dy = ((((x * (L_RHO - z)) >> L_SHIFT) - y) * L_DT) >> L_SHIFT
        dz = (((x * y) >> L_SHIFT) * L_DT >> L_SHIFT) - ((L_BETA_DT * z) >> L_SHIFT)

        x = _l_clamp(x + dx)
        y = _l_clamp(y + dy)
        z = _l_clamp(z + dz)

    return x, y, z


def _to_be64_signed(v: int) -> bytes:
    """Two's-complement 8-byte big-endian, matching put_be64_signed()."""
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


class AccmContext:
    """Per-frame masking context. One instance per peer; chain it forward."""

    def __init__(
        self,
        session_key: bytes,
        header: Header,
        prev_tail: bytes | None = None,
    ) -> None:
        if len(session_key) != KEY_LEN:
            raise ValueError(f"session key must be {KEY_LEN} bytes")
        if prev_tail is not None and len(prev_tail) != TAIL_LEN:
            raise ValueError(f"prev_tail must be {TAIL_LEN} bytes")
        self.session_key = session_key
        self.header = header
        self.prev_tail = prev_tail if prev_tail is not None else bytes(TAIL_LEN)

    def _derive_params(self) -> tuple[bytes, int, int, int, int, int]:
        """Returns (expand, x, y, r1, r2, eps). Mirrors gen_init()."""
        ctxbuf = self.header.serialize() + self.prev_tail
        assert len(ctxbuf) == HEADER_LEN + TAIL_LEN

        seed = kmacxof256(self.session_key, ctxbuf, 12, _CUSTOM_SEED)
        lorenz = _lorenz_q16(seed)

        expand = ctxbuf + b"".join(_to_be64_signed(v) for v in lorenz)
        params = kmacxof256(self.session_key, expand, 20, _CUSTOM_PARAMS)

        x = _clamp_state(int.from_bytes(params[0:8], "big") % Q32_ONE)
        y = _clamp_state(int.from_bytes(params[8:16], "big") % Q32_ONE)
        r1 = _rate_from_u16(int.from_bytes(params[16:18], "big"))
        r2 = _rate_from_u16(int.from_bytes(params[18:20], "big"))
        eps = epsilon_q32(self.header.posture)
        return expand, x, y, r1, r2, eps

    def generate_stream(self, length: int) -> bytes:
        """Keystream = KMACXOF256 base stream XOR chaotic byte.

        The base stream is what makes the output uniform; the chaotic map
        supplies posture-dependent structure on top. See the long comment in
        accm.c for the measurements that forced this construction.
        """
        expand, x, y, r1, r2, eps = self._derive_params()
        one_minus_eps = Q32_ONE - eps
        out = bytearray(length)

        done = 0
        chunk = 0
        while done < length:
            n = min(CHUNK, length - done)
            base = kmacxof256(
                self.session_key,
                expand + chunk.to_bytes(4, "big"),
                n,
                _CUSTOM_STREAM,
            )

            for i in range(n):
                lx = _logistic_q32(r1, x)
                ly = _logistic_q32(r2, y)
                xn = _mul_q32(one_minus_eps, lx) + _mul_q32(eps, ly)
                yn = _mul_q32(one_minus_eps, ly) + _mul_q32(eps, lx)

                x = _clamp_state(xn)
                y = _clamp_state(yn)

                out[done + i] = base[i] ^ _extract(x, y)

            done += n
            chunk += 1

        return bytes(out)

    def mask(self, data: bytes) -> bytes:
        stream = self.generate_stream(len(data))
        return bytes(a ^ b for a, b in zip(data, stream))

    # XOR is self-inverse.
    unmask = mask

    def chain_update(self, masked: bytes) -> None:
        """Roll prev_tail forward. Mirrors accm_chain_update()."""
        if len(masked) >= TAIL_LEN:
            self.prev_tail = bytes(masked[-TAIL_LEN:])
        else:
            self.prev_tail = bytes(TAIL_LEN - len(masked)) + bytes(masked)
