"""
accm_stats.py — statistical sanity checks on an ACCM v2 keystream corpus.

This is a screening tool, not a security proof. A keystream can pass every
test here and still be predictable; these tests only catch gross structural
defects. The security floor of the link is AES-256-GCM underneath the mask,
and that is what the paper should claim (see accm.h).

The specific defect being screened for: a logistic map's invariant density is
arcsine-distributed, concentrated near 0 and 1, so a naive floor(x * 256) byte
extraction is visibly non-uniform. ACCM XORs the two coupled states, which
should flatten it -- this measures whether it actually does.

Usage:
    python src/security/ACCM/tests/accm_stats.py <corpus.bin> [more.bin ...]
"""

from __future__ import annotations

import math
import sys
from collections import Counter
from pathlib import Path


def chi_square_bytes(data: bytes) -> tuple[float, int, float]:
    """Chi-square goodness of fit against a uniform byte distribution."""
    counts = Counter(data)
    n = len(data)
    expected = n / 256.0
    chi = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
    df = 255
    return chi, df, _chi_square_sf(chi, df)


def _chi_square_sf(x: float, df: int) -> float:
    """Survival function for chi-square via the Wilson-Hilferty approximation.

    Accurate to ~1e-3 for df >= 30, which is plenty for a screening verdict
    and avoids a scipy dependency.
    """
    if x <= 0:
        return 1.0
    t = (x / df) ** (1.0 / 3.0)
    mean = 1.0 - 2.0 / (9.0 * df)
    sd = math.sqrt(2.0 / (9.0 * df))
    z = (t - mean) / sd
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def monobit(data: bytes) -> tuple[float, float]:
    """NIST SP 800-22 frequency (monobit) test."""
    ones = sum(bin(b).count("1") for b in data)
    n = len(data) * 8
    s_obs = abs(2 * ones - n) / math.sqrt(n)
    return s_obs, math.erfc(s_obs / math.sqrt(2.0))


def runs_test(data: bytes) -> tuple[float, float] | None:
    """NIST SP 800-22 runs test."""
    bits = []
    for b in data:
        bits.extend((b >> i) & 1 for i in range(7, -1, -1))
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return None  # monobit prerequisite failed
    v = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(v - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return v, math.erfc(num / den)


def serial_correlation(data: bytes) -> float:
    """Lag-1 autocorrelation of the byte sequence."""
    n = len(data)
    mean = sum(data) / n
    num = sum((data[i] - mean) * (data[i + 1] - mean) for i in range(n - 1))
    den = sum((b - mean) ** 2 for b in data)
    return num / den if den else 0.0


def byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte; 8.0 is ideal."""
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyse(path: Path) -> int:
    data = path.read_bytes()
    if not data:
        print(f"{path}: empty")
        return 1

    print(f"=== {path.name}  ({len(data):,} bytes) ===")

    ent = byte_entropy(data)
    chi, df, chi_p = chi_square_bytes(data)
    s_obs, mono_p = monobit(data)
    sc = serial_correlation(data)
    runs = runs_test(data)

    counts = Counter(data)
    lo = min(counts.get(b, 0) for b in range(256))
    hi = max(counts.get(b, 0) for b in range(256))
    exp = len(data) / 256

    failures = 0

    def verdict(ok: bool) -> str:
        nonlocal failures
        if not ok:
            failures += 1
        return "ok  " if ok else "FAIL"

    print(f" {verdict(ent > 7.99)} entropy            {ent:.6f} bits/byte (ideal 8.0)")
    print(f" {verdict(chi_p > 0.01)} chi-square         {chi:.1f} (df={df}), p={chi_p:.4f}")
    print(f" {verdict(mono_p > 0.01)} monobit            S={s_obs:.4f}, p={mono_p:.4f}")
    if runs is None:
        print(f" {verdict(False)} runs               skipped (monobit prerequisite failed)")
    else:
        v, runs_p = runs
        print(f" {verdict(runs_p > 0.01)} runs               V={v:,}, p={runs_p:.4f}")
    print(f" {verdict(abs(sc) < 0.01)} lag-1 correlation  {sc:+.6f} (ideal 0)")
    print(f"      byte counts        min={lo:,} max={hi:,} expected={exp:,.0f}")
    print()
    return failures


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: accm_stats.py <corpus.bin> [more.bin ...]", file=sys.stderr)
        return 2

    total = 0
    for arg in sys.argv[1:]:
        total += analyse(Path(arg))

    if total:
        print(f"{total} check(s) failed")
    else:
        print("all checks passed")
        print()
        print("Screening only. For a defensible result, run NIST SP 800-22 STS")
        print("over >= 55 sequences of 1,000,000 bits each and report the")
        print("proportion and uniformity columns.")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
