"""
test_accm_kat.py — cross-language KAT for ACCM v2.

Runs accm_kat_dump.exe (the C gateway path), recomputes every vector with the
Python server path, and diffs them. It also asserts the two properties the v2
rewrite exists to establish:

  * full key sensitivity — flipping session_key[31], a byte the v1 derivation
    never read, must change the keystream;
  * posture separation — each posture must yield a distinct keystream, and
    that selection must come from the authenticated header rather than
    implicit shared state.

Usage (from repo root):
    python src/security/ACCM/tests/test_accm_kat.py <path-to-accm_kat.exe>
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

from accm import AccmContext  # noqa: E402
from protocol import Header, Posture  # noqa: E402

KEY_A = bytes((i * 11 + 3) & 0xFF for i in range(32))
KEY_B = bytes(KEY_A[:31] + bytes([KEY_A[31] ^ 0x01]))
TAIL = bytes(0xA0 + i for i in range(8))
TS = 1757664000000


def _ks(key, posture, node_id, key_epoch, seq, ts, tail, length):
    header = Header(
        node_id=node_id,
        key_epoch=key_epoch,
        seq=seq,
        timestamp_ms=ts,
        posture=posture,
    )
    return AccmContext(key, header, tail).generate_stream(length).hex()


def expected() -> dict[str, str]:
    header = Header(
        node_id=0x1234,
        key_epoch=0xDEADBEEF,
        seq=0x0102030405060708,
        timestamp_ms=TS,
        posture=Posture.SUSPICIOUS,
    )
    return {
        "header": header.serialize().hex(),
        "nonce": header.nonce().hex(),
        "ks_normal": _ks(KEY_A, Posture.NORMAL, 1, 7, 42, TS, TAIL, 64),
        "ks_suspicious": _ks(KEY_A, Posture.SUSPICIOUS, 1, 7, 42, TS, TAIL, 64),
        "ks_anomaly": _ks(KEY_A, Posture.ANOMALY, 1, 7, 42, TS, TAIL, 64),
        "ks_keyb": _ks(KEY_B, Posture.NORMAL, 1, 7, 42, TS, TAIL, 64),
        "ks_seq43": _ks(KEY_A, Posture.NORMAL, 1, 7, 43, TS, TAIL, 64),
        "ks_epoch8": _ks(KEY_A, Posture.NORMAL, 1, 8, 42, TS, TAIL, 64),
        "ks_node2": _ks(KEY_A, Posture.NORMAL, 2, 7, 42, TS, TAIL, 64),
        "ks_ts": _ks(KEY_A, Posture.NORMAL, 1, 7, 42, TS + 100, TAIL, 64),
        "ks_zerotail": _ks(KEY_A, Posture.NORMAL, 1, 7, 42, TS, bytes(8), 64),
        "ks_long": _ks(KEY_A, Posture.ANOMALY, 9, 3, 1, 1700000000000, TAIL, 512),
    }


def check_properties(want: dict[str, str]) -> int:
    """Assert the security properties the rewrite is supposed to deliver."""
    failures = 0
    checks = [
        (
            "full key sensitivity (session_key[31] matters)",
            want["ks_normal"] != want["ks_keyb"],
        ),
        (
            "posture separation (NORMAL != SUSPICIOUS != ANOMALY)",
            len({want["ks_normal"], want["ks_suspicious"], want["ks_anomaly"]}) == 3,
        ),
        ("seq is an input", want["ks_normal"] != want["ks_seq43"]),
        ("key_epoch is an input", want["ks_normal"] != want["ks_epoch8"]),
        ("node_id is an input", want["ks_normal"] != want["ks_node2"]),
        ("timestamp is an input", want["ks_normal"] != want["ks_ts"]),
        ("prev_tail is an input", want["ks_normal"] != want["ks_zerotail"]),
    ]
    for label, ok in checks:
        print(f"{'ok      ' if ok else 'FAIL    '} {label}")
        if not ok:
            failures += 1
    return failures


def roundtrip_check() -> int:
    """Mask then unmask must be the identity, and chaining must advance."""
    header = Header(node_id=5, key_epoch=2, seq=11, timestamp_ms=TS)
    payload = bytes(range(256)) * 3

    ctx = AccmContext(KEY_A, header, TAIL)
    masked = ctx.mask(payload)
    recovered = AccmContext(KEY_A, header, TAIL).unmask(masked)

    failures = 0
    if recovered != payload:
        print("FAIL     mask/unmask round trip")
        failures += 1
    else:
        print("ok       mask/unmask round trip")

    if masked == payload:
        print("FAIL     mask is a no-op")
        failures += 1

    ctx.chain_update(masked)
    if ctx.prev_tail != masked[-8:]:
        print("FAIL     chain_update")
        failures += 1
    else:
        print("ok       chain_update")

    return failures


def main() -> int:
    want = expected()
    failures = 0

    if len(sys.argv) >= 2:
        proc = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True)
        got = dict(line.split() for line in proc.stdout.splitlines() if line.strip())
        for label, value in want.items():
            if label not in got:
                print(f"MISSING  {label}")
                failures += 1
            elif got[label] != value:
                print(f"MISMATCH {label}")
                print(f"   C      {got[label][:64]}...")
                print(f"   python {value[:64]}...")
                failures += 1
            else:
                print(f"ok       {label}  ({len(value) // 2} bytes)")
        print()
    else:
        print("(no C binary given — running Python-side checks only)\n")

    failures += check_properties(want)
    failures += roundtrip_check()

    print()
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
