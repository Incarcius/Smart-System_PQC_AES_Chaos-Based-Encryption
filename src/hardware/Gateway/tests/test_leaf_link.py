"""
test_leaf_link.py — cross-language KAT for the leaf <-> gateway link.

The ESP32 runs the C implementation; the gateway runs leaf_link.py. If they
diverge by one byte the gateway cannot decode its own sensors, so this diff is
the gate that keeps the link working.

Also checks the properties the handshake exists to provide, which a byte-level
KAT cannot express: a live round trip agrees on a key, and a MITM without the
device PSK does not.

Usage (from repo root):
    python src/hardware/Gateway/tests/test_leaf_link.py <path-to-leaf_kat.exe>
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

import leaf_link as ll  # noqa: E402

KEY = bytes((i * 9 + 4) & 0xFF for i in range(32))
PSK = bytes((i * 17 + 3) & 0xFF for i in range(32))
DH = bytes((i * 5 + 11) & 0xFF for i in range(32))

failures = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global failures
    if ok:
        print(f"  ok       {label}")
    else:
        failures += 1
        print(f"  FAIL     {label}")
        if detail:
            print(f"           {detail}")


def cobs_vectors() -> dict[str, str]:
    def pattern(n: int, kind: int) -> bytes:
        if kind == 0:
            return bytes(n)
        if kind == 1:
            return bytes((i % 255) + 1 for i in range(n))
        if kind == 2:
            return bytes(i % 2 for i in range(n))
        return bytes((i * 37) & 0xFF for i in range(n))

    cases = [
        ("cobs_zero1", 1, 0),
        ("cobs_zeros32", 32, 0),
        ("cobs_seq32", 32, 1),
        ("cobs_alt300", 300, 2),
        ("cobs_run254", 254, 1),
        ("cobs_run255", 255, 1),
        ("cobs_frame80", 80, 3),
    ]
    return {label: ll.cobs_encode(pattern(n, k)).hex() for label, n, k in cases}


def expected() -> dict[str, str]:
    out = cobs_vectors()

    hdr = ll.LeafHeader(
        endpoint_id=0xBEEF, key_epoch=0x01020304, seq=0x0A0B0C0D0E0F, channel_count=5
    )
    out["leaf_header"] = hdr.serialize().hex()
    out["leaf_nonce"] = hdr.nonce().hex()

    frame_hdr = ll.LeafHeader(endpoint_id=0x0007, key_epoch=11, seq=4242, channel_count=5)
    readings = [
        ll.ChannelReading(100.0 + i * 12.25, 0x02 if i == 3 else 0x00) for i in range(5)
    ]
    out["leaf_frame"] = ll.seal_frame(KEY, frame_hdr, 1757664000123, readings).hex()

    hello = bytearray(72)
    hello[0] = 0x01
    hello[1] = ll.MSG_HELLO
    hello[2:4] = (7).to_bytes(2, "big")
    hello[4:8] = (11).to_bytes(4, "big")
    hello[8:40] = bytes((i * 3 + 1) & 0xFF for i in range(32))
    hello[40:72] = bytes((i * 7 + 2) & 0xFF for i in range(32))

    ack = bytearray(72)
    ack[0] = 0x01
    ack[1] = ll.MSG_HELLO_ACK
    ack[2:4] = (7).to_bytes(2, "big")
    ack[8:40] = bytes((i * 11 + 5) & 0xFF for i in range(32))
    ack[40:72] = bytes((i * 13 + 6) & 0xFF for i in range(32))

    session = ll._derive_session(bytes(hello), bytes(ack), DH, PSK)
    out["hs_transcript"] = session.transcript.hex()
    out["hs_session_key"] = session.session_key.hex()
    out["hs_confirm_tag"] = ll.confirm_tag(session).hex()
    return out


def test_live_handshake() -> None:
    """A real round trip, with the C side's leaf role played by cryptography's
    X25519. Proves the two implementations agree on a key derived from actual
    ephemeral material, not just on fixed inputs."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    print("\n-- live handshake --")

    leaf_sk = x25519.X25519PrivateKey.generate()
    leaf_pub = leaf_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    hello = bytearray(72)
    hello[0] = 0x01
    hello[1] = ll.MSG_HELLO
    hello[2:4] = (7).to_bytes(2, "big")
    hello[4:8] = (3).to_bytes(4, "big")
    hello[8:40] = leaf_pub
    hello[40:72] = os.urandom(32)

    gw_session, ack = ll.respond(PSK, bytes(hello))

    gw_pub = x25519.X25519PublicKey.from_public_bytes(ack[8:40])
    dh = leaf_sk.exchange(gw_pub)
    leaf_session = ll._derive_session(bytes(hello), ack, dh, PSK)

    check(
        leaf_session.session_key == gw_session.session_key,
        "both sides derive the same session key",
    )
    check(leaf_session.transcript == gw_session.transcript, "transcripts match")

    confirm = bytearray(24)
    confirm[0] = 0x01
    confirm[1] = ll.MSG_CONFIRM
    confirm[2:4] = (7).to_bytes(2, "big")
    confirm[8:24] = ll.confirm_tag(leaf_session)

    try:
        ll.verify_confirm(gw_session, bytes(confirm))
        check(True, "gateway accepts the leaf's CONFIRM")
    except ll.LeafLinkError as exc:
        check(False, "gateway accepts the leaf's CONFIRM", str(exc))

    # MITM: an attacker completes the DH but has no PSK.
    wrong_psk = bytes(32)
    attacker = ll._derive_session(bytes(hello), ack, dh, wrong_psk)
    check(
        attacker.session_key != leaf_session.session_key,
        "MITM without the PSK cannot reach the leaf's key",
    )
    try:
        ll.verify_confirm(attacker, bytes(confirm))
        check(False, "attacker must fail CONFIRM verification")
    except ll.LeafLinkError:
        check(True, "attacker fails CONFIRM verification")


def test_frame_roundtrip() -> None:
    print("\n-- frame round trip and tamper detection --")

    hdr = ll.LeafHeader(endpoint_id=5, key_epoch=2, seq=99, channel_count=5)
    readings = [ll.ChannelReading(1.5 * i, 0) for i in range(5)]
    frame = ll.seal_frame(KEY, hdr, 1757664000000, readings)

    got_hdr, ts, got = ll.open_frame(KEY, frame)
    check(got_hdr.seq == 99 and ts == 1757664000000, "round trip preserves header")
    check(
        all(abs(a.value - b.value) < 1e-5 for a, b in zip(readings, got)),
        "round trip preserves values",
    )

    for label, off in [("header/AAD", 3), ("ciphertext", 20), ("tag", 70)]:
        bad = bytearray(frame)
        bad[off] ^= 0x01
        try:
            ll.open_frame(KEY, bytes(bad))
            check(False, f"tampered {label} must be rejected")
        except ll.LeafLinkError:
            check(True, f"tampered {label} rejected")

    # COBS must survive a real frame, and produce no zero bytes.
    wire = ll.cobs_encode(frame)
    check(0 not in wire, "COBS output contains no zero byte")
    check(ll.cobs_decode(wire) == frame, "COBS round trip on a real frame")


def main() -> int:
    global failures

    want = expected()

    if len(sys.argv) >= 2:
        print("-- C vs Python vectors --")
        proc = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True)
        got = dict(line.split() for line in proc.stdout.splitlines() if line.strip())
        for label, value in want.items():
            if label not in got:
                check(False, label, "missing from C output")
            elif got[label] != value:
                check(False, label, f"C {got[label][:48]}... != py {value[:48]}...")
            else:
                check(True, f"{label}  ({len(value) // 2} bytes)")
    else:
        print("(no C binary given - Python-side checks only)")

    test_frame_roundtrip()
    test_live_handshake()

    print()
    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
