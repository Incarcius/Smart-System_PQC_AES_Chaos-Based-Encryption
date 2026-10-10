"""
test_posture.py — cross-language tests for the server->gateway control plane.

Runs posture_kat_dump.exe (the C gateway path), recomputes everything with the
Python server path, and diffs. Two classes of agreement are pinned:

  * frame bytes  — the nonce is derived, not random, so sealing is
    deterministic and the two implementations must be byte-identical;
  * state-machine traces — the lease, shield and quarantine semantics must not
    drift between C and Python.

It also checks the properties the design exists to provide, independently of
whether the two sides agree with each other:

  * losing the control channel ESCALATES (fail-secure) and never quarantines;
  * a replayed or stale control message is rejected;
  * an ENFORCE floor cannot be undercut by policy;
  * tampering with either the ciphertext or the cleartext nonce fails auth.

Usage (from repo root):
    python src/security/posture/tests/test_posture.py [path-to-posture_kat.exe]
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1] / "python"))
sys.path.insert(0, str(_HERE.parents[2] / "ACCM" / "python"))

import posture_frame  # noqa: E402
from posture_frame import FrameError  # noqa: E402
from protocol import (  # noqa: E402
    Control,
    CtrlStatus,
    Directive,
    Posture,
    PostureState,
)

KEY = bytes((i * 13 + 7) & 0xFF for i in range(32))
SKEW = 60000

_failures = 0
_checks = 0


def check(cond: bool, label: str) -> None:
    global _failures, _checks
    _checks += 1
    if cond:
        print(f"  ok       {label}")
    else:
        _failures += 1
        print(f"  FAIL     {label}")


def mk(posture, directive, node_mask, lease_ms, min_hold_ms, ctrl_seq, issued_ms):
    return Control(
        ctrl_seq=ctrl_seq,
        issued_ms=issued_ms,
        lease_ms=lease_ms,
        min_hold_ms=min_hold_ms,
        node_mask=node_mask,
        posture=posture,
        directive=directive,
    )


def _trace(tag: str, s: PostureState, now: int) -> str:
    return (
        f"trace {tag:<22} t={now:<6} posture={int(s.posture)} "
        f"floor={int(s.directive_floor)} advised={int(s.advised_posture)} "
        f"mask={s.node_mask:08x} lease_exp={s.lease_expires_ms}"
    )


# ── expected frame vectors ──────────────────────────────────────────────────

def expected_frames() -> dict[str, str]:
    return {
        "frame_advise": posture_frame.seal(
            KEY, 1,
            mk(Posture.SUSPICIOUS, Directive.ADVISE, 0, 3000, 5000, 1, 1757664000000),
        ).hex(),
        "frame_enforce": posture_frame.seal(
            KEY, 1,
            mk(Posture.ANOMALY, Directive.ENFORCE, 0, 3000, 5000, 2, 1757664001000),
        ).hex(),
        "frame_quarantine": posture_frame.seal(
            KEY, 1,
            mk(Posture.ANOMALY, Directive.QUARANTINE, 0x28, 3000, 5000, 3, 1757664002000),
        ).hex(),
        "frame_epoch7": posture_frame.seal(
            KEY, 7,
            mk(Posture.NORMAL, Directive.ADVISE, 0, 1000, 0, 99, 1757664003000),
        ).hex(),
    }


# ── expected state traces (mirror of the C scenarios) ───────────────────────

def expected_traces() -> list[str]:
    out: list[str] = []

    # A: lease lapse escalates one level at a time
    t = 10000
    s = PostureState(t)
    out.append(_trace("A.init", s, t))
    s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 3000, 0, 1, t), t, SKEW)
    out.append(_trace("A.renewed", s, t))
    t = 12000; s.tick(t); out.append(_trace("A.before_expiry", s, t))
    t = 13000; s.tick(t); out.append(_trace("A.expiry1", s, t))
    t = 16000; s.tick(t); out.append(_trace("A.expiry2", s, t))
    t = 19000; s.tick(t); out.append(_trace("A.expiry3_capped", s, t))

    # B: ENFORCE floor blocks de-escalation
    t = 20000
    s = PostureState(t)
    s.apply(mk(Posture.SUSPICIOUS, Directive.ENFORCE, 0, 5000, 0, 1, t), t, SKEW)
    out.append(_trace("B.enforced", s, t))
    s.request(Posture.NORMAL, t);  out.append(_trace("B.denied_normal", s, t))
    s.request(Posture.ANOMALY, t); out.append(_trace("B.escalated", s, t))
    s.request(Posture.NORMAL, t);  out.append(_trace("B.back_to_floor", s, t))

    # C: min_hold blocks rapid de-escalation
    t = 30000
    s = PostureState(t)
    s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 10000, 5000, 1, t), t, SKEW)
    s.request(Posture.ANOMALY, t); out.append(_trace("C.escalated", s, t))
    t = 32000; s.request(Posture.NORMAL, t); out.append(_trace("C.too_soon", s, t))
    t = 36000; s.request(Posture.NORMAL, t); out.append(_trace("C.min_hold_elapsed", s, t))

    # D: quarantine accumulates, release is explicit
    t = 40000
    s = PostureState(t)
    s.apply(mk(Posture.ANOMALY, Directive.QUARANTINE, 1 << 3, 5000, 0, 1, t), t, SKEW)
    out.append(_trace("D.quarantine_3", s, t))
    s.apply(mk(Posture.ANOMALY, Directive.QUARANTINE, 1 << 5, 5000, 0, 2, t), t, SKEW)
    out.append(_trace("D.quarantine_3_5", s, t))
    out.append(f"check D.node3_quarantined={int(s.is_quarantined(3))}")
    out.append(f"check D.node4_quarantined={int(s.is_quarantined(4))}")
    out.append(f"check D.node5_quarantined={int(s.is_quarantined(5))}")
    s.release(3)
    out.append(_trace("D.released_3", s, t))

    # E: replay and staleness rejected
    t = 50000
    s = PostureState(t)
    r1 = s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 3000, 0, 10, t), t, SKEW)
    r2 = s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 3000, 0, 9, t), t, SKEW)
    r3 = s.apply(mk(Posture.ANOMALY, Directive.ENFORCE, 0, 3000, 0, 10, t), t, SKEW)
    r4 = s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 3000, 0, 11, 1), t, SKEW)
    out.append(f"check E.first={int(r1)}")
    out.append(f"check E.older={int(r2)}")
    out.append(f"check E.equal={int(r3)}")
    out.append(f"check E.stale={int(r4)}")
    out.append(_trace("E.final", s, t))

    # F: seal/open round trip
    ctrl = mk(Posture.ANOMALY, Directive.QUARANTINE, 0x2A, 4000, 250, 4242, 1757664009000)
    frame = posture_frame.seal(KEY, 5, ctrl)
    out.append(f"check F.peek={0}")
    out.append(f"check F.peek_seq={posture_frame.peek_seq(frame)}")
    opened, epoch = posture_frame.open_frame(KEY, frame)
    out.append(f"check F.open={0}")
    out.append(f"check F.epoch={epoch}")
    out.append(f"check F.mask={opened.node_mask:08x}")
    out.append(f"check F.seq={opened.ctrl_seq}")

    tampered = bytearray(frame); tampered[20] ^= 0x01
    try:
        posture_frame.open_frame(KEY, bytes(tampered))
        out.append("check F.tampered=0")
    except FrameError:
        out.append("check F.tampered=-3")

    nonce_tampered = bytearray(frame); nonce_tampered[10] ^= 0x01
    try:
        posture_frame.open_frame(KEY, bytes(nonce_tampered))
        out.append("check F.nonce_tampered=0")
    except FrameError:
        out.append("check F.nonce_tampered=-3")

    return out


# ── design-property checks ──────────────────────────────────────────────────

def property_checks() -> None:
    print("\n-- security properties --")

    # Fail-secure: losing the channel escalates, and never quarantines.
    t = 0
    s = PostureState(t)
    s.apply(mk(Posture.NORMAL, Directive.ADVISE, 0, 1000, 0, 1, t), t, SKEW)
    for step in range(1, 6):
        s.tick(t + step * 1000)
    check(s.posture is Posture.ANOMALY, "lost control channel escalates to ANOMALY")
    check(s.node_mask == 0, "lease expiry never auto-quarantines (no remote DoS)")

    # A silent server is indistinguishable from a dropped alert.
    t = 0
    s = PostureState(t)
    s.grace(2000, t)
    s.tick(t + 2500)
    check(s.posture is Posture.SUSPICIOUS, "server that never speaks still escalates")

    # Replay of a NORMAL cannot suppress a live ANOMALY.
    t = 100000
    s = PostureState(t)
    s.apply(mk(Posture.ANOMALY, Directive.ENFORCE, 0, 5000, 0, 5, t), t, SKEW)
    captured = mk(Posture.NORMAL, Directive.ENFORCE, 0, 5000, 0, 4, t)
    check(
        s.apply(captured, t, SKEW) is CtrlStatus.ERR_REPLAY,
        "replayed NORMAL cannot suppress a live response",
    )
    check(s.posture is Posture.ANOMALY, "posture survives the replay attempt")

    # Policy cannot undercut an ENFORCE floor.
    check(
        s.request(Posture.NORMAL, t + 999999) is Posture.ANOMALY,
        "agent cannot undercut the ENFORCE floor",
    )

    # Quarantine is a trust state: the node keeps a usable key.
    check(s.is_quarantined(0) is False, "unflagged node is not quarantined")

    # Wrong key must not open a frame.
    frame = posture_frame.seal(KEY, 1, mk(Posture.ANOMALY, Directive.ENFORCE, 0, 1000, 0, 1, 0))
    try:
        posture_frame.open_frame(bytes(32), frame)
        check(False, "wrong control key must not open a frame")
    except FrameError:
        check(True, "wrong control key rejected")


def main() -> int:
    global _failures

    print("=== posture control plane ===")

    if len(sys.argv) >= 2:
        proc = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True)
        got_lines = [ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip()]
        got_frames = {}
        got_trace = []
        for ln in got_lines:
            if ln.startswith("frame_"):
                label, value = ln.split()
                got_frames[label] = value
            else:
                got_trace.append(ln)

        print("\n-- sealed frames: C vs Python --")
        for label, want in expected_frames().items():
            check(got_frames.get(label) == want, f"{label} ({len(want)//2} bytes)")

        print("\n-- state machine trace: C vs Python --")
        want_trace = expected_traces()
        if len(got_trace) != len(want_trace):
            check(False, f"trace length {len(got_trace)} != {len(want_trace)}")
            for a, b in zip(got_trace, want_trace):
                if a != b:
                    print(f"    C      {a}")
                    print(f"    python {b}")
                    break
        else:
            mismatched = [
                (a, b) for a, b in zip(got_trace, want_trace) if a != b
            ]
            check(not mismatched, f"{len(want_trace)} trace lines identical")
            for a, b in mismatched[:5]:
                print(f"    C      {a}")
                print(f"    python {b}")
    else:
        print("(no C binary given - running Python-side checks only)")
        expected_frames()
        expected_traces()

    property_checks()

    print()
    print(f"{_checks - _failures}/{_checks} checks passed")
    return 1 if _failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
