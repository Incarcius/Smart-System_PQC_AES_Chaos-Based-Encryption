"""Redraw the system workflow flowchart for the current architecture.

Replaces the Semester 4 report diagram. Changes, all of them substantive:

  * HKDF becomes RXCR-KMAC-KDF (rotate-mix pre mix, SHA3-256 floor, KMACXOF256
    expand, domain separated per node and per purpose).
  * The Isolation Forest stage is gone. Detection is the LSTM autoencoder with
    empirical CDF calibration, which also supplies channel attribution.
  * The sensor node no longer performs the lattice exchange. It runs X25519
    bound to its provisioned PSK; ML-KEM-512 and ML-DSA-44 sit between gateway
    and server.
  * AES becomes AES-256-GCM with the deterministic epoch and sequence nonce and
    the frame header as associated data.
  * Chaos masking moves OUTSIDE the authenticated encryption.
  * Three outcome branches become the four level posture ladder, with
    quarantine continuing to ingest data and releasing only on explicit triage.
  * The learned controller runs every cycle under a safety shield rather than
    appearing only on the suspicious branch.
  * The lease path is added: expiry escalates without instruction and never
    quarantines, and the adopted posture is echoed back for verification.

Layout is computed top down rather than hand placed, so group titles cannot
collide with their first box and a box always fits its own text. The two outer
margins are reserved for the feedback paths, so no arrow crosses a box.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent / "fig5_workflow.png"
plt.rcParams.update({"font.family": "serif",
                     "font.serif": ["Times New Roman", "DejaVu Serif"]})

INK, SOFT = "#111111", "#555555"
GX, GW = 12, 76          # group band; 0-12 and 88-100 hold the feedback paths
TITLE_H = 7.6            # vertical space a group title reserves
PAD = 3.0                # padding inside a group
VGAP = 2.6               # gap between stacked boxes
STAGE_GAP = 9.0          # gap between groups, where the arrow lives
LINE_H = 3.9             # per text line inside a box
HEAD_H = 7.2             # box title block

fig, ax = plt.subplots(figsize=(3.3, 8.5))
ax.axis("off")

cursor = [0.0]           # running y, measured downward from 0


def box_height(lines):
    return HEAD_H + LINE_H * len(lines) + 1.6


def draw_box(x, top, w, title, lines, fs=4.75):
    h = box_height(lines)
    ax.add_patch(FancyBboxPatch(
        (x, -top - h), w, h, boxstyle="round,pad=0.32,rounding_size=0.9",
        linewidth=0.65, edgecolor=INK, facecolor="white"))
    ax.text(x + w / 2, -top - 3.4, title, ha="center", va="center",
            fontsize=5.6, fontweight="bold", color=INK)
    for i, ln in enumerate(lines):
        ax.text(x + 2.0, -top - HEAD_H - 1.0 - i * LINE_H, ln,
                ha="left", va="center", fontsize=fs, color=SOFT)
    return h


def stage(title, rows, side_by_side=False):
    """rows: list of (title, lines). Returns (top, bottom) of the group."""
    top = cursor[0]
    if side_by_side:
        h_in = max(box_height(l) for _, l in rows)
    else:
        h_in = sum(box_height(l) for _, l in rows) + VGAP * (len(rows) - 1)
    gh = TITLE_H + h_in + PAD

    ax.add_patch(FancyBboxPatch(
        (GX, -top - gh), GW, gh, boxstyle="round,pad=0.5,rounding_size=1.3",
        linewidth=0.9, edgecolor=INK, facecolor="none"))
    ax.text(GX + GW / 2, -top - 4.0, title, ha="center", va="center",
            fontsize=6.3, fontweight="bold", color=INK)

    y = top + TITLE_H
    if side_by_side:
        w = (GW - 6 - 4) / 2
        for i, (bt, bl) in enumerate(rows):
            draw_box(GX + 3 + i * (w + 4), y, w, bt, bl)
    else:
        for bt, bl in rows:
            y += draw_box(GX + 3, y, GW - 6, bt, bl) + VGAP

    cursor[0] = top + gh + STAGE_GAP
    return top, top + gh


def arrow(x1, y1, x2, y2, rad=0.0, color=INK, dashed=False, ms=6.0, lw=0.75):
    ax.add_patch(FancyArrowPatch(
        (x1, -y1), (x2, -y2), arrowstyle="-|>", mutation_scale=ms,
        linewidth=lw, color=color,
        linestyle=(0, (2.4, 2.0)) if dashed else "solid",
        connectionstyle="arc3,rad=%.2f" % rad))


# ── stages ─────────────────────────────────────────────────────────────────
s1 = stage("1.  Node Boot and Provisioning", [
    ("Device Startup", ["Firmware, crypto core,", "channel configuration"]),
    ("PSK Retrieval", ["32 B device key in NVS;", "will not run without it"]),
], side_by_side=True)

s2 = stage("2.  Session Establishment", [
    ("Node to Gateway", ["X25519 ephemeral bound", "to the device PSK;",
                         "no lattice work on node"]),
    ("Gateway to Server", ["ML-KEM-512 encapsulation,", "ML-DSA-44 signature,",
                           "transcript bound"]),
], side_by_side=True)

s3 = stage("3.  Key Derivation  (RXCR-KMAC-KDF)", [
    ("Extract", ["Rotate and mix pre mix, then SHA3-256 finalizer; the",
                 "output is never weaker than SHA3-256 over the inputs."]),
    ("Expand  (KMACXOF256, domain separated)",
     ["Telemetry key, control key and ACCM seed, per node and",
      "per purpose, in one pass for the whole key pool."]),
])

s4 = stage("4.  Telemetry Pipeline  (1 s window)", [
    ("Aggregate Window", ["Five channels, quality flagged. Quarantined channels",
                          "stay ingested and forwarded, marked untrusted."]),
    ("AES-256-GCM Seal", ["Nonce = key epoch (4 B) || sequence (8 B).",
                          "Frame header is the associated data."]),
    ("ACCM Mask  (outside the AEAD)",
     ["Coupling strength from posture; parameters re derived",
      "per frame and chained by the previous keystream tail."]),
])

s5 = stage("5.  Detection  (control server)", [
    ("LSTM Autoencoder", ["Reconstruction error over a 60 step window.",
                          "Empirical CDF calibration gives a score in [0, 1].",
                          "Per feature error names the responsible channel."]),
])

s6 = stage("6.  Decision and Control", [
    ("Lease Issuer", ["ADVISE, ENFORCE or", "QUARANTINE directive"]),
    ("Learned Controller", ["20 features, 8 actions,", "bounded by safety shield"]),
], side_by_side=True)

ladder_top = cursor[0] - STAGE_GAP + 0.0
# Posture ladder sits just under stage 6, inside its own light frame.
lh = draw_box(GX, cursor[0] - STAGE_GAP + 4.0, GW, "Posture Ladder",
              ["NORMAL  >  SUSPICIOUS  >  ANOMALY  >  QUARANTINE"], fs=5.0)
lad_bottom = cursor[0] - STAGE_GAP + 4.0 + lh
cursor[0] = lad_bottom + STAGE_GAP

# ── outcomes ───────────────────────────────────────────────────────────────
oy = cursor[0]
ow = 30
draw_box(2, oy, ow, "Normal", ["Data released to", "the SCADA backend"])
draw_box(35, oy, ow, "Elevated", ["Rotate keys and", "tighten reporting"])
draw_box(68, oy, ow, "Quarantine", ["Channel isolated,", "released on triage"])
bottom = oy + box_height(["a", "b"])

# ── inter-stage arrows ─────────────────────────────────────────────────────
for a, b in ((s1, s2), (s2, s3), (s3, s4), (s4, s5), (s5, s6)):
    arrow(50, a[1], 50, b[0])
arrow(50, s6[1], 50, lad_bottom - lh + 1.4)
arrow(50, lad_bottom, 17, oy, rad=0.10, ms=5.5)
arrow(50, lad_bottom, 50, oy, ms=5.5)
arrow(50, lad_bottom, 83, oy, rad=-0.10, ms=5.5)

# ── feedback paths in the reserved margins ─────────────────────────────────
mid4 = (s4[0] + s4[1]) / 2
mid6 = (s6[0] + s6[1]) / 2
for x, xin, text, rad in (
    (95, 88, "lease expiry escalates one level, never quarantines", 0),
    (5, 12, "adopted posture echoed in the next authenticated header", 0),
):
    ax.plot([x, x], [-mid6, -mid4], lw=0.75, color=SOFT,
            linestyle=(0, (2.4, 2.0)))
    ax.plot([x, (x + xin) / 2 if x > 50 else (x + xin) / 2], [-mid6, -mid6],
            lw=0.75, color=SOFT, linestyle=(0, (2.4, 2.0)))
    arrow(x, mid4, xin, mid4, color=SOFT, dashed=True, ms=5.0)
    ax.text(x + (2.6 if x > 50 else -2.6), -mid4 - (mid6 - mid4) / 2, text,
            ha="center", va="center", fontsize=4.4, color=SOFT, rotation=90)
# join the margin lines to the decision stage
ax.plot([ (95+88)/2, 88], [-mid6, -mid6], lw=0.75, color=SOFT,
        linestyle=(0, (2.4, 2.0)))
ax.plot([ (5+12)/2, 12], [-mid6, -mid6], lw=0.75, color=SOFT,
        linestyle=(0, (2.4, 2.0)))

ax.set_xlim(0, 100)
ax.set_ylim(-bottom - 2, 2)
fig.tight_layout(pad=0.1)
fig.savefig(OUT, dpi=330)
print("wrote %s  (content height %.0f units)" % (OUT, bottom))
