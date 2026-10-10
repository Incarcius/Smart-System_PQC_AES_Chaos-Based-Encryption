"""Render the paper's result figures from the actual run artefacts.

Nothing here is drawn by hand: every series is read from history.json,
eval.json or recomputed by running the trained detector. Figures are sized for
a 3.4 inch IEEE column and set in Times to match the body text.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path("C:/Users/soham/Downloads/Smart-System_PQC_AES_Chaos-Based-Encryption/"
            "Smart-System_PQC_AES_Chaos-Based-Encryption")
OUT = Path(__file__).resolve().parent

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 7,
    "axes.linewidth": 0.6,
    "axes.labelsize": 7,
    "xtick.labelsize": 6.5,
    "ytick.labelsize": 6.5,
    "legend.fontsize": 6.5,
    "legend.frameon": False,
    "lines.linewidth": 0.9,
})
COL_IN = 3.4


def smooth(x, k):
    x = np.asarray(x, float)
    if len(x) < k:
        return x
    c = np.convolve(x, np.ones(k) / k, mode="valid")
    return np.concatenate([np.full(k - 1, c[0]), c])


# ── Fig. 2: training ────────────────────────────────────────────────────────
def fig_training():
    fig, ax = plt.subplots(2, 1, figsize=(COL_IN, 2.9), sharex=True)
    seeds = [("final_seed21", "seed 1"), ("final_seed22", "seed 2 (deployed)"),
             ("final_seed23", "seed 3")]
    styles = [(":", 0.8), ("-", 1.3), ("--", 0.8)]

    for (d, lbl), (ls, lw) in zip(seeds, styles):
        p = ROOT / "src/ML/dqn/runs" / d / "history.json"
        if not p.exists():
            continue
        h = json.loads(p.read_text())
        ep = np.arange(1, len(h["return"]) + 1)
        ax[0].plot(ep, smooth(h["return"], 100), ls, lw=lw, color="black",
                   label=lbl, alpha=0.9 if lw > 1 else 0.6)
        ax[1].plot(ep, smooth(h["compromised"], 100), ls, lw=lw, color="black",
                   alpha=0.9 if lw > 1 else 0.6)

    ax[0].set_ylabel("episode return")
    ax[0].legend(loc="lower right")
    ax[1].set_ylabel("compromised steps")
    ax[1].set_xlabel("training episode")
    for a in ax:
        a.spines[["top", "right"]].set_visible(False)
        a.grid(axis="y", lw=0.3, alpha=0.3)
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "fig2_training.png", dpi=320)
    plt.close(fig)
    print("fig2_training.png")


# ── Fig. 3: robustness sweep ───────────────────────────────────────────────
def fig_robustness():
    e = json.loads((ROOT / "src/ML/dqn/runs/final_seed22/eval.json").read_text())
    rows = e["sweep"]
    dqn = np.array([r["dqn"] for r in rows])
    thr = np.array([r["threshold"] for r in rows])
    delay = np.array([r["delay"] for r in rows])

    fig, ax = plt.subplots(figsize=(COL_IN, 2.1))
    marks = {1: "o", 3: "s", 6: "^"}
    for d in (1, 3, 6):
        m = delay == d
        ax.scatter(thr[m], dqn[m], s=14, marker=marks[d], facecolors="none",
                   edgecolors="black", linewidths=0.7,
                   label=f"detection delay {d}")
    lo = float(min(dqn.min(), thr.min())) * 1.05
    hi = float(max(dqn.max(), thr.max())) * 0.95
    ax.plot([lo, hi], [lo, hi], "-", color="0.6", lw=0.7)
    ax.text(lo * 0.62, lo * 0.80, "parity", fontsize=6, color="0.4",
            rotation=38, ha="center")
    ax.set_xlabel("threshold policy return")
    ax.set_ylabel("learned policy return")
    ax.legend(loc="lower left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(lw=0.3, alpha=0.3)
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "fig3_robustness.png", dpi=320)
    plt.close(fig)
    print("fig3_robustness.png  (all %d points above parity: %s)"
          % (len(rows), bool((dqn > thr).all())))


# ── Fig. 4: detector score distributions ───────────────────────────────────
def fig_scores():
    import sys
    sys.path.insert(0, str(ROOT / "server" / "LSTM"))
    from data import (LABEL_ATTACK, LABEL_NATURAL, LABEL_NORMAL, WindowSpec,
                      load_multiclass, split_normal)
    from lstm_detector import LSTMDetector

    ds = load_multiclass(ROOT / "data/msu_ornl/csv", WindowSpec(60, 10, 120.0))
    _, _, ev = split_normal(ds, seed=0)
    det = LSTMDetector.from_dir(ROOT / "server/LSTM/runs")
    sc = det.score_array(ev.X)

    fig, ax = plt.subplots(figsize=(COL_IN, 1.95))
    bins = np.linspace(0, 1, 26)
    ax.hist(sc[ev.y == LABEL_NORMAL], bins=bins, density=True, histtype="step",
            color="black", lw=1.0, label="benign (no event)")
    ax.hist(sc[ev.y == LABEL_NATURAL], bins=bins, density=True, histtype="step",
            color="black", lw=0.8, ls="--", label="natural disturbance")
    ax.hist(sc[ev.y == LABEL_ATTACK], bins=bins, density=True, histtype="step",
            color="black", lw=0.8, ls=":", label="attack")
    x = np.linspace(0.001, 0.999, 200)
    from math import gamma
    a, b = 1.5, 6.0
    beta_pdf = (x ** (a - 1) * (1 - x) ** (b - 1)
                * gamma(a + b) / (gamma(a) * gamma(b)))
    ax.plot(x, beta_pdf, color="0.55", lw=0.8,
            label="surrogate assumed benign")
    ax.set_xlabel("calibrated detector score")
    ax.set_ylabel("density")
    ax.set_ylim(0, 6)
    ax.legend(loc="upper center", ncol=1)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "fig4_scores.png", dpi=320)
    plt.close(fig)
    print("fig4_scores.png  (benign mean %.3f)" % sc[ev.y == LABEL_NORMAL].mean())


if __name__ == "__main__":
    fig_training()
    fig_robustness()
    fig_scores()
