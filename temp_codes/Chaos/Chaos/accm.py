import matplotlib.pyplot as plt
import numpy as np

# ── Parameters ────────────────────────────────────────────────────────────────
session_key = [0xA1,0xB2,0xC3,0xD4, 0xE5,0xF6,0x07,0x18,
               0x29,0x3A,0x4B,0x5C, 0x6D,0x7E,0x8F,0x90,
               0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
               0x99,0xAA,0xBB,0xCC, 0xDD,0xEE,0xFF,0x00]

r1 = 3.57 + (session_key[8] / 255.0) * 0.43
r2 = 3.57 + (session_key[9] / 255.0) * 0.43

x0 = 0.28172
y0 = 0.61340

n_eps    = 2000    # number of epsilon values across x-axis
warmup   = 1000    # iterations to discard (transient)
collect  = 300     # iterations to plot per epsilon

# ── Sweep epsilon ─────────────────────────────────────────────────────────────
eps_values = np.linspace(0.001, 0.499, n_eps)

eps_plot = []
x_plot   = []
y_plot   = []

for eps in eps_values:
    x, y = x0, y0

    # warmup
    for _ in range(warmup):
        lx = r1 * x * (1.0 - x)
        ly = r2 * y * (1.0 - y)
        xn = (1.0 - eps) * lx + eps * ly
        yn = (1.0 - eps) * ly + eps * lx
        x  = xn if 1e-10 < xn < 1 - 1e-10 else 0.3141
        y  = yn if 1e-10 < yn < 1 - 1e-10 else 0.2718

    # collect
    for _ in range(collect):
        lx = r1 * x * (1.0 - x)
        ly = r2 * y * (1.0 - y)
        xn = (1.0 - eps) * lx + eps * ly
        yn = (1.0 - eps) * ly + eps * lx
        x  = xn if 1e-10 < xn < 1 - 1e-10 else 0.3141
        y  = yn if 1e-10 < yn < 1 - 1e-10 else 0.2718

        eps_plot.append(eps)
        x_plot.append(x)
        y_plot.append(y)

eps_arr = np.array(eps_plot)
x_arr   = np.array(x_plot)
y_arr   = np.array(y_plot)

# ── Plot ──────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(2, 1, figsize=(14, 10))
fig.patch.set_facecolor('white')
fig.suptitle('ACCM Bifurcation Diagram', fontsize=15, fontweight='bold', y=0.98)

# ── Top plot: x state ─────────────────────────────────────────────────────────
axes[0].scatter(eps_arr, x_arr, s=0.05, color='#1a3a6e', alpha=0.25)

axes[0].axvline(x=0.1, color='teal',    linewidth=2.0,
                linestyle='--', label='Normal mode  (ε = 0.1)')
axes[0].axvline(x=0.4, color='crimson', linewidth=2.0,
                linestyle='--', label='Anomaly mode (ε = 0.4)')

axes[0].set_ylabel('x state (long-term)', fontsize=11)
axes[0].set_title('x Variable Bifurcation', fontsize=12, fontweight='bold')
axes[0].set_facecolor('#f4f4f4')
axes[0].legend(fontsize=10, loc='upper right')
axes[0].set_xlim(0, 0.5)
axes[0].set_ylim(0, 1)

# ── Bottom plot: y state ──────────────────────────────────────────────────────
axes[1].scatter(eps_arr, y_arr, s=0.05, color='#0e6655', alpha=0.25)

axes[1].axvline(x=0.1, color='teal',    linewidth=2.0,
                linestyle='--', label='Normal mode  (ε = 0.1)')
axes[1].axvline(x=0.4, color='crimson', linewidth=2.0,
                linestyle='--', label='Anomaly mode (ε = 0.4)')

axes[1].set_xlabel('Coupling Strength (ε)', fontsize=11)
axes[1].set_ylabel('y state (long-term)', fontsize=11)
axes[1].set_title('y Variable Bifurcation', fontsize=12, fontweight='bold')
axes[1].set_facecolor('#f4f4f4')
axes[1].legend(fontsize=10, loc='upper right')
axes[1].set_xlim(0, 0.5)
axes[1].set_ylim(0, 1)

plt.tight_layout()
plt.savefig('accm_bifurcation.png', dpi=200, bbox_inches='tight')
plt.show()

print("Saved: accm_bifurcation.png")