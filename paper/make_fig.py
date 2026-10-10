"""Render the three-tier architecture figure as a PNG for the Word document.

Designed at the FINAL display size in pixels (a 3.4-inch column at 96 dpi is
326 px) and supersampled 4x, so the type inside the figure lands at a real
point size next to the body text. Designing at an arbitrary large size and
scaling down was the earlier mistake: the labels came out illegible.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
OUT = HERE / "fig1_architecture.png"

S = 4                              # supersample
DW, DH = 326, 104                  # display size in px (3.4in column @96dpi)
W, H = DW * S, DH * S
BG, FG = "white", "black"


def font(name, display_pt):
    for cand in (name, "C:/Windows/Fonts/" + name):
        try:
            return ImageFont.truetype(cand, display_pt * S)
        except Exception:
            continue
    return ImageFont.load_default()


f_title = font("times.ttf", 8)
f_sub = font("timesi.ttf", 6)
f_lbl = font("times.ttf", 6)
f_foot = font("timesi.ttf", 6)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)


def centre(x, y, text, fnt):
    l, t, r, b = d.textbbox((0, 0), text, font=fnt)
    d.text((x - (r - l) / 2, y - (b - t) / 2), text, font=fnt, fill=FG)


BW, BH = 92 * S, 46 * S
BY = 14 * S
xs = [2 * S, (W - BW) // 2, W - BW - 2 * S]
labels = [
    ("Sensor node", "5 channels", "AES-GCM, X25519"),
    ("Field gateway", "1 s windows", "RL policy, detector"),
    ("Control server", "LSTM detector", "lease issuer"),
]

for x, (a, b, c) in zip(xs, labels):
    d.rectangle([x, BY, x + BW, BY + BH], outline=FG, width=1 * S)
    centre(x + BW / 2, BY + 11 * S, a, f_title)
    centre(x + BW / 2, BY + 25 * S, b, f_sub)
    centre(x + BW / 2, BY + 36 * S, c, f_sub)


def arrow(x1, x2, y, text):
    d.line([x1, y, x2, y], fill=FG, width=1 * S)
    head = 4 * S if x2 > x1 else -4 * S
    d.polygon([(x2, y), (x2 - head, y - 2.2 * S), (x2 - head, y + 2.2 * S)],
              fill=FG)
    centre((x1 + x2) / 2, y - 6 * S, text, f_lbl)


g1a, g1b = xs[0] + BW + 2 * S, xs[1] - 2 * S
g2a, g2b = xs[1] + BW + 2 * S, xs[2] - 2 * S
arrow(g1a, g1b, BY + 16 * S, "UART")
arrow(g2a, g2b, BY + 16 * S, "TCP")
arrow(g2b, g2a, BY + 36 * S, "lease")
arrow(g1b, g1a, BY + 36 * S, "epoch")

centre(W / 2, H - 7 * S,
       "ML-KEM-512 / ML-DSA-44 root exchange establishes the key pool", f_foot)

img = img.resize((DW, DH), Image.LANCZOS)
img.save(OUT, "PNG")
print(f"wrote {OUT} ({img.width}x{img.height})")
