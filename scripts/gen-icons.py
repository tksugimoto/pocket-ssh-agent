#!/usr/bin/env python3
"""Generate the PWA icons in web/icons/ (requires Pillow)."""

from pathlib import Path

from PIL import Image, ImageDraw

BG = (20, 23, 28)
FG = (76, 141, 255)
OUT = Path(__file__).resolve().parent.parent / "web" / "icons"


def draw_key(size: int, padding: float, rounded: bool) -> Image.Image:
    ss = 4  # supersampling for smooth edges
    s = size * ss
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if rounded:
        d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=BG)
    else:
        d.rectangle([0, 0, s - 1, s - 1], fill=BG)

    inner = s * (1 - 2 * padding)
    ox = oy = s * padding

    def p(x: float, y: float) -> tuple[float, float]:
        return (ox + x * inner, oy + y * inner)

    # Bow: ring on the left.
    cx, cy, r, ring = 0.30, 0.50, 0.20, 0.075
    d.ellipse([*p(cx - r, cy - r), *p(cx + r, cy + r)], fill=FG)
    d.ellipse([*p(cx - r + ring, cy - r + ring), *p(cx + r - ring, cy + r - ring)], fill=BG)
    # Shaft.
    d.rectangle([*p(cx + r - 0.02, cy - 0.045), *p(0.88, cy + 0.045)], fill=FG)
    # Teeth.
    d.rectangle([*p(0.66, cy + 0.03), *p(0.73, cy + 0.17)], fill=FG)
    d.rectangle([*p(0.78, cy + 0.03), *p(0.86, cy + 0.13)], fill=FG)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    draw_key(192, 0.14, True).save(OUT / "icon-192.png")
    draw_key(512, 0.14, True).save(OUT / "icon-512.png")
    # Maskable icons must keep content inside the central 80% safe zone.
    draw_key(512, 0.22, False).save(OUT / "icon-maskable-512.png")
    # iOS adds its own rounded mask and ignores transparency.
    draw_key(180, 0.16, False).convert("RGB").save(OUT / "apple-touch-icon.png")


if __name__ == "__main__":
    main()
