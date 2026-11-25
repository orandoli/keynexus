"""Generate the PWDSV brand icons (icon + favicon) as PNG files.

Run with the bundled Python:
    python tools/make_icons.py

Outputs:
    src/static/images/pwdsv-icon.png     256x256
    src/static/images/pwdsv-favicon.png   64x64
"""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "static" / "images"

BG_TOP = (11, 79, 138)
BG_BOTTOM = (4, 42, 82)
FG = (255, 255, 255)


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def gradient(size: int) -> Image.Image:
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(size - 1, 1)
        grad.putpixel(
            (0, y),
            tuple(round(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOTTOM)),
        )
    return grad.resize((size, size), Image.Resampling.BILINEAR)


def shield_points(size: int) -> list[tuple[float, float]]:
    """Shield outline: flat top, tapering to a point at the bottom."""
    s = size
    left, right = s * 0.26, s * 0.74
    top, shoulder, tip = s * 0.20, s * 0.46, s * 0.84
    return [
        (left, top),
        (s * 0.50, top - s * 0.03),
        (right, top),
        (right, shoulder),
        (s * 0.50, tip),
        (left, shoulder),
    ]


def render(size: int) -> Image.Image:
    scale = 4
    s = size * scale
    base = gradient(s).convert("RGBA")

    layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    # Shield body
    d.polygon(shield_points(s), fill=FG)

    # Keyhole: circle + stem, punched out of the shield
    cx, cy, r = s * 0.50, s * 0.44, s * 0.105
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=BG_TOP + (255,))
    d.polygon(
        [
            (cx - r * 0.42, cy + r * 0.55),
            (cx + r * 0.42, cy + r * 0.55),
            (cx + r * 0.85, cy + r * 2.55),
            (cx - r * 0.85, cy + r * 2.55),
        ],
        fill=BG_TOP + (255,),
    )

    # Small accent notch under the shield point
    d.rounded_rectangle(
        (s * 0.455, s * 0.885, s * 0.545, s * 0.915),
        radius=s * 0.012,
        fill=FG,
    )

    base.alpha_composite(layer)
    base.putalpha(rounded_mask(s, radius=int(s * 0.22)))
    return base.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, size in (("pwdsv-icon.png", 256), ("pwdsv-favicon.png", 64)):
        img = render(size)
        path = OUT / name
        img.save(path, "PNG", optimize=True)
        print(f"wrote {path.relative_to(ROOT)} ({img.width}x{img.height})")


if __name__ == "__main__":
    main()
