#!/usr/bin/env python3
"""Renders the app icon source (1024×1024) and the monochrome tray template icon.

Run `pnpm --filter @tokenmaxxing/desktop icons` to regenerate the full Tauri icon set.
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "src-tauri" / "icons"
OUT.mkdir(parents=True, exist_ok=True)


def stacked_coins(draw: ImageDraw.ImageDraw, cx: float, cy: float, w: float, h: float, gap: float, fill, outline=None, width=0):
    """Three stacked ellipses — the Tokenmaxxing 'token stack' mark."""
    ry = h / 2
    for i in range(3):
        y = cy + (1 - i) * gap
        draw.ellipse([cx - w / 2, y - ry, cx + w / 2, y + ry], fill=fill, outline=outline, width=width)


def app_icon() -> None:
    size = 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    radius = 224
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=(24, 24, 24, 255))
    draw.rounded_rectangle([8, 8, size - 9, size - 9], radius=radius - 8, outline=(60, 60, 60, 255), width=6)
    # coin stack with a "cut" to give it depth
    stacked_coins(draw, size / 2, size / 2 + 40, 520, 190, 120, fill=(236, 236, 236, 255), outline=(24, 24, 24, 255), width=22)
    img.save(OUT / "source.png")


def tray_icon() -> None:
    # Template icon: black shapes on transparent; macOS recolours it for light/dark menu bars.
    for scale, name in ((2, "tray.png"), (1, "tray-1x.png")):
        size = 22 * scale
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        stacked_coins(draw, size / 2, size / 2 + 1.5 * scale, 15 * scale, 5.5 * scale, 4 * scale, fill=(0, 0, 0, 255), outline=(0, 0, 0, 0), width=0)
        # separate the coins with transparent gaps so the stack reads at 22px
        for i in range(2):
            y = size / 2 + 1.5 * scale + (0.5 - i) * 4 * scale - 0.5 * scale
            draw.rectangle([size / 2 - 7.5 * scale, y - 0.6 * scale, size / 2 + 7.5 * scale, y + 0.6 * scale], fill=(0, 0, 0, 0))
        img.save(OUT / name)


if __name__ == "__main__":
    app_icon()
    tray_icon()
    print(f"wrote {OUT / 'source.png'} and tray icons")
