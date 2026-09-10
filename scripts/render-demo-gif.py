#!/usr/bin/env python3
"""Render docs/assets/demo.gif: an animated terminal card of `make demo`.

This is the headless companion to scripts/record-demo.sh. The asciinema path
records a real PTY and therefore needs an interactive TTY, so it cannot run in
the no-TTY CI/agent environment. This generator is fully deterministic and
needs the installed package, Pillow and a monospace font. Font differences
across hosts can change the rendered bytes.

The frames replay the *verbatim* output captured from a real `make demo` run
(the same text the static docs/assets/demo.svg renders), revealed line by line
with a blinking cursor so the README can show the loop in action.

One-time setup:
    python3 -m pip install Pillow

Usage:
    make demo-gif                                  # -> docs/assets/demo.gif
    python3 scripts/render-demo-gif.py             # equivalent
"""

from __future__ import annotations

import html
import pathlib
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

# --- palette (identical to docs/assets/demo.svg) ----------------------------
BG_TOP = (17, 22, 29)  # #11161d
BG_BOT = (12, 16, 21)  # #0c1015
BAR = (22, 28, 36)  # #161c24
BORDER = (43, 52, 64)  # #2b3440
TITLE = (125, 136, 147)  # #7d8893

DEF = (196, 205, 214)  # #c4cdd6 default text
GREEN = (86, 211, 100)  # #56d364
WHITE = (238, 243, 247)  # #eef3f7
CYAN = (86, 212, 221)  # #56d4dd
DIM = (139, 149, 161)  # #8b95a1
DIMMER = (85, 96, 108)  # #55606c
RED = (255, 123, 114)  # #ff7b72
YELLOW = (227, 179, 65)  # #e3b341

# Traffic lights
LIGHTS = [((255, 95, 86)), ((255, 189, 46)), ((39, 201, 63))]

# Capture the current CLI, not a hand-maintained transcript. Fail if it fails.
B = True
N = False
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _capture_lines():
    with tempfile.TemporaryDirectory(prefix="substation-demo-") as td:
        result = subprocess.run(
            [sys.executable, "-m", "substation.cli", "demo", "--artifacts", td],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    lines = [[("$ make demo", WHITE, B)], []]
    for line in result.stdout.splitlines():
        color = (
            RED
            if "FIRED" in line
            else GREEN
            if "quiet" in line
            else DIM
            if "not-run" in line
            else DEF
        )
        lines.append([(line, color, N)] if line else [])
    return lines


LINES = _capture_lines()

# --- geometry ---------------------------------------------------------------
PAD_X = 26
BAR_H = 42
LINE_H = 22
TOP = BAR_H + 16
FONT_SIZE = 15
SCALE = 2  # supersample, then downscale for crisp text

# Monospace font candidates per platform. DejaVu Sans Mono is the committed
# asset's face; the macOS/extra fallbacks keep `make demo-gif` runnable anywhere
# (the output is only byte-reproducible where DejaVu is available).
_FONT_CANDIDATES = {
    "regular": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",  # Debian/Ubuntu
        "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",  # Fedora
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",  # Arch
        "/opt/homebrew/share/fonts/DejaVuSansMono.ttf",  # macOS (homebrew font-dejavu)
        "/Library/Fonts/DejaVuSansMono.ttf",  # macOS (manual install)
        "/System/Library/Fonts/Menlo.ttc",  # macOS system fallback
    ],
    "bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
        "/opt/homebrew/share/fonts/DejaVuSansMono-Bold.ttf",
        "/Library/Fonts/DejaVuSansMono-Bold.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ],
}


def _find_font(kind):
    for candidate in _FONT_CANDIDATES[kind]:
        if pathlib.Path(candidate).exists():
            return candidate
    raise SystemExit(
        f"render-demo-gif: no {kind} monospace font found. Install DejaVu Sans Mono "
        "(Debian/Ubuntu: `apt install fonts-dejavu-core`; macOS: "
        "`brew install --cask font-dejavu`) or add your font's path to "
        "_FONT_CANDIDATES in scripts/render-demo-gif.py."
    )


FONT_REG = _find_font("regular")
FONT_BLD = _find_font("bold")


def _font(bold):
    return ImageFont.truetype(FONT_BLD if bold else FONT_REG, FONT_SIZE * SCALE)


def _char_w():
    return _font(False).getbbox("M")[2]


BG = tuple((a + b) // 2 for a, b in zip(BG_TOP, BG_BOT))  # flat: small GIF palette


def _measure():
    cw = _char_w()
    max_cols = max((sum(len(t) for t, _, _ in ln) for ln in LINES), default=0)
    width = PAD_X * SCALE * 2 + cw * max_cols
    height = (TOP + LINE_H * len(LINES) + 14) * SCALE
    # round up to even for clean downscale
    return (int(width) + width % 2, int(height) + height % 2, cw)


def _draw_chrome(img, w, h):
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, h], fill=BG)
    d.rectangle([0, 0, w - 1, h - 1], outline=BORDER, width=SCALE)
    d.rectangle([0, 0, w, BAR_H * SCALE], fill=BAR)
    d.line([0, BAR_H * SCALE, w, BAR_H * SCALE], fill=BORDER, width=SCALE)
    for i, col in enumerate(LIGHTS):
        cx = (24 + i * 20) * SCALE
        r = 6 * SCALE
        d.ellipse([cx - r, 21 * SCALE - r, cx + r, 21 * SCALE + r], fill=col)
    tf = ImageFont.truetype(FONT_REG, 13 * SCALE)
    label = "make demo · substation"
    tw = d.textlength(label, font=tf)
    d.text(((w - tw) / 2, 13 * SCALE), label, font=tf, fill=TITLE)
    return d


def _render(visible_lines, cursor_line, cursor_col, show_cursor, w, h, cw, typed=None):
    """Render one frame.

    typed: optional (text, color, bold) segment list for an in-progress first
    line (the command being typed) when no full line is visible yet.
    """
    img = Image.new("RGB", (w, h))
    d = _draw_chrome(img, w, h)

    def cursor_at(col, y):
        cx = PAD_X * SCALE + cw * col
        d.rectangle([cx, y + 2 * SCALE, cx + 9 * SCALE, y + 18 * SCALE], fill=GREEN)

    if typed is not None:
        y = TOP * SCALE
        x = PAD_X * SCALE
        for text, color, bold in typed:
            d.text((x, y), text, font=_font(bold), fill=color)
            x += cw * len(text)
        if show_cursor:
            cursor_at(sum(len(t) for t, _, _ in typed), y)
        return img.resize((w // SCALE, h // SCALE), Image.LANCZOS)

    for i, line in enumerate(LINES[:visible_lines]):
        y = (TOP + i * LINE_H) * SCALE
        x = PAD_X * SCALE
        for text, color, bold in line:
            d.text((x, y), text, font=_font(bold), fill=color)
            x += cw * len(text)
        if show_cursor and i == cursor_line:
            cursor_at(cursor_col, y)
    return img.resize((w // SCALE, h // SCALE), Image.LANCZOS)


def main():
    w, h, cw = _measure()
    frames, durations = [], []

    def add(img, ms):
        frames.append(img)
        durations.append(ms)

    # 1. prompt, type the command, then a couple of cursor blinks
    add(_render(0, 0, 0, True, w, h, cw, typed=[("$ ", GREEN, B)]), 450)
    add(_render(0, 0, 0, True, w, h, cw, typed=[("$", GREEN, B), (" make", WHITE, B)]), 220)
    add(_render(1, 0, 10, True, w, h, cw), 500)
    add(_render(1, 0, 10, False, w, h, cw), 350)

    # 2. reveal output line by line; cursor parks at the end of the newest line
    for n in range(2, len(LINES) + 1):
        cline = n - 1
        ccol = sum(len(t) for t, _, _ in LINES[cline])
        # blank lines flash by quickly; scenario verdicts get a beat to read
        blank = len(LINES[cline]) == 0
        ms = 120 if blank else (520 if cline in (4, 5, 6) else 200)
        add(_render(n, cline, ccol, True, w, h, cw), ms)

    # 3. hold the finished frame with a blinking cursor on the result line
    last = len(LINES)
    rcol = sum(len(t) for t, _, _ in LINES[-1])
    for _ in range(3):
        add(_render(last, last - 1, rcol, True, w, h, cw), 600)
        add(_render(last, last - 1, rcol, False, w, h, cw), 600)

    # Quantize every frame against one shared palette built from the richest
    # (final) frame, so colors stay stable and the GIF palette stays small.
    pal = frames[-1].convert("RGB").quantize(colors=64, method=Image.MAXCOVERAGE)
    pframes = [f.convert("RGB").quantize(palette=pal, dither=Image.NONE) for f in frames]

    out = pathlib.Path(__file__).resolve().parent.parent / "docs" / "assets" / "demo.gif"
    pframes[0].save(
        out,
        save_all=True,
        append_images=pframes[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    # Keep the static SVG on the exact same captured transcript as the GIF.
    width, height = w // SCALE, h // SCALE
    rows = []
    for i, line in enumerate(LINES):
        text = html.escape("".join(segment[0] for segment in line))
        rows.append(
            f'<text x="{PAD_X}" y="{TOP + i * LINE_H + FONT_SIZE}" xml:space="preserve">{text}</text>'
        )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">'
        "<title>Current Substation demo output</title>"
        f'<rect width="{width}" height="{height}" fill="#11161d"/>'
        f'<g font-family="Menlo,DejaVu Sans Mono,monospace" font-size="{FONT_SIZE}" fill="#c4cdd6">'
        + "".join(rows)
        + "</g></svg>\n"
    )
    out.with_suffix(".svg").write_text(svg, encoding="utf-8")
    kb = out.stat().st_size / 1024
    print(f"wrote {out} ({w // SCALE}x{h // SCALE}, {len(frames)} frames, {kb:.0f} KB)")


if __name__ == "__main__":
    main()
