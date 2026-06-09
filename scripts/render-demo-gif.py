#!/usr/bin/env python3
"""Render docs/assets/demo.gif: an animated terminal card of `make demo`.

This is the headless companion to scripts/record-demo.sh. The asciinema path
records a real PTY and therefore needs an interactive TTY, so it cannot run in
the no-TTY CI/agent environment. This generator is fully deterministic and
needs only Pillow plus a monospace font, so it reproduces the GIF anywhere.

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

import os
import pathlib

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

# --- verbatim `make demo` output, as colored segments -----------------------
# Each logical line is a list of (text, color, bold) segments. The text is
# copied character-for-character from a real run so spacing stays faithful.
B = True
N = False
EQ = "=" * 60


def _row(rid, tech, tactic, status):
    """Build a coverage-map row exactly as the CLI prints it.

    Layout (monospace): 2 lead spaces, id (w2), 3 spaces, technique (left, w12),
    tactic (left, w25), then the status marker. Verified against the captured
    output and docs/assets/demo.svg.
    """
    seg = [
        ("  ", DEF, N),
        (rid, WHITE, B),
        ("   ", DEF, N),
        (tech.ljust(12), CYAN, N),
    ]
    if status == "fired":
        seg += [(tactic.ljust(27), DIM, N), ("● FIRED", RED, B)]
    elif status == "quiet":
        seg += [(tactic.ljust(27), DIM, N), ("○ quiet", GREEN, B)]
    else:  # untouched this run
        seg += [(tactic.ljust(28), DIM, N), ("·", DIMMER, N)]
    return seg


LINES = [
    [("$", GREEN, B), (" make demo", WHITE, B)],
    [],
    [
        ("substation", CYAN, B),
        (" demo · Tier-1 loop: generate -> detect -> report (pure Python)", DIM, N),
    ],
    [],
    [
        ("[benign   ]", CYAN, B),
        (" modbus-benign-baseline                 18 events -> ", DEF, N),
        ("quiet (no hits)", GREEN, N),
    ],
    [
        ("[anomalous]", YELLOW, B),
        (" modbus-anomalous-m1-unauthorized-write 10 events -> ", DEF, N),
        ("FIRED", RED, B),
        (" 2 hit(s) ", DEF, N),
        ("-> ", DIMMER, N),
        ("M1", YELLOW, B),
    ],
    [
        ("[anomalous]", YELLOW, B),
        (" modbus-anomalous-m2-illegal-function    4 events -> ", DEF, N),
        ("FIRED", RED, B),
        (" 2 hit(s) ", DEF, N),
        ("-> ", DIMMER, N),
        ("M2", YELLOW, B),
    ],
    [],
    [("ATT&CK-for-ICS coverage map", WHITE, B)],
    [(EQ, DIMMER, N)],
    [("  ID   Technique   Tactic                     This run", DIM, N)],
    [("  " + "-" * 58, DIMMER, N)],
    _row("M1", "T1692.001", "Impair Process Control", "fired"),
    _row("M2", "T0888", "Discovery", "fired"),
    _row("M3", "T0846", "Discovery", "quiet"),
    _row("D1", "T0816", "Inhibit Response Function", "none"),
    _row("D2", "T1691.002", "Inhibit Response Function", "none"),
    _row("D3", "T1692.001", "Impair Process Control", "none"),
    _row("D4", "T0888", "Discovery", "none"),
    _row("S1", "T0858", "Execution", "none"),
    _row("S2", "T0843", "Lateral Movement", "none"),
    _row("S3", "T0888", "Discovery", "none"),
    _row("X1", "T0846", "Discovery", "quiet"),
    [(EQ, DIMMER, N)],
    [
        ("11", WHITE, B),
        (" detections ", DIM, N),
        ("·", DIMMER, N),
        (" ", DIM, N),
        ("10", WHITE, B),
        (" ATT&CK techniques ", DIM, N),
        ("·", DIMMER, N),
        (" ", DIM, N),
        ("5", WHITE, B),
        (" tactics ", DIM, N),
        ("·", DIMMER, N),
        (" ", DIM, N),
        ("2", WHITE, B),
        (" fired this run", DIM, N),
    ],
    [],
    [
        ("Result:", DIM, B),
        (" ", DIM, N),
        ("quiet", GREEN, N),
        (" on the benign baseline; ", DIM, N),
        ("fired 2 detection(s)", RED, N),
        (" on the anomalies ", DIM, N),
        ("(M1, M2)", YELLOW, B),
        (".", DIM, N),
    ],
]

# --- geometry ---------------------------------------------------------------
PAD_X = 26
BAR_H = 42
LINE_H = 22
TOP = BAR_H + 16
FONT_SIZE = 15
SCALE = 2  # supersample, then downscale for crisp text

# Monospace font discovery: probe per-platform candidates instead of assuming a
# Linux path, so `make demo-gif` works on macOS/Windows too (regular, bold).
_FONT_CANDIDATES = [
    # Linux (Debian/Ubuntu/Fedora layouts)
    (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    ),
    (
        "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono-Bold.ttf",
    ),
    ("/usr/share/fonts/TTF/DejaVuSansMono.ttf", "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf"),
    # macOS (system + Homebrew font-dejavu cask)
    ("/Library/Fonts/DejaVuSansMono.ttf", "/Library/Fonts/DejaVuSansMono-Bold.ttf"),
    (
        os.path.expanduser("~/Library/Fonts/DejaVuSansMono.ttf"),
        os.path.expanduser("~/Library/Fonts/DejaVuSansMono-Bold.ttf"),
    ),
    ("/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Menlo.ttc"),
    # Windows
    (r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\consolab.ttf"),
]


def _find_fonts():
    for reg, bld in _FONT_CANDIDATES:
        if os.path.exists(reg) and os.path.exists(bld):
            return reg, bld
    raise SystemExit(
        "render-demo-gif: no monospace font found. Install DejaVu Sans Mono "
        "(Linux: fonts-dejavu / dejavu-sans-mono-fonts; macOS: "
        "`brew install --cask font-dejavu`) or add your font path to "
        "_FONT_CANDIDATES in scripts/render-demo-gif.py."
    )


FONT_REG, FONT_BLD = _find_fonts()


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
    kb = out.stat().st_size / 1024
    print(f"wrote {out} ({w // SCALE}x{h // SCALE}, {len(frames)} frames, {kb:.0f} KB)")


if __name__ == "__main__":
    main()
