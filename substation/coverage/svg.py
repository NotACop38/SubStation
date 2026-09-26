"""Render the ATT&CK-for-ICS coverage matrix as a self-contained SVG card.

The card shows every ICS tactic as a column, the registry's detections as chips
under the tactic they map to (colored by protocol), and headline counts. It is
generated from ``detections/registry.yaml`` like the other coverage artifacts, so
the README image cannot drift from the shipped detections (``make ci`` checks it).

Output is deterministic: coordinates are formatted with fixed precision and
iteration follows the registry and tactic order.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from substation.detect.registry import Detection

__all__ = ["render_svg"]

# Tactic columns in matrix order, with hand-tuned line breaks for the header box.
# IDs and names mirror ``registry.ICS_TACTICS``; a test keeps the two in sync.
_TACTIC_LABELS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("TA0108", ("Initial", "Access")),
    ("TA0104", ("Execution",)),
    ("TA0110", ("Persistence",)),
    ("TA0111", ("Privilege", "Escalation")),
    ("TA0103", ("Evasion",)),
    ("TA0102", ("Discovery",)),
    ("TA0109", ("Lateral", "Movement")),
    ("TA0100", ("Collection",)),
    ("TA0101", ("Command", "and Control")),
    ("TA0107", ("Inhibit", "Response", "Function")),
    ("TA0106", ("Impair", "Process", "Control")),
    ("TA0105", ("Impact",)),
)

# Protocol chip palette: (legend label, chip fill, chip stroke, text/dot color).
_PROTOCOL_STYLE: dict[str, tuple[str, str, str, str]] = {
    "modbus": ("Modbus", "#0c191e", "#2c6470", "#7fe0ea"),
    "dnp3": ("DNP3", "#1c170b", "#6b5a23", "#f0cd6b"),
    "s7comm": ("Siemens S7", "#16122a", "#4b3f80", "#c4b5ff"),
    "cross": ("Cross-protocol", "#1e0f0e", "#6b3330", "#ff9a90"),
}

_SANS = "'Segoe UI',system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif"
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

_WIDTH = 1200
_MARGIN = 22
_COLUMN_WIDTH = 89
_COLUMN_GAP = 8
_HEADER_Y = 92
_HEADER_HEIGHT = 66
_CHIP_TOP = 172
_CHIP_STEP = 29
_CHIP_WIDTH = 73
_CHIP_HEIGHT = 22


def _num(value: float) -> str:
    """Format a coordinate compactly and deterministically."""
    return f"{value:.1f}".removesuffix(".0")


def _text(x: float, y: float, content: str, **attrs: str) -> str:
    rendered = "".join(f' {key.replace("_", "-")}="{value}"' for key, value in attrs.items())
    return f'<text x="{_num(x)}" y="{_num(y)}"{rendered}>{escape(content)}</text>'


def _stat(x: int, width: int, value: str, label: str, color: str) -> list[str]:
    return [
        f'  <g transform="translate({x} 24)">',
        f'    <rect width="{width}" height="40" rx="10" fill="#0c141b" stroke="#22303f"/>',
        "    "
        + _text(
            14,
            27,
            value,
            font_family=_SANS,
            font_size="20",
            font_weight="800",
            fill=color,
        ),
        "    "
        + _text(
            20 + 11.5 * len(value) + 8,
            26,
            label,
            font_family=_SANS,
            font_size="12.5",
            fill="#9da7b1",
        ),
        "  </g>",
    ]


def _tactic_header(x: float, tactic_id: str, lines: tuple[str, ...], covered: bool) -> list[str]:
    fill, stroke, accent = (
        ("#10241a", "#27553b", "#3fb950") if covered else ("#0d121a", "#1f2630", "#2b333d")
    )
    label_color, id_color = ("#e7f0ea", "#7bd69b") if covered else ("#6b7480", "#4a525d")
    center = x + _COLUMN_WIDTH / 2
    # Vertically center the label block above the tactic ID line.
    first_baseline = 124 - 6.5 * (len(lines) - 1)
    out = [
        "  <g>",
        f'    <rect x="{_num(x)}" y="{_HEADER_Y}" width="{_COLUMN_WIDTH}" '
        f'height="{_HEADER_HEIGHT}" rx="8" fill="{fill}" stroke="{stroke}"/>',
        f'    <rect x="{_num(x)}" y="{_HEADER_Y}" width="3.5" height="{_HEADER_HEIGHT}" '
        f'rx="1.5" fill="{accent}"/>',
    ]
    for index, line in enumerate(lines):
        out.append(
            "    "
            + _text(
                center,
                first_baseline + 13 * index,
                line,
                text_anchor="middle",
                font_family=_SANS,
                font_size="11.5",
                font_weight="700",
                fill=label_color,
            )
        )
    out.append(
        "    "
        + _text(
            center,
            150,
            tactic_id,
            text_anchor="middle",
            font_family=_MONO,
            font_size="9",
            fill=id_color,
        )
    )
    out.append("  </g>")
    return out


def _chip(x: float, y: float, label: str, protocol: str) -> list[str]:
    _, fill, stroke, color = _PROTOCOL_STYLE[protocol]
    return [
        f'  <g transform="translate({_num(x)} {_num(y)})">',
        f'    <rect width="{_CHIP_WIDTH}" height="{_CHIP_HEIGHT}" rx="6" '
        f'fill="{fill}" stroke="{stroke}"/>',
        f'    <circle cx="11" cy="11" r="3" fill="{color}"/>',
        "    "
        + _text(
            22,
            15,
            label,
            font_family=_MONO,
            font_size="12.5",
            font_weight="700",
            fill=color,
        ),
        "  </g>",
    ]


def render_svg(detections: list[Detection]) -> str:
    """Render the coverage matrix card for ``detections`` as SVG text."""
    by_tactic: dict[str, list[Detection]] = {}
    for det in detections:
        by_tactic.setdefault(det.attack.tactic_id, []).append(det)
    unknown = sorted(set(by_tactic) - {tactic_id for tactic_id, _ in _TACTIC_LABELS})
    if unknown:
        raise ValueError(f"coverage SVG has no column for tactic(s) {unknown}")
    unknown_protocols = sorted({det.protocol for det in detections} - _PROTOCOL_STYLE.keys())
    if unknown_protocols:
        raise ValueError(f"coverage SVG has no style for protocol(s) {unknown_protocols}")

    techniques = {t.id for det in detections for t in det.attack.techniques}
    covered = sum(1 for tactic_id, _ in _TACTIC_LABELS if by_tactic.get(tactic_id))
    total = len(_TACTIC_LABELS)
    tallest = max((len(dets) for dets in by_tactic.values()), default=1)
    chips_bottom = _CHIP_TOP + tallest * _CHIP_STEP - (_CHIP_STEP - _CHIP_HEIGHT)
    legend_y = chips_bottom + 34
    height = legend_y + 26
    empty_label_y = _CHIP_TOP + (chips_bottom - _CHIP_TOP) / 2 + 4

    summary = (
        f"ATT&CK-for-ICS coverage matrix: {covered} of {total} tactics mapped by "
        f"{len(detections)} detections across {len(techniques)} techniques."
    )
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_WIDTH}" height="{height}" '
        f'viewBox="0 0 {_WIDTH} {height}" role="img" aria-label="{escape(summary)}">',
        "  <title>ATT&amp;CK-for-ICS coverage matrix</title>",
        "  <defs>",
        '    <linearGradient id="card" x1="0" y1="0" x2="0" y2="1">',
        '      <stop offset="0" stop-color="#0e141c"/><stop offset="1" stop-color="#0a0e14"/>',
        "    </linearGradient>",
        '    <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">',
        '      <path d="M30 0H0V30" fill="none" stroke="#141c27" stroke-width="1"/>',
        "    </pattern>",
        "  </defs>",
        f'  <rect x="0.5" y="0.5" width="{_WIDTH - 1}" height="{height - 1}" rx="16" '
        'fill="url(#card)" stroke="#2b3440"/>',
        f'  <rect x="1" y="1" width="{_WIDTH - 2}" height="{height - 2}" rx="16" '
        'fill="url(#grid)" opacity="0.5"/>',
        "  "
        + _text(
            _MARGIN,
            40,
            "ATT&CK-for-ICS coverage",
            font_family=_SANS,
            font_size="22",
            font_weight="800",
            fill="#eef3f7",
        ),
        "  "
        + _text(
            _MARGIN,
            62,
            "Detections by the ATT&CK tactic they map to · generated from detections/registry.yaml",
            font_family=_SANS,
            font_size="13",
            fill="#8b949e",
        ),
    ]
    out += _stat(709, 150, str(len(detections)), "detections", "#3fb950")
    out += _stat(877, 150, str(len(techniques)), "techniques", "#e3b341")
    out += _stat(1045, 133, f"{covered}/{total}", "tactics", "#58a6ff")

    for column, (tactic_id, lines) in enumerate(_TACTIC_LABELS):
        x = _MARGIN + column * (_COLUMN_WIDTH + _COLUMN_GAP)
        mapped = by_tactic.get(tactic_id, [])
        out += _tactic_header(x, tactic_id, lines, bool(mapped))
        if not mapped:
            out.append(
                "  "
                + _text(
                    x + _COLUMN_WIDTH / 2,
                    empty_label_y,
                    "no coverage",
                    text_anchor="middle",
                    font_family=_SANS,
                    font_size="11",
                    fill="#3b434e",
                )
            )
        for row, det in enumerate(mapped):
            out += _chip(x + 8, _CHIP_TOP + row * _CHIP_STEP, det.id, det.protocol)

    out.append(
        "  "
        + _text(
            _MARGIN,
            legend_y + 4,
            "Detection by protocol:",
            font_family=_SANS,
            font_size="12.5",
            fill="#8b949e",
        )
    )
    legend_x = 172
    for label, fill, stroke, color in _PROTOCOL_STYLE.values():
        out += [
            f'  <rect x="{legend_x}" y="{legend_y - 8}" width="16" height="16" rx="4" '
            f'fill="{fill}" stroke="{stroke}"/>',
            f'  <circle cx="{legend_x + 8}" cy="{legend_y}" r="3" fill="{color}"/>',
            "  "
            + _text(
                legend_x + 24,
                legend_y + 4,
                label,
                font_family=_SANS,
                font_size="12.5",
                fill="#c9d1d9",
            ),
        ]
        legend_x += 24 + round(7.2 * len(label)) + 26
    out += [
        f'  <rect x="928" y="{legend_y - 8}" width="16" height="16" rx="4" '
        'fill="#10241a" stroke="#27553b"/>',
        f'  <rect x="928" y="{legend_y - 8}" width="3.5" height="16" rx="1.5" fill="#3fb950"/>',
        "  "
        + _text(952, legend_y + 4, "mapped", font_family=_SANS, font_size="12.5", fill="#c9d1d9"),
        f'  <rect x="1035" y="{legend_y - 8}" width="16" height="16" rx="4" '
        'fill="#0d121a" stroke="#1f2630"/>',
        "  "
        + _text(
            1059,
            legend_y + 4,
            "no mapping",
            font_family=_SANS,
            font_size="12.5",
            fill="#c9d1d9",
        ),
        "</svg>",
    ]
    return "\n".join(out) + "\n"
