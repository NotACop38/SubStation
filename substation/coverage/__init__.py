"""Coverage-map and ATT&CK Navigator layer builder.

Two surfaces live here:

* :func:`render_coverage_map` — the demo's live, in-terminal report of which
  detections the loaded scenarios exercise and whether each fired this run.
* the metadata-driven **coverage generator** (:mod:`substation.coverage.builder`,
  run via ``python -m substation.coverage``) — emits the markdown/JSON coverage
  table and the ATT&CK Navigator layer from ``detections/registry.yaml``
  (PRD.md §6.7). Those artifacts are generated, never hand-edited.
"""

from __future__ import annotations

from substation.detect import Hit
from substation.scenarios import Scenario

from .builder import (
    render_all,
    render_json,
    render_markdown,
    render_navigator_layer,
)

__all__ = [
    "render_coverage_map",
    "render_all",
    "render_markdown",
    "render_json",
    "render_navigator_layer",
]


def render_coverage_map(scenarios: list[Scenario], hits: list[Hit]) -> str:
    """Render a human-readable placeholder coverage map as text.

    Lists each detection ID the loaded scenarios claim to exercise and whether a
    hit was observed for it. Phase 0 always shows "no hits" — the point is to
    prove the report stage consumes the detect stage's output.
    """
    fired = {h.detection_id for h in hits}
    claimed: set[str] = set()
    for s in scenarios:
        claimed.update(s.exercises.fires)
        claimed.update(s.exercises.quiet)

    lines = ["ATT&CK-for-ICS coverage map (Phase 0 placeholder)", "=" * 50]
    if not claimed:
        lines.append("  (no detections exercised by the loaded scenarios yet)")
    for det in sorted(claimed):
        status = "FIRED" if det in fired else "no hits"
        lines.append(f"  {det:<8} {status}")
    lines.append("=" * 50)
    lines.append(f"scenarios loaded: {len(scenarios)} · detections tracked: {len(claimed)}")
    return "\n".join(lines)
