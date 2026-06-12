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
from substation.detect.registry import Detection, load_registry
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


def render_coverage_map(
    scenarios: list[Scenario], hits: list[Hit], registry: list[Detection] | None = None
) -> str:
    """Render the demo's live ATT&CK-for-ICS coverage map as text.

    Driven by the authoritative ``detections/registry.yaml`` (the same metadata the
    generated coverage table is built from), so the demo shows the *real* shipped
    coverage — every detection, its verified ATT&CK technique + tactic, and whether
    it FIRED in this run (from ``hits``) or stayed quiet on the loaded scenarios.
    Pass ``registry`` to reuse an already-loaded registry (the demo does).
    """
    if registry is None:
        registry = load_registry()
    fired = {h.detection_id for h in hits}
    exercised: set[str] = set()
    for s in scenarios:
        exercised.update(s.exercises.fires)
        exercised.update(s.exercises.quiet)

    rows: list[str] = []
    techniques: set[str] = set()
    tactics: set[str] = set()
    for det in registry:
        techniques.update(t.id for t in det.attack.techniques)
        tactics.add(det.attack.tactic_id)
        if det.id in fired:
            run = "● FIRED"
        elif det.id in exercised:
            run = "○ quiet"
        else:
            run = " ·"
        tech = det.attack.primary.id
        rows.append(f"  {det.id:<4} {tech:<11} {det.attack.tactic:<26} {run}")

    header = f"  {'ID':<4} {'Technique':<11} {'Tactic':<26} This run"
    # 60 is the established rendered width (the committed demo transcript/GIF);
    # widen only if a future tactic/technique name outgrows it.
    width = max(60, len(header), *(len(row) for row in rows)) if rows else 60
    lines = ["ATT&CK-for-ICS coverage map", "=" * width]
    lines.append(header)
    lines.append("  " + "-" * (width - 2))
    lines.extend(rows)
    lines.append("=" * width)
    lines.append(
        f"{len(registry)} detections · {len(techniques)} ATT&CK techniques · "
        f"{len(tactics)} tactics · {len(fired)} fired this run"
    )
    return "\n".join(lines)
