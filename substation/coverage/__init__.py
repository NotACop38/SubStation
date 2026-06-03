"""Coverage-map and ATT&CK Navigator layer builder.

Phase 0 is a NO-OP: the reporter exercises the "report" stage by rendering a
placeholder coverage map from the scenario's declared ``exercises`` and the
(empty) hit list. The real metadata-driven coverage map + ATT&CK Navigator layer
(`PRD.md` §6.7) land in later phases.
"""

from __future__ import annotations

from substation.detect import Hit
from substation.scenarios import Scenario

__all__ = ["render_coverage_map"]


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
