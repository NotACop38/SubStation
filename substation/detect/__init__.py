"""Sigma evaluation, Zeek runner, Suricata runner.

Phase 0 is a NO-OP: the detector exercises the "detect" stage by reading the
(empty) JSONL event log and returning no hits. Real Sigma-over-JSON evaluation
(Tier 1) and the Zeek/Suricata runners (Tier 2) land in later phases per the
engine policy (`PRD.md` §6.5).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["Hit", "run_detections"]


@dataclass(frozen=True, slots=True)
class Hit:
    """One detection alert: which detection fired on which event."""

    detection_id: str
    event_index: int


def run_detections(events_path: str | Path) -> list[Hit]:
    """Evaluate detections over the JSONL event log at ``events_path``.

    Phase 0 no-op: reads the (empty) log and returns an empty hit list. Reading
    the file here proves the detect stage is wired to the emit stage's output.

    A *missing* log is an error, not an empty input: silently treating it as
    "no events" would let the pipeline (and future Detection Contract checks)
    report quiet/green even though the detector never consumed any telemetry.
    """
    path = Path(events_path)
    if not path.exists():
        raise FileNotFoundError(f"event log not found: {path} (was the generate stage run?)")
    lines = path.read_text(encoding="utf-8").splitlines()
    _ = lines  # no rules yet; counting events is a Phase 1 concern.
    return []
