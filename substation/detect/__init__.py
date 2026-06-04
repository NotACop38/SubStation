"""Sigma evaluation, Zeek runner, Suricata runner.

Tier 1 (the headline path, PRD.md §6.2) is implemented here: :func:`run_detections`
evaluates every registered **Tier-1 Sigma** detection directly over the ``.jsonl``
event log via the offline evaluator (:mod:`substation.detect.sigma_eval`), the
mechanism confirmed in ``docs/spikes/03-sigma-offline-evaluation.md``. Tier-2
Zeek/Suricata detections (PRD.md §6.5) execute in the Tier-2 runner over PCAP and
are skipped here.

The per-detection metadata (which engine, which tier, which rule file) comes from
the detection registry (:mod:`substation.detect.registry`), so adding a Sigma
detection there makes :func:`run_detections` pick it up with no code change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .registry import Detection, load_registry
from .sigma_eval import load_rule, matching_indices

__all__ = ["Hit", "run_detections", "load_events"]


@dataclass(frozen=True, slots=True)
class Hit:
    """One detection alert: which detection fired on which event."""

    detection_id: str
    event_index: int


def load_events(events_path: str | Path) -> list[dict[str, Any]]:
    """Read a ``.jsonl`` event log into a list of event dicts (blank lines skipped).

    A *missing* log is an error, not an empty input: silently treating it as
    "no events" would let the pipeline (and the Detection Contract checks) report
    quiet/green even though the detector never consumed any telemetry.
    """
    path = Path(events_path)
    if not path.exists():
        raise FileNotFoundError(f"event log not found: {path} (was the generate stage run?)")
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def run_detections(events_path: str | Path, detections: list[Detection] | None = None) -> list[Hit]:
    """Evaluate Tier-1 Sigma detections over the JSONL event log at ``events_path``.

    Returns one :class:`Hit` per (detection, matching event). Tier-2 detections
    (Zeek/Suricata) are skipped — they run in the Tier-2 runner over PCAP. Pass
    ``detections`` to scope evaluation to a subset (the harness does this);
    otherwise the full registry is used.
    """
    events = load_events(events_path)
    registry = load_registry() if detections is None else detections
    hits: list[Hit] = []
    for det in registry:
        if det.engine != "sigma" or det.tier != 1:
            continue
        rule = load_rule(det.rule_path)
        hits.extend(Hit(detection_id=det.id, event_index=i) for i in matching_indices(rule, events))
    return hits
