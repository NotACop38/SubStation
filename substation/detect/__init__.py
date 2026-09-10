"""Tier-1 Sigma evaluation over JSON event logs.

Tier 1 (the headline path, PRD.md §6.2) is implemented here: :func:`run_detections`
evaluates every registered **Tier-1 Sigma** detection directly over the ``.jsonl``
event log via the offline evaluator (:mod:`substation.detect.sigma_eval`), the
mechanism confirmed in ``docs/spikes/03-sigma-offline-evaluation.md``.

Tier-2 Zeek/Suricata detections (PRD.md §6.5) are **not** executed in this
package — they run in the out-of-package Tier-2 runner (``scripts/verify/run.py``
/ ``make verify``) over PCAP and are skipped by :func:`run_detections`.

The per-detection metadata (which engine, which tier, which rule file) comes from
the detection registry (:mod:`substation.detect.registry`), so adding a Sigma
detection there makes :func:`run_detections` pick it up with no code change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from substation.schema import (
    MAX_JSONL_BYTES,
    MAX_JSONL_LINES,
    SchemaValidationError,
    iter_jsonl_lines,
    load_event_schema,
    parse_json_event,
    validate_event,
)

from .registry import Detection, load_registry
from .sigma_eval import load_rule, matching_indices, parse_rule

__all__ = ["Hit", "run_detections", "load_events", "MAX_JSONL_LINES", "MAX_JSONL_BYTES"]


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

    Caps :data:`MAX_JSONL_BYTES` / :data:`MAX_JSONL_LINES` guard local DoS from an
    accidentally huge or hostile input file.
    """
    path = Path(events_path)
    if not path.exists():
        raise FileNotFoundError(f"event log not found: {path} (was the generate stage run?)")
    events: list[dict[str, Any]] = []
    schema = load_event_schema()
    for line_no, line in iter_jsonl_lines(
        path, max_bytes=MAX_JSONL_BYTES, max_lines=MAX_JSONL_LINES
    ):
        if line.strip():
            try:
                event = parse_json_event(line)
                validate_event(event, schema)
            except ValueError as exc:
                raise SchemaValidationError(f"{path}:{line_no}: {exc}") from exc
            events.append(event)
    return events


def run_detections(
    events_path: str | Path,
    detections: list[Detection] | None = None,
    *,
    policy: dict[str, Any] | None = None,
) -> list[Hit]:
    """Evaluate Tier-1 Sigma detections over the JSONL event log at ``events_path``.

    Returns one :class:`Hit` per (detection, matching event). Tier-2 detections
    (Zeek/Suricata) are skipped — they run in the Tier-2 runner over PCAP. Pass
    ``detections`` to scope evaluation to a subset (the harness does this);
    otherwise the full registry is used.
    """
    events = load_events(events_path)
    registry = load_registry() if detections is None else detections
    from substation.policy import compile_policy

    compiled = compile_policy(policy) if policy is not None else None
    hits: list[Hit] = []
    for det in registry:
        if det.engine != "sigma" or det.tier != 1:
            continue
        rule = parse_rule(compiled[det.id]) if compiled is not None else load_rule(det.rule_path)
        hits.extend(Hit(detection_id=det.id, event_index=i) for i in matching_indices(rule, events))
    return hits
