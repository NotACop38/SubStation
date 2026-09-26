"""Tier-1 Sigma evaluation over JSON event logs.

Tier 1 (the headline path, docs/design.md §6.2) is implemented here: :func:`run_detections`
evaluates every registered **Tier-1 Sigma** detection directly over the ``.jsonl``
event log via the offline evaluator (:mod:`substation.detect.sigma_eval`), the
mechanism confirmed in ``docs/spikes/03-sigma-offline-evaluation.md``.

Tier-2 Zeek/Suricata detections (docs/design.md §6.5) are **not** executed in this
package — they run in the out-of-package Tier-2 runner (``scripts/verify/run.py``
/ ``make verify``) over PCAP and are skipped by :func:`run_detections`.

The per-detection metadata (which engine, which tier, which rule file) comes from
the detection registry (:mod:`substation.detect.registry`), so adding a Sigma
detection there makes :func:`run_detections` pick it up with no code change.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from substation.schema import (
    MAX_JSONL_BYTES,
    MAX_JSONL_LINES,
    SchemaValidationError,
    iter_jsonl_lines,
    json_line,
    load_event_schema,
    parse_json_event,
    validate_event,
)

from .registry import Detection, load_registry
from .sigma_eval import ParsedRule, load_rule, matching_indices, parse_rule

__all__ = [
    "Hit",
    "prepare_rules",
    "run_detections",
    "load_events",
    "MAX_JSONL_LINES",
    "MAX_JSONL_BYTES",
]


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
    for line_no, raw in iter_jsonl_lines(
        path, max_bytes=MAX_JSONL_BYTES, max_lines=MAX_JSONL_LINES
    ):
        line = json_line(raw)
        if line is None:
            continue
        try:
            event = parse_json_event(line)
            validate_event(event, schema)
        except ValueError as exc:
            raise SchemaValidationError(f"{path}:{line_no}: {exc}") from exc
        events.append(event)
    return events


def prepare_rules(
    detections: list[Detection] | None = None, *, policy: dict[str, Any] | None = None
) -> dict[str, ParsedRule]:
    """Parse the rule of every Tier-1 Sigma detection once, keyed by detection id.

    With ``policy``, rules are compiled from the site profile instead of read from
    the bundled files. Tier-2 detections (Zeek/Suricata) are skipped. Prepare once
    and pass the result to :func:`run_detections` to evaluate several logs.
    """
    registry = load_registry() if detections is None else detections
    from substation.policy import compile_policy

    compiled = compile_policy(policy) if policy is not None else None
    return {
        det.id: parse_rule(compiled[det.id]) if compiled is not None else load_rule(det.rule_path)
        for det in registry
        if det.engine == "sigma" and det.tier == 1
    }


def run_detections(
    events_path: str | Path,
    detections: list[Detection] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    rules: Mapping[str, ParsedRule] | None = None,
) -> list[Hit]:
    """Evaluate Tier-1 Sigma detections over the JSONL event log at ``events_path``.

    Returns one :class:`Hit` per (detection, matching event), in detection order.
    Pass prepared ``rules`` (see :func:`prepare_rules`) to reuse parsed rules across
    logs; otherwise the rules of ``detections`` (default: the whole registry) are
    prepared here, applying ``policy`` if given.
    """
    events = load_events(events_path)
    if rules is None:
        rules = prepare_rules(detections, policy=policy)
    elif detections is not None or policy is not None:
        raise ValueError("pass prepared rules, or detections/policy to prepare them; not both")
    hits: list[Hit] = []
    for det_id, rule in rules.items():
        hits.extend(Hit(detection_id=det_id, event_index=i) for i in matching_indices(rule, events))
    return hits
