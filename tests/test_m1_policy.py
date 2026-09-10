"""M1 must authorize the full destination, address space and write span."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from substation.detect import run_detections
from substation.detect.registry import load_registry
from substation.detect.sigma_eval import load_rule, matching_indices
from substation.emit import write_artifacts
from substation.protocols.modbus import build_events, event_to_dict
from substation.scenarios import load_scenario

_REPO = Path(__file__).resolve().parent.parent
_M1 = next(d for d in load_registry() if d.id == "M1")
_SPAN = _REPO / "scenarios/modbus/anomalous-m1-span-beyond-policy.yaml"


def test_m1_fires_on_full_span_crossing_policy(tmp_path: Path) -> None:
    emitted = write_artifacts(load_scenario(_SPAN), tmp_path)
    assert [h.event_index for h in run_detections(emitted.jsonl, [_M1])] == [0]


def test_every_small_register_span_obeys_policy() -> None:
    event = build_events(load_scenario(_SPAN))[0]
    # Independent interval oracle covers both boundaries, all legal spans and
    # every adjacent too-long span, rather than mirroring the Sigma selections.
    cases = [(start, size) for start in range(39, 51) for size in range(1, 12)]
    events = [
        event_to_dict(replace(event, address=start, quantity=size, request_values=(0,) * size))
        for start, size in cases
    ]
    expected = [
        i for i, (start, size) in enumerate(cases) if not (start >= 40 and start + size <= 50)
    ]
    assert matching_indices(load_rule(_M1.rule_path), events) == expected


@pytest.mark.parametrize(
    "changes",
    [{"resp_h": "10.0.0.51"}, {"resp_p": 1502}, {"func_code": 5}, {"func_code": 15}],
)
def test_writer_allowlist_does_not_authorize_other_assets_or_coils(
    changes: dict[str, object],
) -> None:
    event = build_events(load_scenario(_SPAN))[0]
    event = replace(event, address=40, quantity=1, request_values=(1,))
    record = event_to_dict(event)
    for key, value in changes.items():
        if key.startswith("resp_"):
            record["conn"][key] = value
        else:
            record[key] = value
    assert matching_indices(load_rule(_M1.rule_path), [record]) == [0]
