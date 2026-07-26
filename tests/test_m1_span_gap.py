"""Document the accepted M1 quantity/span modelling gap (PRD §5.1 / M1 doc).

Sigma field-match cannot express ``address + quantity - 1`` arithmetic. A write
that *starts* in the setpoint band (40–49) but spans past 49 via a large
``quantity`` is therefore not caught by M1 today. This test locks that accepted
limitation so a future close (Zeek or enriched fields) is an intentional change.
"""

from __future__ import annotations

from pathlib import Path

from substation.detect import run_detections
from substation.detect.registry import load_registry
from substation.emit import write_artifacts
from substation.scenarios import load_scenario

_REPO = Path(__file__).resolve().parent.parent
_SCENARIO = _REPO / "scenarios" / "modbus" / "anomalous-m1-span-beyond-policy.yaml"


def test_m1_does_not_fire_on_in_band_start_with_span_past_policy(tmp_path: Path) -> None:
    scenario = load_scenario(_SCENARIO)
    emitted = write_artifacts(scenario, tmp_path)
    m1 = next(d for d in load_registry() if d.id == "M1")
    hits = run_detections(emitted.jsonl, [m1])
    assert hits == [], (
        "M1 unexpectedly fired on a span-beyond-policy write; if this is intentional, "
        "update detections/docs/M1-unauthorized-write.md and remove this acceptance test"
    )
