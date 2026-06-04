"""The Detection Contract harness (Tier 1: Sigma over ``.jsonl``).

This is the data-driven harness PRD.md §6.6 / the Engineering Checklist's
"Detection Definition of Done" call for. It is **fully metadata-driven**: it reads
the detection registry (``detections/registry.yaml``) and every scenario under
``scenarios/``, then for each detection asserts — from that detection's own
``exercises:`` scenarios — that it **fires on its anomalous telemetry** and stays
**quiet on its benign telemetry**. Adding a detection (registry entry + rule +
scenarios) makes new cases appear here automatically; no test code changes.

Tier scoping (PRD.md §6.2): Tier-1 Sigma detections are evaluated directly over
the generated JSON event log here. Tier-2 detections (Zeek/Suricata) execute in
the Tier-2 runner over PCAP, so their fire/quiet cases are *skipped* here with a
reason — but their contract linkage (a rule, ≥1 fire and ≥1 quiet scenario) is
still enforced below.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from substation.detect import run_detections
from substation.detect.registry import Detection, load_registry
from substation.detect.sigma_eval import load_rule
from substation.emit import EmitError, write_artifacts
from substation.protocols.modbus import ModbusError
from substation.scenarios import Scenario, load_scenarios

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCENARIO_DIR = _REPO_ROOT / "scenarios"

REGISTRY: list[Detection] = load_registry()
SCENARIOS: list[Scenario] = load_scenarios(_SCENARIO_DIR)
_BY_ID: dict[str, Detection] = {det.id: det for det in REGISTRY}


def _scenarios_exercising(det_id: str, *, fires: bool) -> list[Scenario]:
    """Scenarios whose ``exercises.fires`` (or ``.quiet``) names ``det_id``."""
    out: list[Scenario] = []
    for scenario in SCENARIOS:
        ids = scenario.exercises.fires if fires else scenario.exercises.quiet
        if det_id in ids:
            out.append(scenario)
    return out


# (detection, scenario) cases, built once from the metadata at collection time.
_FIRE_CASES = [(d, s) for d in REGISTRY for s in _scenarios_exercising(d.id, fires=True)]
_QUIET_CASES = [(d, s) for d in REGISTRY for s in _scenarios_exercising(d.id, fires=False)]
_FIRE_IDS = [f"{d.id}-{s.name}" for d, s in _FIRE_CASES]
_QUIET_IDS = [f"{d.id}-{s.name}" for d, s in _QUIET_CASES]


def _count_hits(det: Detection, scenario: Scenario, tmp_path: Path) -> int:
    """Run the Tier-1 loop (emit -> detect) for one detection on one scenario.

    Skips (rather than fails) when Tier 1 cannot exercise the case: a Tier-2
    detection, or a scenario the current emitter cannot yet encode (a
    forward-looking fixture). The skip reason names why, so the gap is visible.
    """
    if det.engine != "sigma" or det.tier != 1:
        pytest.skip(
            f"{det.id} is a Tier-{det.tier} {det.engine} detection — its fire/quiet "
            "runs in the Tier-2 runner over PCAP, not the Tier-1 Sigma harness"
        )
    try:
        result = write_artifacts(scenario, tmp_path)
    except (EmitError, ModbusError) as exc:
        pytest.skip(f"scenario {scenario.name!r} not yet emittable ({exc})")
    hits = run_detections(result.jsonl, [det])
    return sum(1 for hit in hits if hit.detection_id == det.id)


# --- contract linkage (every detection, every engine) ------------------------


@pytest.mark.parametrize("det", REGISTRY, ids=[d.id for d in REGISTRY])
def test_detection_has_rule_and_doc(det: Detection) -> None:
    assert det.rule_path.exists(), f"{det.id}: missing rule file {det.rule}"
    assert det.doc_path.exists(), f"{det.id}: missing doc file {det.doc}"


@pytest.mark.parametrize("det", REGISTRY, ids=[d.id for d in REGISTRY])
def test_detection_has_fire_and_quiet_scenarios(det: Detection) -> None:
    fires = _scenarios_exercising(det.id, fires=True)
    quiet = _scenarios_exercising(det.id, fires=False)
    assert fires, f"{det.id}: no scenario lists it under exercises.fires"
    assert quiet, f"{det.id}: no scenario lists it under exercises.quiet"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_exercises_reference_known_detections(scenario: Scenario) -> None:
    referenced = set(scenario.exercises.fires) | set(scenario.exercises.quiet)
    unknown = referenced - set(_BY_ID)
    assert not unknown, f"{scenario.name}: exercises name unknown detection(s) {sorted(unknown)}"


@pytest.mark.parametrize(
    "det",
    [d for d in REGISTRY if d.engine == "sigma"],
    ids=[d.id for d in REGISTRY if d.engine == "sigma"],
)
def test_sigma_rule_consistent_with_registry(det: Detection) -> None:
    """A Sigma rule's logsource + ATT&CK tags must agree with the registry.

    Guards against drift between the verified registry metadata (which the
    coverage map is generated from) and the authored rule's own tags.
    """
    rule = load_rule(det.rule_path)
    assert rule.logsource.service == det.protocol, (
        f"{det.id}: rule logsource.service {rule.logsource.service!r} != "
        f"registry protocol {det.protocol!r}"
    )
    tags = {str(tag) for tag in rule.tags}
    assert f"attack.{det.attack.tactic_shortname}" in tags, (
        f"{det.id}: rule is missing the tactic tag attack.{det.attack.tactic_shortname}"
    )
    for technique in det.attack.techniques:
        expected = f"attack.{technique.id.lower()}"
        assert expected in tags, f"{det.id}: rule is missing the technique tag {expected}"


# --- the Detection Contract: fire-on-anomaly + quiet-on-benign ---------------


@pytest.mark.parametrize(("det", "scenario"), _FIRE_CASES, ids=_FIRE_IDS)
def test_fires_on_anomaly(det: Detection, scenario: Scenario, tmp_path: Path) -> None:
    assert scenario.label.value == "anomalous", (
        f"{scenario.name} lists {det.id} under exercises.fires but is not labelled anomalous"
    )
    hits = _count_hits(det, scenario, tmp_path)
    assert hits >= 1, f"{det.id} did not fire on anomalous scenario {scenario.name!r}"


@pytest.mark.parametrize(("det", "scenario"), _QUIET_CASES, ids=_QUIET_IDS)
def test_quiet_on_benign(det: Detection, scenario: Scenario, tmp_path: Path) -> None:
    hits = _count_hits(det, scenario, tmp_path)
    assert hits == 0, f"{det.id} fired on quiet scenario {scenario.name!r} ({hits} hit(s))"
