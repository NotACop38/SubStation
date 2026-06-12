"""The Detection Contract harness (Tier 1: Sigma over ``.jsonl``).

This is the data-driven harness PRD.md §6.6 / the Engineering Checklist's
"Detection Definition of Done" call for. It is **fully metadata-driven**: it reads
the detection registry (``detections/registry.yaml``) and every scenario under
``scenarios/``, then for each detection asserts — from that detection's own
``exercises:`` scenarios — that it **fires on its anomalous telemetry** and stays
**quiet on its benign telemetry**. Adding a detection (registry entry + rule +
scenarios) makes the fire/quiet cases appear here automatically; the one piece
of test code a new *validated Tier-1* fire scenario must add is its exact-hit
entry in ``_EXPECTED_FIRE_HITS`` below (the over-match regression net).

Tier scoping (PRD.md §6.2): Tier-1 Sigma detections are evaluated directly over
the generated JSON event log here. Tier-2 detections (Zeek/Suricata) execute in
the Tier-2 runner over PCAP, so their fire/quiet cases are *skipped* here with a
reason — but their contract linkage (a rule, ≥1 fire and ≥1 quiet scenario) is
still enforced below.
"""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

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


def _count_hits(
    det: Detection, scenario: Scenario, tmp_path: Path, *, allow_unemittable: bool = False
) -> int:
    """Run the Tier-1 loop (emit -> detect) for one detection on one scenario.

    Skips (rather than fails) when Tier 1 cannot exercise the case: a Tier-2
    detection, or an explicitly allowed partial forward-looking fire fixture.
    Validated Tier-1 detections must always emit; otherwise the Detection
    Contract would turn a regression into a green CI skip.
    """
    if det.engine != "sigma" or det.tier != 1:
        pytest.skip(
            f"{det.id} is a Tier-{det.tier} {det.engine} detection — its fire/quiet "
            "runs in the Tier-2 runner over PCAP, not the Tier-1 Sigma harness"
        )
    try:
        result = write_artifacts(scenario, tmp_path)
    except (EmitError, ModbusError) as exc:
        if allow_unemittable:
            pytest.skip(f"scenario {scenario.name!r} not yet emittable ({exc})")
        pytest.fail(
            f"{det.id} is status={det.status!r}; scenario {scenario.name!r} must be "
            f"emittable for the Tier-1 Detection Contract ({exc})"
        )
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
    hits = _count_hits(det, scenario, tmp_path, allow_unemittable=det.status == "partial")
    assert hits >= 1, f"{det.id} did not fire on anomalous scenario {scenario.name!r}"


@pytest.mark.parametrize(("det", "scenario"), _QUIET_CASES, ids=_QUIET_IDS)
def test_quiet_on_benign(det: Detection, scenario: Scenario, tmp_path: Path) -> None:
    hits = _count_hits(det, scenario, tmp_path)
    assert hits == 0, f"{det.id} fired on quiet scenario {scenario.name!r} ({hits} hit(s))"


# --- exact-hit regression net -------------------------------------------------
#
# fire-on-anomaly (>=1 hit) and quiet-on-benign (0 hits) can both pass while a
# rule silently over-matches (e.g. also firing on responses it never meant to).
# This table pins each validated Tier-1 fire case to the exact event indices the
# rule must hit, verified by hand against scenario intent: every hit lands on
# the malicious REQUEST events (plus M2's exception-response arm, by design).
# Changing a shipped rule or scenario such that these move is a deliberate
# contract change — update the table in the same commit.

_EXPECTED_FIRE_HITS: dict[tuple[str, str], tuple[int, ...]] = {
    # M1: the two out-of-policy write requests.
    ("M1", "anomalous-m1-unauthorized-write"): (6, 8),
    ("M1", "anomalous-m1-out-of-policy-write"): (4, 6),
    # M2: the undefined-function request and the ILLEGAL_FUNCTION exception reply.
    ("M2", "anomalous-m2-illegal-function"): (2, 3),
    # D1/D2/D3: the restart / disable-unsolicited / (direct-)operate requests.
    ("D1", "dnp3-anomalous-d1-restart"): (5,),
    ("D2", "dnp3-anomalous-d2-disable-unsolicited"): (3,),
    ("D3", "dnp3-anomalous-d3-unauthorized-operate"): (4, 6),
    # S1: the PLC Stop request. S2: the download-sequence + Create Object requests.
    ("S1", "s7-anomalous-s1-cpu-stop"): (12,),
    ("S2", "s7-anomalous-s2-program-download"): (10, 12, 14, 16),
}


def test_expected_hit_table_covers_every_validated_tier1_fire_case() -> None:
    """A new validated Tier-1 fire scenario must pin its exact hits here too."""
    validated_pairs = {
        (d.id, s.name)
        for d, s in _FIRE_CASES
        if d.engine == "sigma" and d.tier == 1 and d.status == "validated"
    }
    assert validated_pairs == set(_EXPECTED_FIRE_HITS), (
        "validated Tier-1 fire cases and _EXPECTED_FIRE_HITS disagree; "
        f"missing from table: {sorted(validated_pairs - set(_EXPECTED_FIRE_HITS))}, "
        f"stale in table: {sorted(set(_EXPECTED_FIRE_HITS) - validated_pairs)}"
    )


@pytest.mark.parametrize(
    ("det_id", "scenario_name", "expected"),
    [(d, s, idx) for (d, s), idx in _EXPECTED_FIRE_HITS.items()],
    ids=[f"{d}-{s}" for d, s in _EXPECTED_FIRE_HITS],
)
def test_fires_on_exactly_the_expected_events(
    det_id: str, scenario_name: str, expected: tuple[int, ...], tmp_path: Path
) -> None:
    det = _BY_ID[det_id]
    scenario = next(s for s in SCENARIOS if s.name == scenario_name)
    result = write_artifacts(scenario, tmp_path)
    hits = run_detections(result.jsonl, [det])
    indices = tuple(sorted(h.event_index for h in hits if h.detection_id == det.id))
    assert indices == expected, (
        f"{det.id} on {scenario.name!r}: hit event indices {indices} != expected {expected} "
        "(an over- or under-matching rule, or a scenario edit — if deliberate, "
        "update _EXPECTED_FIRE_HITS)"
    )


def test_validated_tier1_emit_errors_fail_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Validated Tier-1 scenarios must fail, not skip, if emission regresses."""
    det, scenario = next(
        (d, s)
        for d, s in _FIRE_CASES
        if d.engine == "sigma" and d.tier == 1 and d.status == "validated"
    )

    def fail_emit(_scenario: Scenario, _out_dir: Path) -> NoReturn:
        raise EmitError("regression made validated fixture un-emittable")

    monkeypatch.setattr("tests.test_detection_contract.write_artifacts", fail_emit)

    with pytest.raises(pytest.fail.Exception, match="must be emittable"):
        _count_hits(det, scenario, tmp_path)
