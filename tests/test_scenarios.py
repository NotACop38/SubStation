"""Tests for the scenario model + YAML loader (Phase 0)."""

from __future__ import annotations

from pathlib import Path

import pytest
from substation.scenarios import (
    ActorRole,
    Label,
    Protocol,
    ScenarioError,
    load_scenario,
    load_scenarios,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"


def test_bundled_example_loads_and_validates() -> None:
    scenario = load_scenario(_EXAMPLE)
    assert scenario.name == "benign-poll"
    assert scenario.protocol is Protocol.MODBUS
    assert scenario.label is Label.BENIGN
    assert len(scenario.actors) == 3
    assert len(scenario.exchanges) == 3
    assert scenario.exercises.quiet == ("M1", "M2", "M3")
    assert scenario.exercises.fires == ()
    # Every exchange references a declared actor.
    ids = {a.id for a in scenario.actors}
    for ex in scenario.exchanges:
        assert ex.source in ids
        assert ex.target in ids


def test_actor_lookup_and_roles() -> None:
    scenario = load_scenario(_EXAMPLE)
    assert scenario.actor("ews-1").role is ActorRole.EWS
    assert scenario.actor("plc-1").port == 502
    with pytest.raises(KeyError):
        scenario.actor("nope")


def test_load_scenarios_finds_bundled_modbus() -> None:
    scenarios = load_scenarios(_REPO_ROOT / "scenarios" / "modbus")
    assert any(s.name == "benign-poll" for s in scenarios)


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "s.yaml"
    p.write_text(text, encoding="utf-8")
    return p


_MINIMAL = """
name: t
protocol: modbus
label: benign
actors:
  - {id: a, role: hmi, host: 10.0.0.1}
exchanges: []
"""


def test_minimal_scenario_ok(tmp_path: Path) -> None:
    scenario = load_scenario(_write(tmp_path, _MINIMAL))
    assert scenario.name == "t"
    assert scenario.exchanges == ()
    # Timing/exercises default sensibly.
    assert scenario.timing.default_interval == 1.0
    assert scenario.exercises.fires == ()


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("", "empty scenario file"),
        (_MINIMAL.replace("protocol: modbus", "protocol: telnet"), "unknown protocol"),
        (_MINIMAL.replace("label: benign", "label: weird"), "unknown label"),
        (_MINIMAL.replace("role: hmi", "role: wizard"), "unknown role"),
        (_MINIMAL + "bogus_key: 1\n", "unknown key"),
        (
            _MINIMAL.replace("actors:\n  - {id: a, role: hmi, host: 10.0.0.1}", "actors: []"),
            "non-empty list",
        ),
    ],
)
def test_invalid_scenarios_raise(tmp_path: Path, text: str, needle: str) -> None:
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert needle in str(exc.value)


def test_exchange_referencing_unknown_actor_raises(tmp_path: Path) -> None:
    text = _MINIMAL.replace(
        "exchanges: []",
        "exchanges:\n  - {source: a, target: ghost, function: Read}",
    )
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert "unknown actor 'ghost'" in str(exc.value)


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, "name: [unterminated\n"))
    assert "invalid YAML" in str(exc.value)


@pytest.mark.parametrize("bad_name", ["../escaped", "a/b", "sub/dir", ".", ""])
def test_unsafe_scenario_name_rejected(tmp_path: Path, bad_name: str) -> None:
    text = _MINIMAL.replace("name: t", f"name: {bad_name!r}")
    with pytest.raises(ScenarioError):
        load_scenario(_write(tmp_path, text))


@pytest.mark.parametrize("falsy", ["[]", "0", "false", "''"])
def test_falsy_params_rejected(tmp_path: Path, falsy: str) -> None:
    text = _MINIMAL.replace(
        "exchanges: []",
        f"exchanges:\n  - {{source: a, target: a, function: Read, params: {falsy}}}",
    )
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert "params" in str(exc.value)


def test_absent_or_null_params_default_to_empty(tmp_path: Path) -> None:
    text = _MINIMAL.replace(
        "exchanges: []",
        "exchanges:\n"
        "  - {source: a, target: a, function: Read}\n"
        "  - {source: a, target: a, function: Read, params: null}",
    )
    scenario = load_scenario(_write(tmp_path, text))
    assert all(dict(ex.params) == {} for ex in scenario.exchanges)


def test_exchange_params_are_immutable(tmp_path: Path) -> None:
    text = _MINIMAL.replace(
        "exchanges: []",
        "exchanges:\n  - {source: a, target: a, function: Read, params: {unit_id: 1}}",
    )
    scenario = load_scenario(_write(tmp_path, text))
    with pytest.raises(TypeError):
        scenario.exchanges[0].params["unit_id"] = 2  # type: ignore[index]


@pytest.mark.parametrize("bad_port", ["-1", "70000", "65536"])
def test_actor_port_out_of_range_rejected(tmp_path: Path, bad_port: str) -> None:
    text = _MINIMAL.replace(
        "- {id: a, role: hmi, host: 10.0.0.1}",
        f"- {{id: a, role: hmi, host: 10.0.0.1, port: {bad_port}}}",
    )
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert "out of range" in str(exc.value)


def test_actor_port_in_range_ok(tmp_path: Path) -> None:
    text = _MINIMAL.replace(
        "- {id: a, role: hmi, host: 10.0.0.1}",
        "- {id: a, role: hmi, host: 10.0.0.1, port: 502}",
    )
    scenario = load_scenario(_write(tmp_path, text))
    assert scenario.actor("a").port == 502


def test_duplicate_yaml_key_rejected(tmp_path: Path) -> None:
    text = _MINIMAL.replace("label: benign", "label: benign\nlabel: anomalous")
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert "duplicate key" in str(exc.value)


def test_nested_params_are_deep_frozen(tmp_path: Path) -> None:
    text = _MINIMAL.replace(
        "exchanges: []",
        "exchanges:\n"
        "  - {source: a, target: a, function: Read, "
        "params: {nested: {k: 1}, values: [1, 2, 3]}}",
    )
    scenario = load_scenario(_write(tmp_path, text))
    params = scenario.exchanges[0].params
    # Nested list is frozen to a tuple; nested mapping is read-only.
    assert params["values"] == (1, 2, 3)
    with pytest.raises(TypeError):
        params["nested"]["k"] = 2  # type: ignore[index]


def test_detection_in_both_fires_and_quiet_rejected(tmp_path: Path) -> None:
    text = _MINIMAL + "exercises:\n  fires: [M1]\n  quiet: [M1]\n"
    with pytest.raises(ScenarioError) as exc:
        load_scenario(_write(tmp_path, text))
    assert "both" in str(exc.value)
