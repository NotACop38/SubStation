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
