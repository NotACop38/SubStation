"""Packaged detections/scenarios resolve via substation.content."""

from __future__ import annotations

from substation.content import content_path, content_root
from substation.detect.registry import load_registry
from substation.scenarios import load_scenario


def test_content_root_exposes_registry_and_scenarios() -> None:
    root = content_root()
    assert (root / "detections" / "registry.yaml").is_file()
    assert (root / "scenarios" / "modbus").is_dir()
    assert content_path("detections", "registry.yaml").is_file()


def test_load_registry_and_scenario_via_content_api() -> None:
    registry = load_registry()
    assert any(d.id == "M1" for d in registry)
    scenario = load_scenario(content_path("scenarios", "modbus", "benign-poll.yaml"))
    assert scenario.name == "benign-poll"
