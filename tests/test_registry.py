"""Focused tests for detection-registry metadata strictness."""

from __future__ import annotations

from pathlib import Path

import pytest
from substation.detect.registry import RegistryError, load_registry


def _write_registry(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "registry.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _minimal_registry(*, tactic_id: str = "TA0102", technique_id: str = "T0888") -> str:
    return f"""
detections:
  - id: M2
    title: Illegal / abnormal function code
    protocol: modbus
    engine: sigma
    tier: 1
    status: validated
    rule: detections/sigma/modbus_m2_illegal_function_code.yml
    doc: detections/docs/M2-illegal-function-code.md
    attack:
      tactic: Discovery
      tactic_id: {tactic_id}
      techniques:
        - id: {technique_id}
          name: Remote System Information Discovery
"""


def test_registry_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = _write_registry(
        tmp_path,
        """
detections:
  - id: M2
    title: first
    title: second
    protocol: modbus
    engine: sigma
    tier: 1
    status: validated
    rule: detections/sigma/modbus_m2_illegal_function_code.yml
    doc: detections/docs/M2-illegal-function-code.md
    attack:
      tactic: Discovery
      tactic_id: TA0102
      techniques:
        - id: T0888
          name: Remote System Information Discovery
""",
    )

    with pytest.raises(RegistryError, match="duplicate key"):
        load_registry(path)


def test_registry_rejects_malformed_attack_tactic_id(tmp_path: Path) -> None:
    path = _write_registry(tmp_path, _minimal_registry(tactic_id="TA102"))

    with pytest.raises(RegistryError, match="tactic_id"):
        load_registry(path)


def test_registry_rejects_malformed_attack_technique_id(tmp_path: Path) -> None:
    path = _write_registry(tmp_path, _minimal_registry(technique_id="1692.001"))

    with pytest.raises(RegistryError, match="techniques\\[0\\].id"):
        load_registry(path)
