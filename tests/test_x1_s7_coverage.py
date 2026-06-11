"""Regression coverage for X1's S7 normalization surface."""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_X1_RULE = _REPO_ROOT / "detections" / "zeek" / "x1_cross_protocol_baseline.zeek"
_X1_DOC = _REPO_ROOT / "detections" / "docs" / "X1-cross-protocol-baseline.md"
_S7_X1_SCENARIO = _REPO_ROOT / "scenarios" / "s7" / "anomalous-x1-new-function.yaml"


def test_x1_observes_general_s7_header_not_only_read_szl() -> None:
    """X1 must observe non-SZL S7comm functions through the base header event."""
    rule = _X1_RULE.read_text()

    assert "event s7comm_header" in rule
    assert "norm_s7comm_header_func" in rule
    assert "event s7comm_read_szl" in rule
    assert 'observe(c, norm_func("s7comm", norm_s7comm_header_func' in rule


def test_x1_documents_and_fixtures_non_szl_s7_fire_case() -> None:
    """Keep a committed S7 non-SZL fire scenario linked from the X1 doc."""
    doc = _X1_DOC.read_text()
    scenario = _S7_X1_SCENARIO.read_text()

    assert "s7comm_header" in doc
    assert "s7/anomalous-x1-new-function.yaml" in doc
    assert "function: WriteVariable" in scenario
    assert "- X1" in scenario


def test_x1_skips_actual_read_szl_request_function_from_generic_header() -> None:
    """Read SZL requests use User-Data FUNC 0x44 and must stay SZL-only."""
    rule = _X1_RULE.read_text()

    assert "function_code == 0x44" in rule
    assert "function_code == 0x04 && subfunction == 0x01" not in rule
