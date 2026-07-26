"""Unit tests for the Tier-1 Sigma offline evaluator (substation.detect.sigma_eval)."""

from __future__ import annotations

import pytest
from substation.detect.sigma_eval import SigmaEvalError, matching_indices, parse_rule

_ALLOWLIST_RULE = """
title: write from non-allowlisted source
id: 00000000-0000-0000-0000-000000000001
logsource: {product: ot, service: modbus}
detection:
    writes:
        action_class: write
    allowlisted:
        conn.orig_h:
            - 10.0.0.10
            - 10.0.0.11
        detail.unit: 1
    condition: writes and not allowlisted
"""

_EXCEPTION_RULE = """
title: illegal function exception
id: 00000000-0000-0000-0000-000000000002
logsource: {product: ot, service: modbus}
detection:
    other_code:
        action_class: other
    exc:
        is_exception: true
        error: ILLEGAL_FUNCTION
    condition: other_code or exc
"""


def _event(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "action_class": "read",
        "is_exception": False,
        "error": None,
        "conn": {"orig_h": "10.0.0.10"},
        "detail": {"unit": 1},
    }
    base.update(over)
    return base


def test_and_not_with_value_list_and_dotted_paths() -> None:
    rule = parse_rule(_ALLOWLIST_RULE)
    events = [
        _event(action_class="write"),  # 0: allow-listed writer, unit 1 -> quiet
        _event(action_class="write", conn={"orig_h": "10.0.0.77"}),  # 1: rogue -> fire
        _event(action_class="write", detail={"unit": 2}),  # 2: off-policy unit -> fire
        _event(action_class="read", conn={"orig_h": "10.0.0.77"}),  # 3: read -> quiet
    ]
    assert matching_indices(rule, events) == [1, 2]


def test_or_matches_numeric_bool_and_string_leaves() -> None:
    rule = parse_rule(_EXCEPTION_RULE)
    events = [
        _event(action_class="other"),  # 0: abnormal code arm -> fire
        _event(is_exception=True, error="ILLEGAL_FUNCTION"),  # 1: exception arm -> fire
        _event(is_exception=True, error="ILLEGAL_DATA_ADDRESS"),  # 2: other error -> quiet
        _event(action_class="read"),  # 3: normal -> quiet
    ]
    assert matching_indices(rule, events) == [0, 1]


def test_missing_field_does_not_match() -> None:
    rule = parse_rule(_ALLOWLIST_RULE)
    # No conn/detail at all: the 'allowlisted' selection cannot match, so a write
    # still fires (writes AND NOT allowlisted), proving absent fields read as False.
    assert matching_indices(rule, [{"action_class": "write"}]) == [0]


def test_boolean_field_not_matched_by_string_token() -> None:
    # is_exception is a real bool; a 0/1 integer must not satisfy `is_exception: true`.
    rule = parse_rule(_EXCEPTION_RULE)
    assert matching_indices(rule, [_event(is_exception=1, error="ILLEGAL_FUNCTION")]) == []


def test_numeric_range_modifiers() -> None:
    rule = parse_rule(
        """
title: setpoint band
id: 00000000-0000-0000-0000-000000000004
logsource: {product: ot, service: modbus}
detection:
    band:
        detail.address|gte: 40
        detail.address|lte: 49
    condition: band
"""
    )
    events = [
        _event(detail={"address": 39}),
        _event(detail={"address": 40}),
        _event(detail={"address": 49}),
        _event(detail={"address": 50}),
    ]
    assert matching_indices(rule, events) == [1, 2]


def test_unsupported_wildcard_raises() -> None:
    rule = parse_rule(
        """
title: wildcard
id: 00000000-0000-0000-0000-000000000003
logsource: {product: ot, service: modbus}
detection:
    sel:
        func_name: READ_*
    condition: sel
"""
    )
    with pytest.raises(SigmaEvalError):
        matching_indices(rule, [_event(func_name="READ_COILS")])
