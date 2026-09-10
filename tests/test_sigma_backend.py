"""Independent execution of exported Sigma, including known backend boundaries."""

from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from scripts.verify.sigma_backend import main, sqlite_hits
from substation.detect.registry import load_registry
from substation.detect.sigma_eval import matching_indices, parse_rule
from substation.policy import compile_policy, load_policy
from substation.protocols.modbus import build_events, event_to_dict
from substation.scenarios import load_scenario
from substation.schema import validate_event

ROOT = Path(__file__).resolve().parents[1]


def policy() -> dict[str, Any]:
    return load_policy(ROOT / "detections/policies/bundled-demo.yaml")


def write_event(address: int, quantity: int, code: int = 16) -> dict[str, Any]:
    return {
        "proto": "modbus",
        "direction": "request",
        "action_class": "write",
        "func_code": code,
        "conn": {"orig_h": "10.0.0.10", "resp_h": "10.0.0.50", "resp_p": 502},
        "detail": {"unit": 1, "address": address, "quantity": quantity},
    }


def test_all_authored_and_exported_rules_agree_on_catalogue_and_external_corpus(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["events"] > 223  # synthetic catalogue plus external sensor observations
    assert set(report["authored"]) == {d.id for d in load_registry() if d.engine == "sigma"}
    assert report["authored"] == report["site_export"]
    assert all(hits > 0 for hits in report["authored"].values())


@pytest.mark.parametrize("space", ["coil", "holding-register"])
def test_exported_m1_matches_interval_oracle(space: str) -> None:
    site = policy()
    site["modbus"]["writes"] = [
        {
            "sources": ["10.0.0.10"],
            "destination": "10.0.0.50",
            "port": 502,
            "units": [1],
            "address_space": space,
            "ranges": [{"start": 40, "end": 49}],
        }
    ]
    source = compile_policy(site)["M1"]
    events = [
        write_event(a, q, code)
        for code in (5, 6, 15, 16)
        for a in (0, 39, 40, 41, 48, 49, 50, 65535)
        for q in (1, 2, 9, 10, 11, 123, 124, 1968)
    ]
    expected = []
    for i, event in enumerate(events):
        code, detail = event["func_code"], event["detail"]
        allowed = (
            code in ((5, 15) if space == "coil" else (6, 16))
            and (code not in (5, 6) or detail["quantity"] == 1)
            and detail["address"] >= 40
            and detail["address"] + detail["quantity"] <= 50
        )
        if not allowed:
            expected.append(i)
    assert sqlite_hits(source, events) == expected
    assert matching_indices(parse_rule(source), events) == expected


def test_empty_permissions_wrong_target_and_case_contract() -> None:
    site = policy()
    site["modbus"]["writes"] = []
    event = write_event(40, 1)
    assert sqlite_hits(compile_policy(site)["M1"], [event]) == [0]
    source = compile_policy(policy())["M1"]
    wrong_target = copy.deepcopy(event)
    wrong_target["conn"]["resp_h"] = "10.0.0.51"
    event["proto"] = "MODBUS"
    event["direction"] = "REQUEST"
    assert sqlite_hits(source, [event, wrong_target]) == [1]


def test_null_under_negated_permission_is_a_known_unqualified_boundary() -> None:
    # Valid schema permits absent Modbus detail fields. Python matches NOT false;
    # raw SQLite gets NOT NULL. Never fill NULLs to conceal this deployment gap.
    source = compile_policy(policy())["M1"]
    events = build_events(load_scenario(ROOT / "scenarios/modbus/benign-baseline.yaml"))
    event = event_to_dict(next(e for e in events if e.is_orig and e.func_code == 6))
    del event["detail"]["quantity"]
    validate_event(event)
    assert matching_indices(parse_rule(source), [event]) == [0]
    assert sqlite_hits(source, [event]) == []


def test_large_coil_policy_exceeds_sqlite_expression_limit() -> None:
    # Portable Sigma expansion is bounded by the compiler, but a backend can
    # impose a lower limit. This known failure must remain documented, not skipped.
    site = policy()
    site["modbus"]["writes"][0]["address_space"] = "coil"
    site["modbus"]["writes"][0]["ranges"] = [{"start": 0, "end": 65535}]
    source = compile_policy(site)["M1"]
    with pytest.raises(sqlite3.OperationalError, match="Expression tree is too large"):
        sqlite_hits(source, [write_event(0, 1, 5)])
