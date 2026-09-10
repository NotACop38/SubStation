"""Site policy uses complete-span and destination-bound authorization."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from substation.detect.sigma_eval import matching_indices, parse_rule
from substation.schema import SchemaValidationError


def policy_data() -> dict[str, Any]:
    return {
        "schema": "substation-site-policy/v1",
        "name": "example-site",
        "modbus": {
            "writes": [
                {
                    "sources": ["192.0.2.10"],
                    "destination": "192.0.2.50",
                    "port": 502,
                    "units": [1],
                    "address_space": "holding-register",
                    "ranges": [{"start": 40, "end": 49}],
                }
            ]
        },
        "channels": {key: [] for key in ("D1", "D2", "D3", "S1", "S2")},
    }


def test_compiled_span_matches_independent_interval_oracle(tmp_path: Path) -> None:
    from substation.policy import compile_policy, load_policy

    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(policy_data()))
    rule = parse_rule(compile_policy(load_policy(source))["M1"])
    for code in (5, 6, 15, 16):
        for address in range(38, 52):
            for quantity in (0, 1, 2, 10, 11, 124):
                event = {
                    "proto": "modbus",
                    "direction": "request",
                    "action_class": "write",
                    "func_code": code,
                    "conn": {"orig_h": "192.0.2.10", "resp_h": "192.0.2.50", "resp_p": 502},
                    "detail": {"unit": 1, "address": address, "quantity": quantity},
                }
                allowed = (
                    code in (6, 16)
                    and (code != 6 or quantity == 1)
                    and quantity >= 1
                    and address >= 40
                    and address + quantity <= 50
                )
                assert bool(matching_indices(rule, [event])) is not allowed


@pytest.mark.parametrize(
    "change",
    [
        {"port": True},
        {"units": [True]},
        {"sources": ["example.com"]},
        {"ranges": [{"start": 50, "end": 40}]},
        {"unexpected": 1},
    ],
)
def test_invalid_grants_fail(tmp_path: Path, change: dict[str, Any]) -> None:
    from substation.policy import load_policy

    data = policy_data()
    data["modbus"]["writes"][0].update(change)
    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(data))
    with pytest.raises(SchemaValidationError):
        load_policy(source)


def test_export_is_deterministic_and_does_not_overwrite(tmp_path: Path) -> None:
    from substation.policy import compile_policy, export_policy, load_policy

    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(policy_data()))
    policy = load_policy(source)
    assert compile_policy(policy) == compile_policy(copy.deepcopy(policy))
    out = tmp_path / "rules"
    export_policy(policy, out)
    assert (out / "M1.yml").read_text() == compile_policy(policy)["M1"]
    with pytest.raises(FileExistsError):
        export_policy(policy, out)


def test_bundled_profile_preserves_all_scenario_results(tmp_path: Path) -> None:
    from substation.detect import run_detections
    from substation.emit import write_artifacts
    from substation.policy import load_policy
    from substation.scenarios import load_scenario

    root = Path(__file__).resolve().parents[1]
    policy = load_policy(root / "detections/policies/bundled-demo.yaml")
    for scenario in sorted((root / "scenarios").glob("*/*.yaml")):
        events = write_artifacts(load_scenario(scenario), tmp_path).jsonl
        assert run_detections(events, policy=policy) == run_detections(events), scenario


def test_channel_requires_each_endpoint_and_service(tmp_path: Path) -> None:
    from substation.policy import compile_policy, load_policy

    data = policy_data()
    data["channels"]["D1"] = [
        {"sources": ["192.0.2.10"], "destination": "192.0.2.50", "port": 20000}
    ]
    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(data))
    rule = parse_rule(compile_policy(load_policy(source))["D1"])
    event: dict[str, Any] = {
        "proto": "dnp3",
        "direction": "request",
        "func_name": "COLD_RESTART",
        "conn": {"orig_h": "192.0.2.10", "resp_h": "192.0.2.50", "resp_p": 20000},
    }
    assert not matching_indices(rule, [event])
    for field, changed in [("orig_h", "192.0.2.11"), ("resp_h", "192.0.2.51"), ("resp_p", 502)]:
        other = copy.deepcopy(event)
        other["conn"][field] = changed
        assert matching_indices(rule, [other]) == [0]


def test_rules_exported_and_cli_policy_hits_are_identical(tmp_path: Path, capsys: Any) -> None:
    import json

    from substation.cli import main
    from substation.detect import load_events
    from substation.emit import write_artifacts
    from substation.policy import compile_policy, load_policy
    from substation.scenarios import load_scenario

    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(policy_data()))
    path = write_artifacts(
        load_scenario(root / "scenarios/modbus/benign-baseline.yaml"), tmp_path
    ).jsonl
    rules = compile_policy(load_policy(source))
    expected = {
        (name, index)
        for name, rule in rules.items()
        for index in matching_indices(parse_rule(rule), load_events(path))
    }
    assert main(["detect", str(path), "--policy", str(source)]) == 0
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {(row["detection_id"], row["event_index"]) for row in output} == expected


def test_aliases_are_rejected_before_yaml_object_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import substation.policy as policy_module

    source = tmp_path / "policy.yaml"
    # Small synthetic merge fixture; never construct an expanded alias graph.
    source.write_text(
        "first: &first {name: example}\nsecond: &second {<<: [*first, *first]}\n<<: *second\n"
    )

    def construction_must_not_run(_text: str) -> object:
        raise AssertionError("alias expansion reached the object constructor")

    monkeypatch.setattr(policy_module, "safe_load_strict", construction_must_not_run)
    with pytest.raises(SchemaValidationError, match="anchors or aliases"):
        policy_module.load_policy(source)
