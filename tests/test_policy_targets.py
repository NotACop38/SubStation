"""Source permissions apply only to the intended asset/service in sample policies."""

from __future__ import annotations

from typing import Any

import pytest
from substation.detect.registry import load_registry
from substation.detect.sigma_eval import load_rule, matching_indices


@pytest.mark.parametrize(
    ("det_id", "proto", "function", "source", "target", "port"),
    [
        ("D1", "dnp3", "COLD_RESTART", "10.0.1.10", "10.0.1.50", 20000),
        ("D2", "dnp3", "DISABLE_UNSOLICITED", "10.0.1.10", "10.0.1.50", 20000),
        ("D3", "dnp3", "OPERATE", "10.0.1.10", "10.0.1.50", 20000),
        ("S1", "s7comm", "PLC Stop", "10.0.4.10", "10.0.4.50", 102),
        ("S2", "s7comm", "Request Download", "10.0.4.10", "10.0.4.50", 102),
    ],
)
def test_allowed_source_is_not_trusted_on_other_targets(
    det_id: str, proto: str, function: str, source: str, target: str, port: int
) -> None:
    det = next(d for d in load_registry() if d.id == det_id)
    events: list[dict[str, Any]] = [
        {
            "proto": proto,
            "direction": "request",
            "func_name": function,
            "conn": {"orig_h": src, "resp_h": dst, "resp_p": service},
        }
        for src, dst, service in [
            (source, target, port),
            (source, "192.0.2.50", port),
            (source, target, port + 1),
            ("192.0.2.10", target, port),
        ]
    ]
    assert matching_indices(load_rule(det.rule_path), events) == [1, 2, 3]


def test_s1_distinguishes_cpu_start_from_other_plc_control_services() -> None:
    det = next(d for d in load_registry() if d.id == "S1")
    events = [
        {
            "proto": "s7comm",
            "direction": "request",
            "func_name": "PLC Control",
            "conn": {"orig_h": "192.0.2.10", "resp_h": "10.0.4.50", "resp_p": 102},
            "detail": {"subfunction_code": service},
        }
        for service in ("P_PROGRAM", "_GARB", "_INSE")
    ]
    assert matching_indices(load_rule(det.rule_path), events) == [0]
