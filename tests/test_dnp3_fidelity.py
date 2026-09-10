"""Independent decoder and boundary regressions for the DNP3 fixture model."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from scripts.verify import run as verify
from scripts.verify.dnp3 import compare_dnp3_events
from substation.emit import write_artifacts
from substation.emit.dnp3_pcap import _app_bytes
from substation.protocols.dnp3 import Dnp3Error, build_events, event_to_dict
from substation.scenarios import Exchange, Scenario, load_scenario

ROOT = Path(__file__).resolve().parents[1]


def scenario(*exchanges: Exchange) -> Scenario:
    baseline = load_scenario(ROOT / "scenarios/dnp3/benign-baseline.yaml")
    return replace(baseline, exchanges=exchanges) if exchanges else baseline


def request(function: str, **params: Any) -> Exchange:
    return Exchange("master-1", "rtu-1", function, params=params)


def test_control_operation_names_match_icsnpp() -> None:
    for token, label in (("PULSE_ON", "Pulse On"), ("Latch Off", "Latch Off")):
        events = build_events(scenario(request("Operate", operation_type=token)))
        assert event_to_dict(events[0])["detail"]["control"]["operation_type"] == label


def test_earlier_event_operation_spelling_keeps_its_wire_meaning() -> None:
    event = build_events(scenario(request("Operate", operation_type="Latch_On")))[0]
    assert event.control is not None
    earlier = replace(event, control={**event.control, "operation_type": "Latch_On"})
    assert _app_bytes(earlier) == _app_bytes(event)


@pytest.mark.parametrize("function", ["Confirm", "DirectOperateNR", "ImmedFreezeNR"])
def test_no_response_functions_do_not_synthesize_replies(function: str) -> None:
    events = build_events(scenario(request(function)))
    assert len(events) == 1 and events[0].is_orig
    with pytest.raises(Dnp3Error, match="iin"):
        build_events(scenario(request(function, iin=1)))


@pytest.mark.parametrize(
    "function", ["Write", "EnableUnsolicited", "DisableUnsolicited", "AssignClass"]
)
def test_request_only_objects_reject_ignored_response_ranges(function: str) -> None:
    with pytest.raises(Dnp3Error, match="range_low"):
        build_events(scenario(request(function, range_low=123)))


@pytest.mark.parametrize("value, wire", [(0x0102, b"\x01\x02"), (0x8001, b"\x80\x01")])
def test_iin_octets_preserve_zeek_numeric_representation(value: int, wire: bytes) -> None:
    response = build_events(scenario(request("ColdRestart", iin=value)))[1]
    assert _app_bytes(response)[2:4] == wire


@pytest.mark.parametrize(
    "object_type, points, payload_bytes",
    [
        ("Binary Output", 1, 1),
        ("Binary Output", 8, 1),
        ("Binary Output", 9, 2),
        ("Binary Output", 17, 3),
        ("Binary Input With Status", 17, 17),
        ("16-Bit Binary Counter", 17, 51),
        ("16-Bit Analog Input", 17, 51),
        ("32-Bit Analog Input", 17, 85),
        ("16-Bit Analog Output Block", 17, 51),
        ("32-Bit Analog Output Block", 17, 85),
    ],
)
def test_point_payload_includes_packed_bits_and_status(
    object_type: str, points: int, payload_bytes: int
) -> None:
    response = build_events(
        scenario(request("Read", object_type=object_type, range_high=points - 1))
    )[1]
    # Application header (4), group/variation/qualifier + 16-bit start/stop (7).
    assert len(_app_bytes(response)) == 11 + payload_bytes


@pytest.mark.parametrize(
    "object_type, max_points", [("Binary Output", 1904), ("32-Bit Analog Output Block", 47)]
)
def test_single_frame_limit_counts_actual_payload_bytes(object_type: str, max_points: int) -> None:
    fixture = scenario(request("Read", object_type=object_type, range_high=max_points - 1))
    assert len(_app_bytes(build_events(fixture)[1])) <= 249  # plus transport octet
    with pytest.raises(Dnp3Error, match="single-frame"):
        build_events(scenario(request("Read", object_type=object_type, range_high=max_points)))


def test_comparison_rejects_lost_duplicate_reordered_or_changed_rows() -> None:
    # Hand-authored decoded observations, independent of the expectation builder.
    events = [event_to_dict(e) for e in build_events(scenario(request("ColdRestart")))]
    identity = {
        "id.orig_h": "10.0.1.10",
        "id.orig_p": "49152",
        "id.resp_h": "10.0.1.50",
        "id.resp_p": "20000",
    }
    rows = [
        {
            **identity,
            "message": "1",
            "kind": "header",
            "is_orig": "T",
            "func_code": "13",
            "func_name": "COLD_RESTART",
            "iin": "-",
        },
        {
            **identity,
            "message": "2",
            "kind": "header",
            "is_orig": "F",
            "func_code": "129",
            "func_name": "RESPONSE",
            "iin": "0",
        },
    ]
    assert compare_dnp3_events(events, rows) == []
    assert compare_dnp3_events(events, rows[1:])
    assert compare_dnp3_events(events, rows + rows[:1])
    for field, value in (
        ("message", "1"),
        ("is_orig", "T"),
        ("iin", "256"),
        ("id.resp_p", "20001"),
    ):
        changed = copy.deepcopy(rows)
        changed[1][field] = value
        assert compare_dnp3_events(events, changed), field


@pytest.mark.skipif(shutil.which("zeek") is None, reason="local Zeek is unavailable")
@pytest.mark.parametrize("case", ["baseline", "boundaries", "no-responses"])
def test_real_dnp3_parser_matches_every_message_and_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    scripts = ROOT / ".verify-cache/icsnpp-dnp3/scripts"
    if not scripts.is_dir():
        pytest.skip("ICSNPP cache is absent; make verify obtains the pinned parser")
    fixture = scenario()
    if case != "baseline":
        fixture = load_scenario(ROOT / f"tests/data/fidelity/dnp3/{case}.yaml")
    artifacts = write_artifacts(fixture, tmp_path)
    events = [json.loads(line) for line in artifacts.jsonl.read_text().splitlines()]
    monkeypatch.setattr(verify, "_NATIVE_ZEEK", shutil.which("zeek"))
    logs = verify.run_zeek(
        artifacts.pcap, [str(scripts), str(ROOT / "scripts/verify/dnp3-observe.zeek")], []
    )
    try:
        rows = verify.read_zeek_log(logs, "substation_dnp3.log")
        assert compare_dnp3_events(events, rows) == []
        assert verify.read_zeek_log(logs, "weird.log") == []
        # Prove the oracle notices detail corruption and association drift.
        for field in (
            "operation_type",
            "index_number",
            "on_time",
            "object_count",
            "range_low",
            "object_type",
        ):
            changed = copy.deepcopy(rows)
            row = next((row for row in changed if row.get(field, "-") != "-"), None)
            if row is None:
                continue
            row[field] = "changed"
            assert compare_dnp3_events(events, changed), field
        control = next(row for row in rows if row["kind"] == "control")
        control["message"] = "999"
        assert compare_dnp3_events(events, rows)
    finally:
        shutil.rmtree(logs)
