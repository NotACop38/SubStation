"""Phase-3 DNP3 emission tests: one model -> matching PCAP + schema-valid JSON.

These prove the LOCKED dual-emit guarantee (PRD §6.1) holds for DNP3 the same way it
does for Modbus: the PCAP and JSON are built from the same shared event list, so they
cannot drift. We assert the JSON validates against the frozen schema, the hand-built
DNP3 PCAP carries exactly one DNP3 link frame per JSON event with matching function
codes in the same order, the CRCs are valid, and the whole thing is byte-stable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import TCP
from scapy.utils import rdpcap
from substation.emit import write_artifacts
from substation.protocols.dnp3 import Dnp3Error, dnp3_crc
from substation.scenarios import load_scenario
from substation.schema import iter_jsonl_errors

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BASELINE = _REPO_ROOT / "scenarios" / "dnp3" / "benign-baseline.yaml"


def _write_scenario(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scenario.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _json_events(jsonl_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]


def _dnp3_frames(pcap_path: Path) -> list[bytes]:
    """Return the DNP3 link-frame bytes of every DNP3-bearing packet, in file order."""
    frames: list[bytes] = []
    for packet in rdpcap(str(pcap_path)):
        if not packet.haslayer(TCP):
            continue
        payload = bytes(packet[TCP].payload)
        if payload[:2] == b"\x05\x64":
            frames.append(payload)
    return frames


def _frame_function_code(frame: bytes) -> int:
    """Extract the application function code from a single-block DNP3 frame."""
    # header(10) = 05 64 LEN CTRL DEST(2) SRC(2) CRC(2); then transport(1) + app.
    # app = app_control(1) + function_code(1) + ...; function code is body[2].
    body = frame[10:]
    return body[2]


def test_baseline_emits_schema_valid_jsonl(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    assert result.event_count > 0
    assert result.pcap.exists() and result.pcap.stat().st_size > 24  # > header-only
    events = _json_events(result.jsonl)
    assert len(events) == result.event_count
    assert all(e["proto"] == "dnp3" for e in events)
    assert list(iter_jsonl_errors(result.jsonl)) == []  # the frozen schema gate


def test_pcap_and_jsonl_do_not_drift(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    frames = _dnp3_frames(result.pcap)
    # Exactly one DNP3 link frame per JSON event, same function code, same order.
    assert len(frames) == len(events)
    assert [_frame_function_code(f) for f in frames] == [int(e["func_code"]) for e in events]


def test_pcap_link_crcs_are_valid(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    for frame in _dnp3_frames(result.pcap):
        header, crc = frame[:8], int.from_bytes(frame[8:10], "little")
        assert dnp3_crc(header) == crc  # verified algorithm (spike 05)


def test_emission_is_byte_deterministic(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    first = write_artifacts(scenario, tmp_path / "a")
    second = write_artifacts(scenario, tmp_path / "b")
    assert first.pcap.read_bytes() == second.pcap.read_bytes()
    assert first.jsonl.read_text() == second.jsonl.read_text()


def test_request_response_pairing_and_action_class(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _OPERATE_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    # An OPERATE request pairs with a RESPONSE; the response inherits the verb.
    req = next(e for e in events if e["func_name"] == "OPERATE")
    assert req["is_orig"] is True and req["action_class"] == "control"
    assert req["detail"]["control"]["operation_type"] == "Latch_On"
    resp = next(e for e in events if e["func_name"] == "RESPONSE")
    assert resp["is_orig"] is False and resp["action_class"] == "control"
    assert resp["detail"]["fc_reply"] == "RESPONSE"


def test_unsolicited_response_is_outstation_originated(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _UNSOL_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    # The unsolicited response is a single outstation-originated event (no request).
    unsol = [e for e in events if e["func_name"] == "UNSOLICITED_RESPONSE"]
    assert len(unsol) == 1
    assert unsol[0]["is_orig"] is False and unsol[0]["direction"] == "response"
    # On a master-initiated connection the originator is still the master.
    assert unsol[0]["conn"]["orig_h"] == "10.0.1.10"


def test_unsupported_function_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _BAD_FN_SCENARIO))
    with pytest.raises(Dnp3Error, match="unsupported DNP3 function"):
        write_artifacts(scenario, tmp_path)


def test_request_from_outstation_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _BACKWARDS_SCENARIO))
    with pytest.raises(Dnp3Error, match="must originate from the master"):
        write_artifacts(scenario, tmp_path)


_OPERATE_SCENARIO = """
name: dnp3-operate
protocol: dnp3
label: benign
actors:
  - {id: master, role: master, host: 10.0.1.10}
  - {id: rtu, role: outstation, host: 10.0.1.50, port: 20000}
exchanges:
  - source: master
    target: rtu
    function: Operate
    params: {index_number: 3, operation_type: Latch_On, trip_control_code: Close}
"""

_UNSOL_SCENARIO = """
name: dnp3-unsol
protocol: dnp3
label: benign
actors:
  - {id: master, role: master, host: 10.0.1.10}
  - {id: rtu, role: outstation, host: 10.0.1.50, port: 20000}
exchanges:
  - source: master
    target: rtu
    function: Read
    params: {object_type: Binary Input, range_low: 0, range_high: 1, object_count: 2}
  - source: rtu
    target: master
    function: UnsolicitedResponse
    params: {object_type: Binary Input, range_low: 0, range_high: 0, object_count: 1}
"""

_BAD_FN_SCENARIO = """
name: dnp3-bad-fn
protocol: dnp3
label: benign
actors:
  - {id: master, role: master, host: 10.0.1.10}
  - {id: rtu, role: outstation, host: 10.0.1.50, port: 20000}
exchanges:
  - {source: master, target: rtu, function: Teleport}
"""

_BACKWARDS_SCENARIO = """
name: dnp3-backwards
protocol: dnp3
label: benign
actors:
  - {id: master, role: master, host: 10.0.1.10}
  - {id: rtu, role: outstation, host: 10.0.1.50, port: 20000}
exchanges:
  - {source: rtu, target: master, function: Read}
"""
