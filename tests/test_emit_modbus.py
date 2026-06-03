"""Phase-1 Modbus emission tests: one model -> matching PCAP + schema-valid JSON.

These prove the LOCKED dual-emit guarantee (PRD §6.1): the PCAP and JSON are built
from the same shared event list, so they cannot drift. We assert the JSON validates
against the frozen schema, the PCAP carries exactly one Modbus segment per JSON
event with matching transaction/unit/function, and the whole thing is byte-stable.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import TCP
from scapy.utils import rdpcap
from substation.emit import EmitError, write_artifacts
from substation.protocols.modbus import ModbusError
from substation.scenarios import load_scenario
from substation.schema import iter_jsonl_errors

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"

_MBAP = struct.Struct(">HHHBB")  # transId, protoId, length, unitId, funcCode


def _modbus_segments(pcap_path: Path) -> list[tuple[int, int, int]]:
    """Return (tid, unit, func_code) for every Modbus-bearing packet, in file order."""
    segments: list[tuple[int, int, int]] = []
    for packet in rdpcap(str(pcap_path)):
        if not packet.haslayer(TCP):
            continue
        payload = bytes(packet[TCP].payload)
        if len(payload) < _MBAP.size:
            continue
        tid, proto, _length, unit, func = _MBAP.unpack(payload[: _MBAP.size])
        if proto == 0:  # Modbus protocol identifier
            segments.append((tid, unit, func))
    return segments


def _json_events(jsonl_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]


def _write_scenario(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scenario.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_benign_scenario_emits_schema_valid_jsonl(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)

    assert result.event_count == 6  # 3 exchanges -> request + response each
    assert result.pcap.exists() and result.pcap.stat().st_size > 24  # > header-only
    events = _json_events(result.jsonl)
    assert len(events) == result.event_count
    assert list(iter_jsonl_errors(result.jsonl)) == []  # the frozen schema gate


def test_pcap_and_jsonl_do_not_drift(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)

    events = _json_events(result.jsonl)
    segments = _modbus_segments(result.pcap)

    # Exactly one Modbus segment per JSON event, with identical key fields and order.
    assert len(segments) == len(events)
    json_keys = [(int(e["func_code"]), e["detail"]["tid"], e["detail"]["unit"]) for e in events]
    pcap_keys = [(func, tid, unit) for (tid, unit, func) in segments]
    assert pcap_keys == json_keys


def test_request_response_pairing_and_action_class(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)

    # Events come in matched request/response pairs sharing tid + uid.
    for request, response in zip(events[0::2], events[1::2], strict=True):
        assert request["is_orig"] is True and request["direction"] == "request"
        assert response["is_orig"] is False and response["direction"] == "response"
        assert request["uid"] == response["uid"]
        assert request["detail"]["tid"] == response["detail"]["tid"]
        assert response["detail"]["matched"] is True

    # The legitimate setpoint write is classified as a write with its value echoed.
    write = next(e for e in events if e["func_name"] == "WRITE_SINGLE_REGISTER")
    assert write["action_class"] == "write"
    assert write["detail"]["request_values"] == [1500]


def test_emission_is_byte_deterministic(tmp_path: Path) -> None:
    scenario = load_scenario(_EXAMPLE)
    first = write_artifacts(scenario, tmp_path / "a")
    second = write_artifacts(scenario, tmp_path / "b")
    assert first.pcap.read_bytes() == second.pcap.read_bytes()
    assert first.jsonl.read_text() == second.jsonl.read_text()


_MULTI_FUNCTION_SCENARIO = """
name: multi-fn
protocol: modbus
label: benign
actors:
  - {id: hmi, role: hmi, host: 10.0.0.10}
  - {id: plc, role: plc, host: 10.0.0.50, port: 502}
exchanges:
  - source: hmi
    target: plc
    function: ReadCoils
    params: {address: 0, quantity: 9}
  - source: hmi
    target: plc
    function: WriteMultipleRegisters
    params: {address: 10, values: [11, 22, 33]}
  - source: hmi
    target: plc
    function: WriteSingleCoil
    params: {address: 4, value: 1}
"""

_UNSUPPORTED_FN_SCENARIO = """
name: bad-fn
protocol: modbus
label: benign
actors:
  - {id: hmi, role: hmi, host: 10.0.0.10}
  - {id: plc, role: plc, host: 10.0.0.50, port: 502}
exchanges:
  - source: hmi
    target: plc
    function: Teleport
    params: {address: 0, quantity: 1}
"""

_MISSING_PARAM_SCENARIO = """
name: missing-param
protocol: modbus
label: benign
actors:
  - {id: hmi, role: hmi, host: 10.0.0.10}
  - {id: plc, role: plc, host: 10.0.0.50, port: 502}
exchanges:
  - source: hmi
    target: plc
    function: ReadHoldingRegisters
    params: {address: 0}
"""

_DNP3_SCENARIO = """
name: dnp3-stub
protocol: dnp3
label: benign
actors:
  - {id: master, role: master, host: 10.0.0.10}
exchanges: []
"""


def test_other_function_codes_emit_and_validate(tmp_path: Path) -> None:
    # Exercises the read-bit, multi-register-write and single-coil encoders beyond
    # the bundled example so the whole core function set round-trips and validates.
    scenario = load_scenario(_write_scenario(tmp_path, _MULTI_FUNCTION_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    assert result.event_count == 6
    assert list(iter_jsonl_errors(result.jsonl)) == []
    assert len(_modbus_segments(result.pcap)) == 6


def test_unsupported_function_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _UNSUPPORTED_FN_SCENARIO))
    with pytest.raises(ModbusError, match="unsupported Modbus function"):
        write_artifacts(scenario, tmp_path)


def test_missing_required_param_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _MISSING_PARAM_SCENARIO))
    with pytest.raises(ModbusError, match="missing required param 'quantity'"):
        write_artifacts(scenario, tmp_path)


def test_non_modbus_protocol_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _DNP3_SCENARIO))
    with pytest.raises(EmitError, match="Modbus only"):
        write_artifacts(scenario, tmp_path)
