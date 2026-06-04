"""Phase-4 S7 emission tests: one model -> matching PCAP + schema-valid JSON.

These prove the LOCKED dual-emit guarantee (PRD §6.1) holds for S7 the same way it
does for Modbus/DNP3: the PCAP and JSON are built from the same shared event list, so
they cannot drift. We assert the JSON validates against the frozen schema, the
hand-built TPKT/COTP/S7comm PCAP carries exactly one S7 PDU per JSON event with
matching function semantics in the same order, the TPKT lengths are correct, and the
whole thing is byte-stable. scapy ships no S7 layer (spike 07), so framing is checked
by hand against the verified wire layout.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import TCP
from scapy.utils import rdpcap
from substation.emit import write_artifacts
from substation.protocols.s7comm import S7Error
from substation.scenarios import load_scenario
from substation.schema import iter_jsonl_errors

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BASELINE = _REPO_ROOT / "scenarios" / "s7" / "benign-baseline.yaml"


def _write_scenario(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scenario.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _json_events(jsonl_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]


def _s7_payloads(pcap_path: Path) -> list[bytes]:
    """Return the TPKT payload bytes of every S7-bearing data packet, in file order."""
    payloads: list[bytes] = []
    for packet in rdpcap(str(pcap_path)):
        if not packet.haslayer(TCP):
            continue
        payload = bytes(packet[TCP].payload)
        # Every S7 message is a TPKT unit: version 0x03, reserved 0x00.
        if payload[:2] == b"\x03\x00":
            payloads.append(payload)
    return payloads


def _classify(payload: bytes) -> str:
    """Coarse classification of a TPKT payload: cotp | s7comm | s7comm_plus."""
    # TPKT(4) then COTP. A DT data PDU is 02 f0 80; a CR/CC is LI Ex/Dx.
    if payload[4:7] == b"\x02\xf0\x80":
        proto = payload[7]
        return "s7comm" if proto == 0x32 else "s7comm_plus" if proto == 0x72 else "?"
    return "cotp"


def test_baseline_emits_schema_valid_jsonl(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    assert result.event_count > 0
    assert result.pcap.exists() and result.pcap.stat().st_size > 24  # > header-only
    events = _json_events(result.jsonl)
    assert len(events) == result.event_count
    assert all(e["proto"] == "s7comm" for e in events)
    assert list(iter_jsonl_errors(result.jsonl)) == []  # the frozen schema gate


def test_pcap_and_jsonl_do_not_drift(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    payloads = _s7_payloads(result.pcap)
    # Exactly one TPKT/S7 PDU per JSON event, same protocol kind, same order.
    assert len(payloads) == len(events)
    kinds = [_classify(p) for p in payloads]
    expected = [
        "cotp" if "cotp" in e["detail"] else "s7comm_plus" if "plus" in e["detail"] else "s7comm"
        for e in events
    ]
    assert kinds == expected


def test_pcap_tpkt_lengths_are_valid(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    for payload in _s7_payloads(result.pcap):
        tpkt_len = int.from_bytes(payload[2:4], "big")
        assert tpkt_len == len(payload)  # TPKT length covers the whole unit (spike 07)


def test_cotp_handshake_brackets_each_connection(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    # Each S7 connection opens with a COTP CR (request) then CC (response).
    cotp = [e for e in events if "cotp" in e["detail"]]
    crs = [e for e in cotp if e["func_name"] == "CR Connection Request"]
    ccs = [e for e in cotp if e["func_name"] == "CC Connection Confirm"]
    # The baseline has two connections (EWS + HMI), so two CR/CC pairs.
    assert len(crs) == 2 and len(ccs) == 2
    for cr in crs:
        assert cr["is_orig"] is True and cr["detail"]["cotp"]["pdu_code"] == "0x0e"
    for cc in ccs:
        assert cc["is_orig"] is False and cc["detail"]["cotp"]["pdu_code"] == "0x0d"


def test_read_szl_request_param_matches_capture(tmp_path: Path) -> None:
    # The Read-SZL request parameter is verified byte-for-byte against snap7.pcap
    # (spike 07): 00 01 12 04 11 | FUNC(0x44) | SUBFUNC(0x01) | 00.
    scenario = load_scenario(_write_scenario(tmp_path, _READ_SZL_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    payloads = _s7_payloads(result.pcap)
    for event, payload in zip(events, payloads, strict=True):
        if event["func_name"] != "Request: CPU Functions" or not event["is_orig"]:
            continue
        s7 = payload[7:]  # after TPKT(4) + COTP DT(3)
        param = s7[10:18]  # 10-byte User-Data header, then the 8-byte parameter
        assert param == b"\x00\x01\x12\x04\x11\x44\x01\x00"
        assert event["detail"]["read_szl"]["szl_id_name"] == "Module identification"


def test_request_response_pairing_and_action_class(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _STOP_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    stops = [e for e in events if e["func_name"] == "PLC Stop"]
    # A PLC Stop request pairs with an ACK-Data response; both classify as control.
    assert len(stops) == 2
    req = next(e for e in stops if e["is_orig"])
    resp = next(e for e in stops if not e["is_orig"])
    assert req["action_class"] == "control" and req["detail"]["rosctr_name"] == "Job-Request"
    assert resp["action_class"] == "control" and resp["detail"]["rosctr_name"] == "ACK-Data"


def test_plus_object_is_marked_write(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _PLUS_SCENARIO))
    result = write_artifacts(scenario, tmp_path)
    events = _json_events(result.jsonl)
    create = next(e for e in events if e["func_name"] == "Create Object" and e["is_orig"])
    assert create["action_class"] == "write"
    assert create["detail"]["plus"]["opcode_name"] == "Request"
    assert create["detail"]["plus"]["function_name"] == "Create Object"


def test_emission_is_byte_deterministic(tmp_path: Path) -> None:
    scenario = load_scenario(_BASELINE)
    first = write_artifacts(scenario, tmp_path / "a")
    second = write_artifacts(scenario, tmp_path / "b")
    assert first.pcap.read_bytes() == second.pcap.read_bytes()
    assert first.jsonl.read_text() == second.jsonl.read_text()


def test_unsupported_function_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _BAD_FN_SCENARIO))
    with pytest.raises(S7Error, match="unsupported S7 function"):
        write_artifacts(scenario, tmp_path)


def test_request_from_plc_raises(tmp_path: Path) -> None:
    scenario = load_scenario(_write_scenario(tmp_path, _BACKWARDS_SCENARIO))
    with pytest.raises(S7Error, match="must originate from the client/master"):
        write_artifacts(scenario, tmp_path)


_READ_SZL_SCENARIO = """
name: s7-readszl
protocol: s7comm
label: benign
actors:
  - {id: ews, role: ews, host: 10.0.4.10}
  - {id: plc, role: plc, host: 10.0.4.50, port: 102}
exchanges:
  - {source: ews, target: plc, function: ReadSZL, params: {szl_id: 0x0011}}
"""

_STOP_SCENARIO = """
name: s7-stop
protocol: s7comm
label: anomalous
actors:
  - {id: ews, role: ews, host: 10.0.4.10}
  - {id: plc, role: plc, host: 10.0.4.50, port: 102}
exchanges:
  - {source: ews, target: plc, function: PlcStop}
"""

_PLUS_SCENARIO = """
name: s7-plus
protocol: s7comm
label: anomalous
actors:
  - {id: ews, role: ews, host: 10.0.4.10}
  - {id: plc, role: plc, host: 10.0.4.50, port: 102}
exchanges:
  - {source: ews, target: plc, function: CreateObject}
"""

_BAD_FN_SCENARIO = """
name: s7-bad-fn
protocol: s7comm
label: benign
actors:
  - {id: ews, role: ews, host: 10.0.4.10}
  - {id: plc, role: plc, host: 10.0.4.50, port: 102}
exchanges:
  - {source: ews, target: plc, function: Teleport}
"""

_BACKWARDS_SCENARIO = """
name: s7-backwards
protocol: s7comm
label: benign
actors:
  - {id: ews, role: ews, host: 10.0.4.10}
  - {id: plc, role: plc, host: 10.0.4.50, port: 102}
exchanges:
  - {source: plc, target: ews, function: ReadVariable}
"""
