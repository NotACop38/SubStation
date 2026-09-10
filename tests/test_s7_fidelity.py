"""S7 regression checks against independent decoder observations."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from scripts.verify import run as verify
from scripts.verify.s7 import LOGS, compare_s7_events
from substation.emit import s7comm_pcap, write_artifacts
from substation.emit.s7comm_pcap import _s7comm_pdu
from substation.protocols.s7comm import S7Error, build_events, event_to_dict
from substation.scenarios import Exchange, Scenario, load_scenario

ROOT = Path(__file__).resolve().parents[1]


def scenario(function: str, **params: object) -> Scenario:
    return replace(
        load_scenario(ROOT / "tests/data/fidelity/s7/operations.yaml"),
        exchanges=(Exchange("ews", "plc", function, params=params),),
    )


@pytest.mark.parametrize("number", ["1", "1234", "123456", "1" * 251])
def test_block_filename_requires_five_ascii_digits(number: str) -> None:
    with pytest.raises(S7Error, match="block_number"):
        build_events(scenario("RequestDownload", block_number=number))


@pytest.mark.parametrize("function", ["SetupCommunication", "ReadSZL", "RequestDownload"])
def test_success_response_fields_are_present(function: str) -> None:
    response = build_events(scenario(function))[-1]
    assert response.detail["error_class"] == "No error"
    assert response.detail["error_code"] == "0x00"


def test_download_status_and_session_belong_to_the_request() -> None:
    request, response = build_events(scenario("RequestDownload"))[-2:]
    assert request.detail["upload_download"]["function_status"] == "0x00"
    assert request.detail["upload_download"]["session_id"] == 256
    assert "function_status" not in response.detail["upload_download"]


def test_read_szl_request_carries_the_encoded_return_code() -> None:
    request = build_events(scenario("ReadSZL"))[-2]
    assert request.detail["read_szl"]["return_code"] == "0xff"


@pytest.mark.parametrize("reference", [1, 255, 256, 65535])
def test_wire_reference_stays_big_endian(reference: int) -> None:
    request = build_events(scenario("SetupCommunication"))[-2]
    frame = _s7comm_pdu(replace(request, pdu_reference=reference))
    # TPKT(4) + COTP(3) + protocol/ROSCTR/redundancy(4).
    assert frame[11:13] == reference.to_bytes(2, "big")


def test_comparator_rejects_missing_duplicate_reordered_and_changed_rows() -> None:
    events = [event_to_dict(e) for e in build_events(scenario("SetupCommunication"))]
    identity = {
        "id.orig_h": "192.0.2.10",
        "id.orig_p": "49152",
        "id.resp_h": "192.0.2.50",
        "id.resp_p": "102",
    }
    request = {
        **identity,
        "is_orig": "T",
        "source_h": "192.0.2.10",
        "source_p": "49152",
        "destination_h": "192.0.2.50",
        "destination_p": "102",
    }
    response = {
        **identity,
        "is_orig": "F",
        "source_h": "192.0.2.50",
        "source_p": "102",
        "destination_h": "192.0.2.10",
        "destination_p": "49152",
    }
    application = {
        "pdu_reference": "256",
        "function_code": "0xf0",
        "function_name": "Setup Communication",
    }
    rows = {
        "cotp.log": [
            {**request, "pdu_code": "0x0e", "pdu_name": "CR Connection Request"},
            {**response, "pdu_code": "0x0d", "pdu_name": "CC Connection Confirm"},
            {**request, "pdu_code": "0x0f", "pdu_name": "DT Data"},
            {**response, "pdu_code": "0x0f", "pdu_name": "DT Data"},
        ],
        "s7comm.log": [
            {**request, **application, "rosctr_code": "1", "rosctr_name": "Job-Request"},
            {
                **response,
                **application,
                "rosctr_code": "3",
                "rosctr_name": "ACK-Data",
                "error_class": "No error",
                "error_code": "0x00",
            },
        ],
    }
    assert compare_s7_events(events, rows) == []
    for replacement in (
        [],
        rows["s7comm.log"][1:],
        rows["s7comm.log"] * 2,
        rows["s7comm.log"][::-1],
    ):
        assert compare_s7_events(events, {**rows, "s7comm.log": replacement})
    for field, value in (
        ("pdu_reference", "1"),
        ("is_orig", "F"),
        ("id.resp_p", "103"),
        ("error_code", "0x01"),
    ):
        changed = copy.deepcopy(rows)
        changed["s7comm.log"][0][field] = value
        assert compare_s7_events(events, changed), field


@pytest.mark.parametrize("case", ["operations", "identifiers"])
def test_real_s7_fields_and_reference_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    if shutil.which("zeek") is None:
        pytest.skip("native Zeek is unavailable; make verify runs required S7 checks")
    monkeypatch.setattr(verify, "_NATIVE_ZEEK", shutil.which("zeek"))
    if not verify._s7_plugin_probe("unused")[0]:
        pytest.skip("native S7 plugin is unavailable; make verify --require-complete requires it")
    fixture = load_scenario(ROOT / "tests/data/fidelity/s7/operations.yaml")
    if case == "identifiers":
        # Every SZL name/default plus reference rollover from 255 to 256.
        fixture = replace(
            fixture,
            exchanges=tuple(
                Exchange("ews", "plc", "ReadSZL", params={"szl_id": 0xFF00 | i, "szl_index": i})
                for i in range(256)
            ),
        )
    artifacts = write_artifacts(fixture, tmp_path)
    events = [json.loads(line) for line in artifacts.jsonl.read_text().splitlines()]
    logs = verify.run_zeek(artifacts.pcap, ["icsnpp/s7comm"], [])
    try:
        rows = {name: verify.read_zeek_log(logs, name) for name in LOGS}
        assert compare_s7_events(events, rows) == []
        assert verify.read_zeek_log(logs, "weird.log") == []
        # Every decoded field is significant, including optional response details.
        for name, observations in rows.items():
            for row_index, row in enumerate(observations):
                if row_index > 1 and case == "identifiers":
                    break
                for field in row:
                    if field in ("ts", "uid"):
                        continue
                    changed = copy.deepcopy(rows)
                    changed[name][row_index][field] = "corrupted"
                    assert compare_s7_events(events, changed), (name, field)
    finally:
        shutil.rmtree(logs)


@pytest.mark.parametrize(
    "length, expected",
    [
        (b"0", "0"),
        (b"0" * 40, "0"),
        (b"65534", "65534"),
        (b"2147483647", "2147483647"),
        (b"2147483648", None),
        (b"", None),
        (b"1x", None),
    ],
)
def test_patched_parser_bounds_decimal_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: bytes, expected: str | None
) -> None:
    if shutil.which("zeek") is None:
        pytest.skip("native Zeek is unavailable")
    monkeypatch.setattr(verify, "_NATIVE_ZEEK", shutil.which("zeek"))
    if not verify._s7_plugin_probe("unused")[0]:
        pytest.skip("requires the reviewed S7 bounds patch; never probe unpatched numeric buffers")
    original = s7comm_pcap._job_param_data

    def param_data(event: Any) -> tuple[bytes, bytes]:
        param, data = original(event)
        if event.s7_function == 0x1D and not event.is_orig:
            # Synthetic length-delimited decimal text, in a files-only capture.
            return param[:8] + bytes([len(length)]) + length, data
        return param, data

    monkeypatch.setattr(s7comm_pcap, "_job_param_data", param_data)
    artifacts = write_artifacts(scenario("StartUpload"), tmp_path)
    logs = verify.run_zeek(artifacts.pcap, ["icsnpp/s7comm"], [])
    try:
        rows = verify.read_zeek_log(logs, "s7comm_upload_download.log")
        responses = [row for row in rows if row["is_orig"] == "F"]
        diagnostics = verify.read_zeek_log(logs, "weird.log")
        if expected is None:
            assert responses == []
            assert any(row["name"] == "s7comm_invalid_upload_blocklength" for row in diagnostics)
        else:
            assert [row["blocklength"] for row in responses] == [expected]
            assert diagnostics == []
    finally:
        shutil.rmtree(logs)
