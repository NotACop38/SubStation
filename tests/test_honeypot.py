"""Tests for the optional research honeypot (substation.honeypot).

These exercise the **pure** protocol core (process_frame) and configuration safety
without ever opening a socket: they prove (1) the honeypot's probe log conforms to
the frozen event-log schema, (2) the shipped Tier-1 detections fire on honeypot
telemetry, and (3) the loopback-only safety default is enforced.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Any

import pytest
from substation.detect.sigma_eval import load_rule, matching_indices
from substation.honeypot.modbus import (
    HoneypotConfig,
    HoneypotConfigError,
    StubDevice,
    process_frame,
)
from substation.schema import iter_event_errors

_REPO_ROOT = Path(__file__).resolve().parent.parent
_M1_RULE = _REPO_ROOT / "detections" / "sigma" / "modbus_m1_unauthorized_write.yml"
_M2_RULE = _REPO_ROOT / "detections" / "sigma" / "modbus_m2_illegal_function_code.yml"

_PROBER = "203.0.113.7"
_PROBER_PORT = 51000
_HP_HOST = "127.0.0.1"
_HP_PORT = 5020


def _mbap_frame(func_code: int, payload: bytes, *, tid: int = 1, unit: int = 1) -> bytes:
    """Assemble a Modbus/TCP request ADU."""
    pdu = bytes((func_code,)) + payload
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _run(raw: bytes, device: StubDevice | None = None) -> tuple[bytes | None, list[dict[str, Any]]]:
    return process_frame(
        raw,
        orig_h=_PROBER,
        orig_p=_PROBER_PORT,
        resp_h=_HP_HOST,
        resp_p=_HP_PORT,
        uid="CHoneypotTest00001",
        ts=1_717_000_000.0,
        device=device if device is not None else StubDevice(),
    )


def _assert_schema_valid(events: list[dict[str, Any]]) -> None:
    for event in events:
        assert list(iter_event_errors(event)) == [], event


def test_read_holding_registers_logs_schema_valid_pair() -> None:
    # READ_HOLDING_REGISTERS (0x03), address 100, quantity 4 — within stub range.
    reply, events = _run(_mbap_frame(0x03, struct.pack(">HH", 100, 4)))
    assert reply is not None
    assert len(events) == 2
    request, response = events
    assert request["direction"] == "request"
    assert request["func_name"] == "READ_HOLDING_REGISTERS"
    assert request["action_class"] == "read"
    assert response["direction"] == "response"
    assert response["detail"] == {
        "tid": 1,
        "unit": 1,
        "func": "READ_HOLDING_REGISTERS",
        "address": 100,
        "quantity": 4,
        "response_values": [100, 101, 102, 103],
        "matched": True,
    }
    _assert_schema_valid(events)
    # The wire reply echoes the function code with a byte count + 4 registers.
    assert reply[7] == 0x03
    assert reply[8] == 8  # byte count = 4 registers * 2


def test_read_out_of_range_yields_illegal_data_address() -> None:
    # Quantity that runs past the bounded stub address space -> exception reply.
    reply, events = _run(_mbap_frame(0x04, struct.pack(">HH", 2000, 10)))
    assert reply is not None
    request, response = events
    assert response["is_exception"] is True
    assert response["error"] == "ILLEGAL_DATA_ADDRESS"
    assert response["func_code"] == 0x04 | 0x80
    _assert_schema_valid(events)


def test_reserved_function_code_yields_illegal_function() -> None:
    # 0x42 is not an implemented function: request surfaces as action_class `other`,
    # the reply as an ILLEGAL_FUNCTION exception.
    reply, events = _run(_mbap_frame(0x42, b"\x00\x00"))
    assert reply is not None
    request, response = events
    assert request["action_class"] == "other"
    assert request["func_name"] == "UNKNOWN_FUNCTION_0x42"
    assert response["is_exception"] is True
    assert response["error"] == "ILLEGAL_FUNCTION"
    _assert_schema_valid(events)


def test_write_single_register_round_trips_and_persists() -> None:
    device = StubDevice()
    reply, events = _run(_mbap_frame(0x06, struct.pack(">HH", 40, 1500)), device)
    assert reply is not None
    request, response = events
    assert request["action_class"] == "write"
    assert request["detail"] == {
        "tid": 1,
        "unit": 1,
        "func": "WRITE_SINGLE_REGISTER",
        "address": 40,
        "quantity": 1,
        "request_values": [1500],
    }
    _assert_schema_valid(events)
    # The stub persists the write: a subsequent read returns it.
    _, read_events = _run(_mbap_frame(0x03, struct.pack(">HH", 40, 1), tid=2), device)
    assert read_events[1]["detail"]["response_values"] == [1500]


def test_non_modbus_frame_is_ignored() -> None:
    # Protocol id != 0 is not Modbus: nothing to send, nothing to log.
    reply, events = _run(struct.pack(">HHHB", 1, 99, 2, 1) + b"\x03")
    assert reply is None
    assert events == []


def test_honeypot_telemetry_fires_m2() -> None:
    rule = load_rule(_M2_RULE)
    # A reserved-code probe (request `other` + ILLEGAL_FUNCTION reply) both fire M2.
    _, events = _run(_mbap_frame(0x09, b"\x00\x00"))
    assert matching_indices(rule, events) == [0, 1]


def test_honeypot_telemetry_fires_m1_for_unlisted_writer() -> None:
    rule = load_rule(_M1_RULE)
    # A write from the (non-allow-listed) prober is unauthorized -> M1 fires on the
    # request event.
    _, events = _run(_mbap_frame(0x06, struct.pack(">HH", 40, 7)))
    assert matching_indices(rule, events) == [0]


def test_config_rejects_external_bind_without_optin() -> None:
    with pytest.raises(HoneypotConfigError, match="non-loopback"):
        HoneypotConfig(log_path=Path("x.jsonl"), bind_host="0.0.0.0").validate()  # noqa: S104


def test_config_allows_loopback_by_default() -> None:
    # Default bind is loopback and validates without the opt-in.
    HoneypotConfig(log_path=Path("x.jsonl")).validate()
    assert HoneypotConfig(log_path=Path("x.jsonl")).bind_host == "127.0.0.1"


def test_config_allows_external_with_optin() -> None:
    HoneypotConfig(log_path=Path("x.jsonl"), bind_host="10.99.0.5", allow_external=True).validate()


def test_oversized_read_quantity_is_rejected_not_crash() -> None:
    # 128 registers is in-range for the stub but exceeds the spec max (125) and
    # would overflow the response's 1-byte byte-count: must reply ILLEGAL_DATA_VALUE.
    reply, events = _run(_mbap_frame(0x03, struct.pack(">HH", 0, 128)))
    assert reply is not None
    _, response = events
    assert response["is_exception"] is True
    assert response["error"] == "ILLEGAL_DATA_VALUE"
    assert response["func_code"] == 0x03 | 0x80
    _assert_schema_valid(events)


def test_malformed_multi_write_byte_count_is_rejected_not_crash() -> None:
    # FC15 quantity 9 needs 2 data bytes but declares byte_count 1 — would IndexError.
    coils = _mbap_frame(0x0F, struct.pack(">HHB", 0, 9, 1) + b"\xff")
    reply, events = _run(coils)
    assert reply is not None
    assert events[1]["error"] == "ILLEGAL_DATA_VALUE"
    _assert_schema_valid(events)
    # FC16 quantity 1 with an odd byte_count 1 — would raise struct.error.
    regs = _mbap_frame(0x10, struct.pack(">HHB", 0, 1, 1) + b"\x00")
    reply2, events2 = _run(regs)
    assert reply2 is not None
    assert events2[1]["error"] == "ILLEGAL_DATA_VALUE"
    _assert_schema_valid(events2)


def test_illegal_single_coil_value_is_rejected_and_does_not_mutate() -> None:
    # FC05 permits only 0x0000/0xFF00; 0x0001 is ILLEGAL_DATA_VALUE and must not
    # change the coil (else a scanner silently corrupts the stub state).
    device = StubDevice()
    reply, events = _run(_mbap_frame(0x05, struct.pack(">HH", 10, 0x0001)), device)
    assert reply is not None
    request, response = events
    assert request["detail"]["request_values"] == [1]  # raw value logged, not coerced
    assert response["is_exception"] is True
    assert response["error"] == "ILLEGAL_DATA_VALUE"
    _assert_schema_valid(events)
    # The coil is untouched: a later read returns the deterministic default (10 & 1).
    _, read_events = _run(_mbap_frame(0x01, struct.pack(">HH", 10, 1), tid=2), device)
    assert read_events[1]["detail"]["response_values"] == [10 & 1]


def test_processing_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pure core must never construct a socket — it only parses bytes."""

    def no_sockets(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the honeypot core must not open a socket")

    monkeypatch.setattr(socket, "socket", no_sockets)
    reply, events = _run(_mbap_frame(0x03, struct.pack(">HH", 0, 2)))
    assert reply is not None
    _assert_schema_valid(events)
