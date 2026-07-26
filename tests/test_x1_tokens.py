"""Lock X1 baseline token parity with detections/zeek/x1_cross_protocol_baseline.zeek."""

from __future__ import annotations

from pathlib import Path

from substation.detect.x1_tokens import x1_norm_func
from substation.protocols.dnp3 import build_events as build_dnp3
from substation.protocols.dnp3 import event_to_dict as dnp3_to_dict
from substation.protocols.modbus import build_events as build_modbus
from substation.protocols.modbus import event_to_dict as modbus_to_dict
from substation.protocols.s7comm import build_events as build_s7
from substation.protocols.s7comm import event_to_dict as s7_to_dict
from substation.scenarios import load_scenario

_REPO = Path(__file__).resolve().parent.parent


def test_x1_modbus_and_dnp3_tokens_are_proto_code() -> None:
    modbus = load_scenario(_REPO / "scenarios" / "modbus" / "benign-baseline.yaml")
    tokens = {
        x1_norm_func(modbus_to_dict(e))
        for e in build_modbus(modbus)
        if x1_norm_func(modbus_to_dict(e)) is not None
    }
    assert "modbus:3" in tokens  # READ_HOLDING_REGISTERS
    assert all(t is not None and t.startswith("modbus:") for t in tokens)

    dnp3 = load_scenario(_REPO / "scenarios" / "dnp3" / "benign-baseline.yaml")
    d_tokens = {
        x1_norm_func(dnp3_to_dict(e))
        for e in build_dnp3(dnp3)
        if x1_norm_func(dnp3_to_dict(e)) is not None
    }
    assert "dnp3:1" in d_tokens  # READ
    assert "dnp3:4" in d_tokens  # OPERATE


def test_x1_s7_tokens_match_zeek_normalizers() -> None:
    s7 = load_scenario(_REPO / "scenarios" / "s7" / "benign-baseline.yaml")
    tokens = [
        x1_norm_func(s7_to_dict(e)) for e in build_s7(s7) if x1_norm_func(s7_to_dict(e)) is not None
    ]
    assert "s7comm:szl=0x11" in tokens  # Read SZL 0x0011 → Zeek %x form
    assert "s7comm:rosctr=0x01,function=0x04" in tokens  # Read Variable
    assert "s7comm:rosctr=0x01,function=0x28,plc_control=P_PROGRAM" in tokens
    # COTP-only frames must not produce tokens (Zeek never observes them as s7comm).
    assert all(t is not None and t.startswith("s7comm") for t in tokens)
