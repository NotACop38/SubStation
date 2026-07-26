"""X1 normalized function tokens — parity with the Zeek CrossProtoBaseline script.

The Tier-2 runner injects X1's learned baseline via ``redef``. Tokens MUST match
``detections/zeek/x1_cross_protocol_baseline.zeek`` ``norm_func`` /
``norm_s7comm_header_func`` / SZL / S7comm-plus forms, or quiet/fire checks
silently disagree with the real engine. This module is the Python mirror used
to derive the baseline from emitted JSON (and unit-tested for parity).
"""

from __future__ import annotations

from typing import Any

__all__ = ["x1_norm_func"]


def _parse_hexish(value: object, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        if text.startswith(("0x", "0X")):
            return int(text, 16)
        if text.isdigit() or (text[0] == "-" and text[1:].isdigit()):
            return int(text)
        return default
    return default


def x1_norm_func(event: dict[str, Any]) -> str | None:
    """Return the X1 ``(proto:func)`` token for a *request* event, or ``None``.

    Returns ``None`` for responses and for frames X1 does not observe (e.g. bare
    COTP CR/CC with no S7comm header). Matches Zeek event filters in
    ``x1_cross_protocol_baseline.zeek``.
    """
    if not event.get("is_orig"):
        return None
    proto = event.get("proto")
    if proto == "modbus":
        return f"modbus:{event['func_code']}"
    if proto == "dnp3":
        return f"dnp3:{event['func_code']}"
    if proto == "s7comm":
        return _norm_s7comm(event)
    return None


def _norm_s7comm(event: dict[str, Any]) -> str | None:
    detail = event.get("detail")
    if not isinstance(detail, dict):
        return None

    # S7comm-plus path (Zeek s7comm_plus_header).
    plus = detail.get("plus")
    if isinstance(plus, dict) and "opcode" in plus:
        opcode = _parse_hexish(plus.get("opcode"))
        function = _parse_hexish(plus.get("function_code") or plus.get("function"))
        return f"s7comm-plus:opcode=0x{opcode:02x},function=0x{function:04x}"

    # COTP-only frames have no rosctr — X1 does not observe them.
    if "rosctr_code" not in detail:
        return None

    rosctr = _parse_hexish(detail.get("rosctr_code"))
    function = _parse_hexish(detail.get("function_code"))

    # Read SZL: Zeek's s7comm_header handler skips these; s7comm_read_szl emits
    # s7comm:szl=0x%x (same precedence as the Zeek script).
    sub_raw = detail.get("subfunction_code")
    subfunction = 0
    plc_control = ""
    if isinstance(sub_raw, str) and not sub_raw.startswith(("0x", "0X")) and not sub_raw.isdigit():
        plc_control = sub_raw
    else:
        subfunction = _parse_hexish(sub_raw)

    if rosctr == 0x07 and function == 0x44 and subfunction == 0x01:
        read_szl = detail.get("read_szl")
        if isinstance(read_szl, dict):
            szl_id = _parse_hexish(read_szl.get("szl_id"))
            return f"s7comm:szl=0x{szl_id:x}"
        return "s7comm:szl=0x0"

    # General s7comm_header path.
    func = f"rosctr=0x{rosctr:02x},function=0x{function:02x}"
    if subfunction != 0:
        func = f"{func},subfunction=0x{subfunction:02x}"
    if plc_control:
        func = f"{func},plc_control={plc_control}"
    return f"s7comm:{func}"
