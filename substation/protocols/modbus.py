"""Modbus semantics shared by the JSON and PCAP emitters (PRD §6.1, §6.4).

:func:`build_events` turns a loaded :class:`~substation.scenarios.Scenario` into
an ordered list of :class:`ModbusEvent` — the **single intermediate model both
emitters consume**, so the PCAP and JSON artifacts cannot drift (the LOCKED core
design principle, PRD §6.1: one scenario model drives both emitters).

This module is pure Python and protocol-semantic only: it carries *what each
Modbus message means*. The JSON emitter (:mod:`substation.emit.json_emitter`)
maps that to the ICSNPP-aligned envelope+detail (``docs/schema.md``); the PCAP
emitter (:mod:`substation.emit.pcap_emitter`) maps the same events to Modbus/TCP
wire bytes via scapy (spike 02). Keeping the semantic model here — and importing
no scapy — means JSON-only consumers never pull a packet library.

Function-code names are the frozen Zeek ``Modbus::function_codes`` spellings
recorded in ``docs/schema.md`` and ``docs/spikes/01-icsnpp-modbus-fields.md`` —
taken from the verified source, never invented from memory (CLAUDE.md VERIFY
gate). Numeric function codes are Modbus Application Protocol spec v1.1b3 (PRD §9).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from substation.scenarios import Actor, Protocol, Scenario

__all__ = [
    "ModbusError",
    "ModbusEvent",
    "build_events",
    "event_to_dict",
    "resolve_function",
    "FUNCTION_NAMES",
    "ACTION_CLASS",
    "DEFAULT_MODBUS_PORT",
    "RESPONSE_DELAY",
    "ILLEGAL_FUNCTION",
    "ILLEGAL_DATA_ADDRESS",
    "EXCEPTION_CODE_BYTES",
    "is_standard_function",
    "abnormal_function_name",
]

DEFAULT_MODBUS_PORT = 502
# Synthetic outstation turnaround between a request and its response (seconds).
RESPONSE_DELAY = 0.05
# IANA dynamic/ephemeral port range start; client ports are assigned from here.
_EPHEMERAL_BASE = 49152

# Modbus function codes (Modbus Application Protocol Specification v1.1b3, PRD §9).
READ_COILS = 0x01
READ_DISCRETE_INPUTS = 0x02
READ_HOLDING_REGISTERS = 0x03
READ_INPUT_REGISTERS = 0x04
WRITE_SINGLE_COIL = 0x05
WRITE_SINGLE_REGISTER = 0x06
WRITE_MULTIPLE_COILS = 0x0F
WRITE_MULTIPLE_REGISTERS = 0x10

# code -> Zeek ``Modbus::function_codes`` name (docs/schema.md; spike 01).
FUNCTION_NAMES: dict[int, str] = {
    READ_COILS: "READ_COILS",
    READ_DISCRETE_INPUTS: "READ_DISCRETE_INPUTS",
    READ_HOLDING_REGISTERS: "READ_HOLDING_REGISTERS",
    READ_INPUT_REGISTERS: "READ_INPUT_REGISTERS",
    WRITE_SINGLE_COIL: "WRITE_SINGLE_COIL",
    WRITE_SINGLE_REGISTER: "WRITE_SINGLE_REGISTER",
    WRITE_MULTIPLE_COILS: "WRITE_MULTIPLE_COILS",
    WRITE_MULTIPLE_REGISTERS: "WRITE_MULTIPLE_REGISTERS",
}

# code -> normalized action_class (docs/schema.md "action_class mapping (Modbus)").
ACTION_CLASS: dict[int, str] = {
    READ_COILS: "read",
    READ_DISCRETE_INPUTS: "read",
    READ_HOLDING_REGISTERS: "read",
    READ_INPUT_REGISTERS: "read",
    WRITE_SINGLE_COIL: "write",
    WRITE_SINGLE_REGISTER: "write",
    WRITE_MULTIPLE_COILS: "write",
    WRITE_MULTIPLE_REGISTERS: "write",
}

# The FULL set of function codes base Zeek's ``Modbus::function_codes`` table NAMES
# (verified against base/protocols/modbus/consts.zeek, 2026-06-04). A code in this
# table is a *defined* Modbus function; a code ABSENT from it is what Zeek renders
# ``unknown-N`` and is the only thing we treat as an abnormal/undefined M2 probe. We
# encode only the eight standard read/write codes above, so a code that is defined
# here but not in FUNCTION_NAMES (e.g. 0x09 PROGRAM_484, 0x08 DIAGNOSTICS) is a real
# legacy/diagnostic function we cannot faithfully emit — that raises, rather than
# being mis-encoded as an undefined probe.
_ZEEK_DEFINED_FUNCTION_CODES: frozenset[int] = frozenset(
    {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x28,
        0x29,
        0x2B,
        0x5A,
        0x5B,
        0x7D,
        0x7E,
        0x7F,
    }
)

# Quantity limits from the Modbus spec; reject impossible scenarios up front so an
# author sees a clear error instead of a malformed PDU.
_MAX_READ_REGISTERS = 125
_MAX_READ_BITS = 2000
_MAX_WRITE_REGISTERS = 123
_MAX_WRITE_BITS = 1968

_U16 = 0xFFFF

# A request may carry a reserved/undefined (non-standard) function code — the M2
# "illegal/abnormal function code" recon signal (PRD §5.1). Zeek's
# ``Modbus::function_codes`` table renders any code *absent* from it as
# ``unknown-<decimal>`` (verified against base/protocols/modbus/consts.zeek on
# 2026-06-04 — NB 0x09 is *not* undefined there, it is the legacy PROGRAM_484, so
# the emitter only treats codes genuinely absent from that table as abnormal). A
# spec-compliant outstation answers an unsupported function with an
# ILLEGAL_FUNCTION exception (Modbus Application Protocol spec v1.1b3, PRD §9).
_MAX_REQUEST_FUNCTION = 0x7F  # 0x80+ is the exception-response bit; never a request code.
EXCEPTION_FLAG = 0x80  # set on the function code in an exception response (code | 0x80).
ILLEGAL_FUNCTION = "ILLEGAL_FUNCTION"
ILLEGAL_DATA_ADDRESS = "ILLEGAL_DATA_ADDRESS"
# Exception name -> on-the-wire Modbus exception code byte (base Zeek
# ``Modbus::exception_codes``, verified 2026-06-04).
EXCEPTION_CODE_BYTES: dict[str, int] = {
    ILLEGAL_FUNCTION: 0x01,
    ILLEGAL_DATA_ADDRESS: 0x02,
}


class ModbusError(ValueError):
    """Raised when a scenario cannot be encoded as Modbus telemetry."""


@dataclass(frozen=True, slots=True)
class ModbusEvent:
    """One Modbus request **or** response — the unit both emitters consume.

    A scenario *exchange* expands to two events (request then matched response)
    sharing a connection (``uid`` + 4-tuple) and transaction id (``tid``). Both
    emitters read the very same objects, which is what guarantees PCAP and JSON
    cannot drift.
    """

    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    is_orig: bool
    func_code: int
    func_name: str
    action_class: str
    unit: int
    tid: int
    address: int | None = None
    quantity: int | None = None
    request_values: tuple[int, ...] = ()
    response_values: tuple[int, ...] = ()
    matched: bool = False
    is_exception: bool = False
    error: str | None = None
    exception_code: str | None = None

    @property
    def direction(self) -> str:
        """``request`` when from the originator, else ``response`` (schema-aligned)."""
        return "request" if self.is_orig else "response"


# --- function-name resolution ------------------------------------------------


def _normalize_function(name: str) -> str:
    """Collapse a function label to a comparison token (case/separator-insensitive)."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


_FUNCTION_BY_TOKEN: dict[str, int] = {
    _normalize_function(label): code for code, label in FUNCTION_NAMES.items()
}


def is_standard_function(code: int) -> bool:
    """True when ``code`` is one of the eight encoded standard read/write codes."""
    return code in FUNCTION_NAMES


def abnormal_function_name(code: int) -> str:
    """Zeek ``Modbus::function_codes`` rendering of a code absent from the table.

    Base Zeek's table has ``&default = fmt("unknown-%d", i)`` (verified against
    base/protocols/modbus/consts.zeek), so an undefined code N logs as
    ``unknown-N``; the emitter mirrors that spelling for fidelity.
    """
    return f"unknown-{code}"


def resolve_function(function: str) -> int:
    """Resolve a scenario ``function`` string to a Modbus function code.

    Accepts the Zeek name (``READ_HOLDING_REGISTERS``), the common CamelCase
    spelling used in scenarios (``ReadHoldingRegisters``), or a numeric code
    (``6`` / ``0x06``). A numeric code in the valid request range (1..0x7F) that
    is *not* one of the eight standard codes resolves as an abnormal/undefined
    function (the M2 recon signal) rather than raising — the emitter renders it
    ``unknown-N`` and draws an ILLEGAL_FUNCTION exception. A non-numeric label
    that names no known function, or a code outside the request range, raises
    :class:`ModbusError`.
    """
    token = _normalize_function(function)
    if token in _FUNCTION_BY_TOKEN:
        return _FUNCTION_BY_TOKEN[token]
    raw = function.strip().lower()
    try:
        code = int(raw, 16) if raw.startswith("0x") else int(raw)
    except ValueError:
        code = -1
    if code in FUNCTION_NAMES:
        return code
    if 1 <= code <= _MAX_REQUEST_FUNCTION and code not in _ZEEK_DEFINED_FUNCTION_CODES:
        # A code GENUINELY absent from Zeek's function-code table (e.g. 0x42) — the
        # only thing we treat as an abnormal/undefined M2 probe (renders unknown-N).
        return code
    supported = ", ".join(FUNCTION_NAMES[c] for c in sorted(FUNCTION_NAMES))
    if code in _ZEEK_DEFINED_FUNCTION_CODES:
        # A real, Zeek-named legacy/diagnostic function we do not encode — refuse to
        # mis-emit it as an undefined probe (which would create false M2 hits and a
        # JSON/Zeek fidelity mismatch). See modbus.py review (codex P2).
        raise ModbusError(
            f"Modbus function {function!r} (code {code:#04x}) is a defined function "
            f"Zeek names but this emitter does not encode; supported: {supported}. "
            "Use one of those, or a numeric code absent from the Modbus function table "
            "for an abnormal/undefined (M2) probe."
        )
    raise ModbusError(
        f"unsupported Modbus function {function!r}; supported: {supported}, "
        f"or a numeric undefined request code in 1..{_MAX_REQUEST_FUNCTION}"
    )


# --- param parsing -----------------------------------------------------------


def _req_int(params: Mapping[str, object], key: str, where: str, lo: int, hi: int) -> int:
    if key not in params:
        raise ModbusError(f"{where}: missing required param {key!r}")
    return _check_int(params[key], f"{where}.{key}", lo, hi)


def _opt_int(
    params: Mapping[str, object], key: str, where: str, lo: int, hi: int, default: int
) -> int:
    if key not in params:
        return default
    return _check_int(params[key], f"{where}.{key}", lo, hi)


def _check_int(value: object, where: str, lo: int, hi: int) -> int:
    # bool is an int subclass in Python; a coil/register count is never a bool.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModbusError(f"{where}: expected an integer")
    if not lo <= value <= hi:
        raise ModbusError(f"{where}: {value} out of range ({lo}-{hi})")
    return value


def _req_bit(params: Mapping[str, object], key: str, where: str) -> int:
    if key not in params:
        raise ModbusError(f"{where}: missing required param {key!r}")
    return _check_bit(params[key], f"{where}.{key}")


def _check_bit(value: object, where: str) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and value in (0, 1):
        return value
    raise ModbusError(f"{where}: expected 0, 1, or a boolean")


def _req_int_list(
    params: Mapping[str, object], key: str, where: str, lo: int, hi: int, max_len: int
) -> tuple[int, ...]:
    seq = _req_seq(params, key, where, max_len)
    return tuple(_check_int(item, f"{where}.{key}[{i}]", lo, hi) for i, item in enumerate(seq))


def _req_bit_list(
    params: Mapping[str, object], key: str, where: str, max_len: int
) -> tuple[int, ...]:
    seq = _req_seq(params, key, where, max_len)
    return tuple(_check_bit(item, f"{where}.{key}[{i}]") for i, item in enumerate(seq))


def _req_seq(
    params: Mapping[str, object], key: str, where: str, max_len: int
) -> tuple[object, ...]:
    if key not in params:
        raise ModbusError(f"{where}: missing required param {key!r}")
    value = params[key]
    # The loader deep-freezes scenario lists to tuples; accept either.
    if not isinstance(value, (list, tuple)):
        raise ModbusError(f"{where}.{key}: expected a list of integers")
    if not value:
        raise ModbusError(f"{where}.{key}: must be a non-empty list")
    if len(value) > max_len:
        raise ModbusError(f"{where}.{key}: too many values ({len(value)} > {max_len})")
    return tuple(value)


def _check_span(address: int, count: int, where: str) -> None:
    """Reject a coil/register span that runs past the 16-bit Modbus address space.

    ``address`` and ``count`` may each be individually in range while their span
    ``[address, address + count)`` still overflows past ``0xFFFF`` — an impossible
    Modbus operation we refuse up front rather than emit telemetry for.
    """
    if address + count > _U16 + 1:
        raise ModbusError(
            f"{where}: span [{address}, {address + count}) runs past the 16-bit "
            f"Modbus address space (address + quantity must be <= {_U16 + 1})"
        )


@dataclass(frozen=True, slots=True)
class _Payload:
    """Per-function semantic content shared by the request and its response."""

    address: int | None
    quantity: int | None
    request_values: tuple[int, ...]
    response_values: tuple[int, ...]


def _encode_exchange(code: int, params: Mapping[str, object], where: str) -> _Payload:
    """Validate ``params`` for ``code`` and synthesize request/response values.

    Response values are deterministic (a function of the address) so artifacts are
    byte-reproducible: emitting a scenario twice yields identical PCAP + JSON.
    """
    if code in (READ_COILS, READ_DISCRETE_INPUTS):
        address = _req_int(params, "address", where, 0, _U16)
        quantity = _req_int(params, "quantity", where, 1, _MAX_READ_BITS)
        _check_span(address, quantity, where)
        response = tuple((address + i) & 1 for i in range(quantity))
        return _Payload(address, quantity, (), response)
    if code in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        address = _req_int(params, "address", where, 0, _U16)
        quantity = _req_int(params, "quantity", where, 1, _MAX_READ_REGISTERS)
        _check_span(address, quantity, where)
        response = tuple((address + i) & _U16 for i in range(quantity))
        return _Payload(address, quantity, (), response)
    if code == WRITE_SINGLE_REGISTER:
        address = _req_int(params, "address", where, 0, _U16)
        value = _req_int(params, "value", where, 0, _U16)
        return _Payload(address, 1, (value,), (value,))
    if code == WRITE_SINGLE_COIL:
        address = _req_int(params, "address", where, 0, _U16)
        value = _req_bit(params, "value", where)
        return _Payload(address, 1, (value,), (value,))
    if code == WRITE_MULTIPLE_REGISTERS:
        address = _req_int(params, "address", where, 0, _U16)
        values = _req_int_list(params, "values", where, 0, _U16, _MAX_WRITE_REGISTERS)
        _check_span(address, len(values), where)
        return _Payload(address, len(values), values, ())
    if code == WRITE_MULTIPLE_COILS:
        address = _req_int(params, "address", where, 0, _U16)
        values = _req_bit_list(params, "values", where, _MAX_WRITE_BITS)
        _check_span(address, len(values), where)
        return _Payload(address, len(values), values, ())
    # resolve_function only returns codes we encode; guard the invariant anyway.
    raise ModbusError(f"{where}: no encoder for function code {code:#04x}")


def _abnormal_payload(params: Mapping[str, object], where: str) -> _Payload:
    """Validate the (optional) span of an undefined-function probe.

    An undefined function code carries no defined data model, so ``address`` and
    ``quantity`` are optional. They are kept as a **pair** so the one shared model
    drives both emitters identically (PRD §6.1): if either is given the other is
    defaulted (address->0, quantity->1), so the JSON and the PCAP body never
    disagree on which fields are present (codex P3). No response values are
    synthesized (the outstation answers with an exception).
    """
    has_addr = "address" in params
    has_qty = "quantity" in params
    if not has_addr and not has_qty:
        return _Payload(None, None, (), ())
    address = _check_int(params["address"], f"{where}.address", 0, _U16) if has_addr else 0
    quantity = _check_int(params["quantity"], f"{where}.quantity", 1, _U16) if has_qty else 1
    return _Payload(address, quantity, (), ())


# --- connection bookkeeping --------------------------------------------------

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _zeek_uid(key: str) -> str:
    """Deterministic Zeek-style connection uid (``C`` + 17 base62 chars)."""
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=13).digest()
    n = int.from_bytes(digest, "big")
    chars: list[str] = []
    for _ in range(17):
        n, rem = divmod(n, 62)
        chars.append(_B62[rem])
    return "C" + "".join(chars)


def _ipv4(host: str, actor_id: str) -> str:
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise ModbusError(
            f"actor {actor_id!r} host {host!r} is not an IPv4 address "
            "(Modbus/TCP PCAP emission requires IPv4)"
        ) from None
    return host


@dataclass(slots=True)
class _Conn:
    """A simulated persistent Modbus/TCP connection between two actors."""

    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    _tid: int = 0
    # Time the last response on this connection completed; requests are clamped to
    # not precede it so a single flow's events stay causally ordered (see build_events).
    last_response_ts: float = float("-inf")

    def next_tid(self) -> int:
        # Modbus transaction id is 16-bit; cycle 1..65535 (never 0) per connection.
        self._tid = self._tid % _U16 + 1
        return self._tid


def _connection(conns: dict[tuple[str, str], _Conn], src: Actor, dst: Actor) -> _Conn:
    key = (src.id, dst.id)
    conn = conns.get(key)
    if conn is None:
        orig_h = _ipv4(src.host, src.id)
        resp_h = _ipv4(dst.host, dst.id)
        resp_p = dst.port if dst.port is not None else DEFAULT_MODBUS_PORT
        orig_p = _EPHEMERAL_BASE + len(conns)
        if orig_p > _U16:
            raise ModbusError("too many distinct connections for the ephemeral port range")
        conn = _Conn(
            uid=_zeek_uid(f"{orig_h}:{orig_p}>{resp_h}:{resp_p}"),
            orig_h=orig_h,
            orig_p=orig_p,
            resp_h=resp_h,
            resp_p=resp_p,
        )
        conns[key] = conn
    return conn


def build_events(scenario: Scenario) -> list[ModbusEvent]:
    """Expand a Modbus scenario into the ordered shared event list.

    Each exchange becomes a request event and a matched response event on a
    persistent per-(source, target) connection, with a deterministic uid,
    ephemeral port, transaction id, and timestamps derived from the scenario
    timing. Both emitters consume the returned list verbatim.
    """
    if scenario.protocol is not Protocol.MODBUS:
        raise ModbusError(
            f"build_events: expected a modbus scenario, got {scenario.protocol.value}"
        )
    actors = {a.id: a for a in scenario.actors}
    conns: dict[tuple[str, str], _Conn] = {}
    events: list[ModbusEvent] = []
    prev_base_ts: float | None = None  # start time of the previous exchange

    for idx, exchange in enumerate(scenario.exchanges):
        where = f"exchanges[{idx}] ({exchange.function})"
        code = resolve_function(exchange.function)
        # A genuinely undefined request code (the M2 abnormal-function signal) has
        # no standard name/class/payload: render it Zeek's `unknown-N`, class it
        # `other`, and have the outstation answer ILLEGAL_FUNCTION.
        if is_standard_function(code):
            func_name = FUNCTION_NAMES[code]
            action_class = ACTION_CLASS[code]
            exception_name: str | None = None
        else:
            func_name = abnormal_function_name(code)
            action_class = "other"
            exception_name = ILLEGAL_FUNCTION
        # The loader guarantees source/target reference declared actors.
        conn = _connection(conns, actors[exchange.source], actors[exchange.target])
        tid = conn.next_tid()
        unit = _opt_int(exchange.params, "unit_id", where, 0, 255, 1)
        payload = (
            _abnormal_payload(exchange.params, where)
            if exception_name is not None
            else _encode_exchange(code, exchange.params, where)
        )
        # Base time: an explicit offset is seconds from timing.start and always
        # wins; an omitted offset (None) auto-spaces default_interval after the
        # previous exchange (the first such exchange starts at timing.start).
        if exchange.offset is not None:
            base_ts = scenario.timing.start + exchange.offset
        elif prev_base_ts is None:
            base_ts = scenario.timing.start
        else:
            base_ts = prev_base_ts + scenario.timing.default_interval
        prev_base_ts = base_ts
        # Serialize transactions on a connection: a request never precedes the
        # previous response on the same flow. This keeps each flow causally
        # ordered (and its TCP seq/ack valid) even when exchanges share a base
        # time or sit closer than RESPONSE_DELAY, so the PCAP's global time sort
        # cannot reorder a request ahead of an earlier response (PR #5 review).
        request_ts = max(base_ts, conn.last_response_ts)
        response_ts = request_ts + RESPONSE_DELAY
        conn.last_response_ts = response_ts

        events.append(
            ModbusEvent(
                ts=request_ts,
                uid=conn.uid,
                orig_h=conn.orig_h,
                orig_p=conn.orig_p,
                resp_h=conn.resp_h,
                resp_p=conn.resp_p,
                is_orig=True,
                func_code=code,
                func_name=func_name,
                action_class=action_class,
                unit=unit,
                tid=tid,
                address=payload.address,
                quantity=payload.quantity,
                request_values=payload.request_values,
            )
        )
        # An exception response carries the exception function on the wire
        # (code | 0x80) and the `<FUNCTION>_EXCEPTION` name — the established schema
        # convention (the honeypot + the golden events render exceptions this way),
        # so detections/baselines keying on func_code/func_name match the PCAP and
        # honeypot telemetry alike (codex P2).
        if exception_name is not None:
            response_func_code = code | EXCEPTION_FLAG
            response_func_name = f"{func_name}_EXCEPTION"
        else:
            response_func_code = code
            response_func_name = func_name
        events.append(
            ModbusEvent(
                ts=response_ts,
                uid=conn.uid,
                orig_h=conn.orig_h,
                orig_p=conn.orig_p,
                resp_h=conn.resp_h,
                resp_p=conn.resp_p,
                is_orig=False,
                func_code=response_func_code,
                func_name=response_func_name,
                action_class=action_class,
                unit=unit,
                tid=tid,
                address=payload.address,
                quantity=payload.quantity,
                response_values=payload.response_values,
                matched=True,
                is_exception=exception_name is not None,
                error=exception_name,
                exception_code=exception_name,
            )
        )

    return events


def event_to_dict(event: ModbusEvent) -> dict[str, Any]:
    """Render one Modbus event as the schema's envelope + Modbus ``detail`` dict.

    The JSON emitter (:mod:`substation.emit.json_emitter`) writes the returned record
    after validating it against the frozen event-log schema (``docs/schema.md``).
    """
    detail: dict[str, Any] = {"tid": event.tid, "unit": event.unit, "func": event.func_name}
    if event.address is not None:
        detail["address"] = event.address
    if event.quantity is not None:
        detail["quantity"] = event.quantity
    if event.request_values:
        detail["request_values"] = list(event.request_values)
    if event.response_values:
        detail["response_values"] = list(event.response_values)
    if event.exception_code is not None:
        detail["exception_code"] = event.exception_code
    if event.matched:
        detail["matched"] = True

    return {
        "ts": event.ts,
        "uid": event.uid,
        "conn": {
            "orig_h": event.orig_h,
            "orig_p": event.orig_p,
            "resp_h": event.resp_h,
            "resp_p": event.resp_p,
        },
        "proto": "modbus",
        "is_orig": event.is_orig,
        "direction": event.direction,
        "func_code": event.func_code,
        "func_name": event.func_name,
        "action_class": event.action_class,
        "is_exception": event.is_exception,
        "error": event.error,
        "detail": detail,
    }
