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

from substation.scenarios import Actor, Protocol, Scenario

__all__ = [
    "ModbusError",
    "ModbusEvent",
    "build_events",
    "resolve_function",
    "FUNCTION_NAMES",
    "ACTION_CLASS",
    "DEFAULT_MODBUS_PORT",
    "RESPONSE_DELAY",
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

# Quantity limits from the Modbus spec; reject impossible scenarios up front so an
# author sees a clear error instead of a malformed PDU.
_MAX_READ_REGISTERS = 125
_MAX_READ_BITS = 2000
_MAX_WRITE_REGISTERS = 123
_MAX_WRITE_BITS = 1968

_U16 = 0xFFFF


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


def resolve_function(function: str) -> int:
    """Resolve a scenario ``function`` string to a supported Modbus code.

    Accepts the Zeek name (``READ_HOLDING_REGISTERS``), the common CamelCase
    spelling used in scenarios (``ReadHoldingRegisters``), or a numeric code
    (``6`` / ``0x06``). Raises :class:`ModbusError` for anything unsupported.
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
    supported = ", ".join(FUNCTION_NAMES[c] for c in sorted(FUNCTION_NAMES))
    raise ModbusError(f"unsupported Modbus function {function!r}; supported: {supported}")


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
        response = tuple((address + i) & 1 for i in range(quantity))
        return _Payload(address, quantity, (), response)
    if code in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        address = _req_int(params, "address", where, 0, _U16)
        quantity = _req_int(params, "quantity", where, 1, _MAX_READ_REGISTERS)
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
        return _Payload(address, len(values), values, ())
    if code == WRITE_MULTIPLE_COILS:
        address = _req_int(params, "address", where, 0, _U16)
        values = _req_bit_list(params, "values", where, _MAX_WRITE_BITS)
        return _Payload(address, len(values), values, ())
    # resolve_function only returns codes we encode; guard the invariant anyway.
    raise ModbusError(f"{where}: no encoder for function code {code:#04x}")


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

    for idx, exchange in enumerate(scenario.exchanges):
        where = f"exchanges[{idx}] ({exchange.function})"
        code = resolve_function(exchange.function)
        func_name = FUNCTION_NAMES[code]
        action_class = ACTION_CLASS[code]
        # The loader guarantees source/target reference declared actors.
        conn = _connection(conns, actors[exchange.source], actors[exchange.target])
        tid = conn.next_tid()
        unit = _opt_int(exchange.params, "unit_id", where, 0, 255, 1)
        payload = _encode_exchange(code, exchange.params, where)
        request_ts = scenario.timing.start + exchange.offset

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
        events.append(
            ModbusEvent(
                ts=request_ts + RESPONSE_DELAY,
                uid=conn.uid,
                orig_h=conn.orig_h,
                orig_p=conn.orig_p,
                resp_h=conn.resp_h,
                resp_p=conn.resp_p,
                is_orig=False,
                func_code=code,
                func_name=func_name,
                action_class=action_class,
                unit=unit,
                tid=tid,
                address=payload.address,
                quantity=payload.quantity,
                response_values=payload.response_values,
                matched=True,
            )
        )

    return events
