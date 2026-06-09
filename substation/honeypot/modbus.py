"""Passive, isolated Modbus/TCP honeypot that logs inbound probes (PRD §6.10).

A minimal Modbus responder for **research**: it binds a listening socket, answers
inbound requests with **banner/coil/register stubs only**, and records every probe
as a Substation event-log line so the existing detections can run against captured
probe traffic. It is **not** a PLC emulator — there is no process model, only stub
reads/writes and standards-compliant exception replies.

Safety posture (non-negotiable — see ``substation/honeypot/README.md``):

- **Passive.** It only ``accept()``s inbound connections and replies on them. It
  **never** calls ``connect()`` / initiates an outbound connection, and never
  touches real OT equipment.
- **Isolated by default.** It binds **loopback only** unless the operator passes an
  explicit ``allow_external`` opt-in, so a careless run cannot be reached off-box.
- **Out of the headline path.** Nothing in the demo/CLI imports this; it is opt-in.

Design: the protocol logic is a **pure function** (:func:`process_frame`) that maps
raw request bytes to ``(response_bytes, [event, ...])`` with no I/O, so it is fully
unit-testable without ever opening a socket. :class:`ModbusHoneypot` is the thin
socket loop around it. Every emitted event is built through the **same**
``substation.protocols.modbus.event_to_dict`` mapping the simulator uses and is
validated against the frozen event-log schema before it is written, so honeypot
logs cannot drift from the contract the detections bind to (``docs/schema.md``).
"""

from __future__ import annotations

import json
import socket
import struct
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from substation.protocols._common import zeek_uid as _zeek_uid
from substation.protocols.modbus import (
    DEFAULT_MODBUS_PORT,
    READ_COILS,
    READ_DISCRETE_INPUTS,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    WRITE_MULTIPLE_COILS,
    WRITE_MULTIPLE_REGISTERS,
    WRITE_SINGLE_COIL,
    WRITE_SINGLE_REGISTER,
    ModbusEvent,
    event_to_dict,
    function_action_class,
    zeek_function_name,
)
from substation.schema import load_event_schema, validate_event

__all__ = [
    "HoneypotConfig",
    "HoneypotConfigError",
    "ModbusHoneypot",
    "StubDevice",
    "process_frame",
]

# --- Modbus/TCP wire constants ----------------------------------------------

_MBAP_LEN = 7  # transaction id(2) + protocol id(2) + length(2) + unit id(1)
_MAX_PDU = 253  # Modbus PDU max (Modbus Application Protocol Spec v1.1b3)
_MAX_ADU = _MBAP_LEN + _MAX_PDU  # largest legal Modbus/TCP frame
_EXCEPTION_FLAG = 0x80
_ON = 0xFF00  # WRITE_SINGLE_COIL "on" value
_OFF = 0x0000  # WRITE_SINGLE_COIL "off" value (any other value is illegal)
_U16 = 0xFFFF

# Per-function quantity limits (Modbus Application Protocol Spec v1.1b3). A request
# outside these is malformed: a compliant device answers ILLEGAL_DATA_VALUE rather
# than emitting an over-long PDU. Enforcing them also keeps a scanner from crashing
# the honeypot (e.g. a register read of 128 would overflow the 1-byte byte-count).
_MAX_READ_REGISTERS = 125
_MAX_READ_BITS = 2000
_MAX_WRITE_REGISTERS = 123
_MAX_WRITE_BITS = 1968

# Modbus exception codes (spec v1.1b3) -> the ICSNPP/Zeek decoded names the schema
# and M2 key on. We only ever raise these three from a stub responder.
_ILLEGAL_FUNCTION = 0x01
_ILLEGAL_DATA_ADDRESS = 0x02
_ILLEGAL_DATA_VALUE = 0x03
_EXCEPTION_NAMES: dict[int, str] = {
    _ILLEGAL_FUNCTION: "ILLEGAL_FUNCTION",
    _ILLEGAL_DATA_ADDRESS: "ILLEGAL_DATA_ADDRESS",
    _ILLEGAL_DATA_VALUE: "ILLEGAL_DATA_VALUE",
}

# Hosts that keep the honeypot unreachable off-box. Binding anything else requires
# the explicit allow_external opt-in (see HoneypotConfig).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class HoneypotConfigError(ValueError):
    """Raised for an unsafe or invalid honeypot configuration."""


# --- stub device -------------------------------------------------------------


@dataclass(slots=True)
class StubDevice:
    """In-memory coil/register stubs (PRD §6.10: "coil/register stubs" only).

    Not a process model: reads return a deterministic default unless a prior write
    set the address, and the address space is bounded so a recon sweep of a large
    range draws an ``ILLEGAL_DATA_ADDRESS`` exception (useful M2 telemetry) rather
    than allocating unbounded memory.
    """

    address_space: int = 1024
    _registers: dict[int, int] = field(default_factory=dict)
    _coils: dict[int, int] = field(default_factory=dict)

    def in_range(self, address: int, count: int) -> bool:
        """True when ``[address, address + count)`` fits the stub address space."""
        return address >= 0 and count >= 0 and address + count <= self.address_space

    def read_registers(self, address: int, count: int) -> list[int]:
        return [self._registers.get(address + i, (address + i) & _U16) for i in range(count)]

    def read_coils(self, address: int, count: int) -> list[int]:
        return [self._coils.get(address + i, (address + i) & 1) for i in range(count)]

    def write_register(self, address: int, value: int) -> None:
        self._registers[address] = value & _U16

    def write_registers(self, address: int, values: list[int]) -> None:
        for i, value in enumerate(values):
            self.write_register(address + i, value)

    def write_coil(self, address: int, bit: int) -> None:
        self._coils[address] = 1 if bit else 0

    def write_coils(self, address: int, bits: list[int]) -> None:
        for i, bit in enumerate(bits):
            self.write_coil(address + i, bit)


# --- pure protocol core ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Conn:
    """The connection 4-tuple from the honeypot's point of view (it is responder)."""

    orig_h: str  # the prober (originator)
    orig_p: int
    resp_h: str  # the honeypot (responder)
    resp_p: int


@dataclass(frozen=True, slots=True)
class _Parsed:
    """A decoded Modbus/TCP request frame."""

    tid: int
    unit: int
    func_code: int
    data: bytes


def _parse_frame(raw: bytes) -> _Parsed | None:
    """Decode one Modbus/TCP ADU; ``None`` if it is not a parseable Modbus frame.

    A probe that is not Modbus (or is truncated below a function code) is not a
    schema event we can represent, so it is skipped rather than logged malformed.
    """
    if len(raw) < _MBAP_LEN + 1:
        return None
    tid, proto_id, length, unit = struct.unpack(">HHHB", raw[:_MBAP_LEN])
    if proto_id != 0:  # protocol identifier is 0 for Modbus
        return None
    if length < 2:  # must cover at least unit id + function code
        return None
    func_code = raw[_MBAP_LEN]
    # length counts unit id (1) + PDU; clamp the PDU to the bytes actually present.
    pdu_end = min(len(raw), _MBAP_LEN + (length - 1))
    data = raw[_MBAP_LEN + 1 : pdu_end]
    return _Parsed(tid=tid, unit=unit, func_code=func_code, data=data)


def _func_name(func_code: int) -> str:
    """Decoded Zeek function name, including ``unknown-N`` for undefined codes."""
    return zeek_function_name(func_code)


def _request_event(
    parsed: _Parsed,
    conn: _Conn,
    *,
    uid: str,
    ts: float,
    address: int | None = None,
    quantity: int | None = None,
    request_values: tuple[int, ...] = (),
) -> dict[str, Any]:
    """Build the schema event for the inbound probe (the request side)."""
    event = ModbusEvent(
        ts=ts,
        uid=uid,
        orig_h=conn.orig_h,
        orig_p=conn.orig_p,
        resp_h=conn.resp_h,
        resp_p=conn.resp_p,
        is_orig=True,
        func_code=parsed.func_code,
        func_name=_func_name(parsed.func_code),
        action_class=function_action_class(parsed.func_code),
        unit=parsed.unit,
        tid=parsed.tid,
        address=address,
        quantity=quantity,
        request_values=request_values,
    )
    return event_to_dict(event)


def _response_event(
    parsed: _Parsed,
    conn: _Conn,
    *,
    uid: str,
    ts: float,
    address: int | None = None,
    quantity: int | None = None,
    response_values: tuple[int, ...] = (),
    exception_code: int | None = None,
) -> dict[str, Any]:
    """Build the schema event for the honeypot's reply (normal or exception)."""
    action_class = function_action_class(parsed.func_code)
    if exception_code is not None:
        name = _EXCEPTION_NAMES[exception_code]
        event = ModbusEvent(
            ts=ts,
            uid=uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=False,
            func_code=parsed.func_code | _EXCEPTION_FLAG,
            func_name=f"{_func_name(parsed.func_code)}_EXCEPTION",
            action_class=action_class,
            unit=parsed.unit,
            tid=parsed.tid,
            matched=True,
            is_exception=True,
            error=name,
            exception_code=name,
        )
        return event_to_dict(event)
    event = ModbusEvent(
        ts=ts,
        uid=uid,
        orig_h=conn.orig_h,
        orig_p=conn.orig_p,
        resp_h=conn.resp_h,
        resp_p=conn.resp_p,
        is_orig=False,
        func_code=parsed.func_code,
        func_name=_func_name(parsed.func_code),
        action_class=action_class,
        unit=parsed.unit,
        tid=parsed.tid,
        address=address,
        quantity=quantity,
        response_values=response_values,
        matched=True,
    )
    return event_to_dict(event)


def _mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    """Wrap a PDU in the Modbus/TCP MBAP header (length = unit id + PDU)."""
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _exception_pdu(func_code: int, exception_code: int) -> bytes:
    return bytes((func_code | _EXCEPTION_FLAG, exception_code))


def _pack_bits(bits: list[int]) -> bytes:
    """Pack coil/discrete-input bits LSB-first into bytes (Modbus order)."""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _exception_reply(
    parsed: _Parsed,
    conn: _Conn,
    *,
    uid: str,
    ts: float,
    exception_code: int,
    request_event: dict[str, Any] | None = None,
) -> tuple[bytes, list[dict[str, Any]]]:
    """Build an exception reply + its events (synthesizing the request event if absent)."""
    if request_event is None:
        request_event = _request_event(parsed, conn, uid=uid, ts=ts)
    response_event = _response_event(parsed, conn, uid=uid, ts=ts, exception_code=exception_code)
    pdu = _exception_pdu(parsed.func_code, exception_code)
    return _mbap(parsed.tid, parsed.unit, pdu), [request_event, response_event]


def process_frame(
    raw: bytes,
    *,
    orig_h: str,
    orig_p: int,
    resp_h: str,
    resp_p: int,
    uid: str,
    ts: float,
    device: StubDevice,
) -> tuple[bytes | None, list[dict[str, Any]]]:
    """Pure core: map one inbound request frame to ``(reply_bytes, [events])``.

    Returns the Modbus/TCP reply to send (``None`` if the frame is not parseable
    Modbus and nothing should be sent) and the list of schema event dicts to log
    (the request probe plus the honeypot's reply). No I/O — fully unit-testable
    without a socket.
    """
    parsed = _parse_frame(raw)
    if parsed is None:
        return None, []

    conn = _Conn(orig_h=orig_h, orig_p=orig_p, resp_h=resp_h, resp_p=resp_p)
    code = parsed.func_code
    data = parsed.data

    # --- reads ---------------------------------------------------------------
    if code in (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        if len(data) < 4:
            return _exception_reply(
                parsed, conn, uid=uid, ts=ts, exception_code=_ILLEGAL_DATA_VALUE
            )
        address, quantity = struct.unpack(">HH", data[:4])
        request_event = _request_event(
            parsed, conn, uid=uid, ts=ts, address=address, quantity=quantity
        )
        is_coil = code in (READ_COILS, READ_DISCRETE_INPUTS)
        # A quantity outside the spec range is malformed (ILLEGAL_DATA_VALUE) — and
        # left unguarded a large register count would overflow the response's 1-byte
        # byte-count field and crash the handler.
        max_quantity = _MAX_READ_BITS if is_coil else _MAX_READ_REGISTERS
        if not 1 <= quantity <= max_quantity:
            return _exception_reply(
                parsed,
                conn,
                uid=uid,
                ts=ts,
                exception_code=_ILLEGAL_DATA_VALUE,
                request_event=request_event,
            )
        if not device.in_range(address, quantity):
            return _exception_reply(
                parsed,
                conn,
                uid=uid,
                ts=ts,
                exception_code=_ILLEGAL_DATA_ADDRESS,
                request_event=request_event,
            )
        values = (
            device.read_coils(address, quantity)
            if is_coil
            else (device.read_registers(address, quantity))
        )
        body = _pack_bits(values) if is_coil else b"".join(struct.pack(">H", v) for v in values)
        pdu = bytes((code, len(body))) + body
        response_event = _response_event(
            parsed,
            conn,
            uid=uid,
            ts=ts,
            address=address,
            quantity=quantity,
            response_values=tuple(values),
        )
        return _mbap(parsed.tid, parsed.unit, pdu), [request_event, response_event]

    # --- single writes -------------------------------------------------------
    if code in (WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER):
        if len(data) < 4:
            return _exception_reply(
                parsed, conn, uid=uid, ts=ts, exception_code=_ILLEGAL_DATA_VALUE
            )
        address, value = struct.unpack(">HH", data[:4])
        if code == WRITE_SINGLE_COIL and value not in (_OFF, _ON):
            # The spec allows only 0x0000/0xFF00 for a single coil; any other value
            # is ILLEGAL_DATA_VALUE and must NOT mutate the coil. Log the raw value
            # so the malformed probe is visible rather than silently coerced.
            request_event = _request_event(
                parsed, conn, uid=uid, ts=ts, address=address, quantity=1, request_values=(value,)
            )
            return _exception_reply(
                parsed,
                conn,
                uid=uid,
                ts=ts,
                exception_code=_ILLEGAL_DATA_VALUE,
                request_event=request_event,
            )
        if code == WRITE_SINGLE_COIL:
            request_values: tuple[int, ...] = (1 if value == _ON else 0,)
        else:
            request_values = (value,)
        request_event = _request_event(
            parsed,
            conn,
            uid=uid,
            ts=ts,
            address=address,
            quantity=1,
            request_values=request_values,
        )
        if not device.in_range(address, 1):
            return _exception_reply(
                parsed,
                conn,
                uid=uid,
                ts=ts,
                exception_code=_ILLEGAL_DATA_ADDRESS,
                request_event=request_event,
            )
        if code == WRITE_SINGLE_COIL:
            device.write_coil(address, request_values[0])
        else:
            device.write_register(address, value)
        # A single write echoes the request frame verbatim as its response.
        pdu = bytes((code,)) + struct.pack(">HH", address, value)
        response_event = _response_event(
            parsed,
            conn,
            uid=uid,
            ts=ts,
            address=address,
            quantity=1,
            response_values=request_values,
        )
        return _mbap(parsed.tid, parsed.unit, pdu), [request_event, response_event]

    # --- multiple writes -----------------------------------------------------
    if code in (WRITE_MULTIPLE_COILS, WRITE_MULTIPLE_REGISTERS):
        if len(data) < 5:
            return _exception_reply(
                parsed, conn, uid=uid, ts=ts, exception_code=_ILLEGAL_DATA_VALUE
            )
        address, quantity, byte_count = struct.unpack(">HHB", data[:5])
        body = data[5 : 5 + byte_count]
        is_coil = code == WRITE_MULTIPLE_COILS
        # Validate quantity and the declared byte count against the spec BEFORE
        # indexing/unpacking: a frame whose byte_count is too small for `quantity`
        # (e.g. FC15 qty 9 byte_count 1, or an odd FC16 byte_count) would otherwise
        # raise IndexError/struct.error and crash the handler. Such frames are
        # malformed -> ILLEGAL_DATA_VALUE.
        max_quantity = _MAX_WRITE_BITS if is_coil else _MAX_WRITE_REGISTERS
        expected_bytes = (quantity + 7) // 8 if is_coil else quantity * 2
        well_formed = (
            1 <= quantity <= max_quantity
            and byte_count == expected_bytes
            and len(body) >= expected_bytes
        )
        if not well_formed:
            return _exception_reply(
                parsed, conn, uid=uid, ts=ts, exception_code=_ILLEGAL_DATA_VALUE
            )
        if code == WRITE_MULTIPLE_REGISTERS:
            values = [int(v) for (v,) in struct.iter_unpack(">H", body[: quantity * 2])]
        else:
            values = [(body[i // 8] >> (i % 8)) & 1 for i in range(quantity)]
        request_event = _request_event(
            parsed,
            conn,
            uid=uid,
            ts=ts,
            address=address,
            quantity=quantity,
            request_values=tuple(values),
        )
        if not device.in_range(address, quantity):
            return _exception_reply(
                parsed,
                conn,
                uid=uid,
                ts=ts,
                exception_code=_ILLEGAL_DATA_ADDRESS,
                request_event=request_event,
            )
        if code == WRITE_MULTIPLE_REGISTERS:
            device.write_registers(address, values)
        else:
            device.write_coils(address, values)
        # The response to a multiple write echoes the starting address and count.
        pdu = bytes((code,)) + struct.pack(">HH", address, quantity)
        response_event = _response_event(
            parsed, conn, uid=uid, ts=ts, address=address, quantity=quantity
        )
        return _mbap(parsed.tid, parsed.unit, pdu), [request_event, response_event]

    # --- unsupported / reserved function code --------------------------------
    # A reserved/undefined or simply unimplemented function: a compliant device
    # answers ILLEGAL_FUNCTION. The request itself surfaces as action_class
    # `other` (M2's abnormal-code arm) and the reply as an ILLEGAL_FUNCTION
    # exception (M2's exception arm).
    return _exception_reply(parsed, conn, uid=uid, ts=ts, exception_code=_ILLEGAL_FUNCTION)


# --- socket server -----------------------------------------------------------


@dataclass(slots=True)
class HoneypotConfig:
    """Honeypot runtime configuration. Loopback-only unless ``allow_external``.

    ``bind_host`` defaults to loopback so a careless run cannot be reached off-box.
    Binding any non-loopback address (to actually capture remote probes on an
    isolated research segment) requires ``allow_external=True`` as a deliberate
    opt-in — anything else raises :class:`HoneypotConfigError`.
    """

    log_path: Path
    bind_host: str = "127.0.0.1"
    port: int = DEFAULT_MODBUS_PORT
    allow_external: bool = False
    recv_timeout: float = 10.0
    backlog: int = 8
    # Rotate the probe log once it reaches this size (bytes): the current file is
    # renamed to <log>.1 (replacing any previous one) and a fresh file is started.
    # A noisy scanner must not be able to grow the log without bound. 0 disables.
    max_log_bytes: int = 50 * 1024 * 1024

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise HoneypotConfigError(f"port {self.port} out of range (1-65535)")
        if self.max_log_bytes < 0:
            raise HoneypotConfigError("max_log_bytes must be >= 0 (0 disables rotation)")
        if self.bind_host not in _LOOPBACK_HOSTS and not self.allow_external:
            raise HoneypotConfigError(
                f"refusing to bind non-loopback address {self.bind_host!r} without "
                "allow_external=True. The honeypot must be deployed network-isolated "
                "(see substation/honeypot/README.md); set the opt-in only on an "
                "isolated research segment."
            )


class _ProbeLog:
    """Append-only, size-capped writer for schema-validated honeypot events.

    When the log reaches ``max_bytes`` it is rotated to ``<log>.1`` (replacing
    any previous rotation) so a noisy scanner cannot fill the disk; at most two
    files (current + one rotation) ever exist.
    """

    def __init__(self, path: Path, max_bytes: int = 0) -> None:
        self._schema = load_event_schema()
        self._path = path
        self._max_bytes = max_bytes
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")
        self._size = path.stat().st_size

    def _rotate_if_needed(self, incoming: int) -> None:
        if self._max_bytes <= 0 or self._size + incoming <= self._max_bytes:
            return
        self._fh.close()
        self._path.replace(self._path.with_name(self._path.name + ".1"))
        self._fh = self._path.open("a", encoding="utf-8")
        self._size = 0

    def write(self, event: dict[str, Any]) -> None:
        # Validate against the frozen contract before writing so the honeypot can
        # never emit telemetry the detections cannot consume (docs/schema.md).
        validate_event(event, self._schema)
        line = json.dumps(event, allow_nan=False) + "\n"
        self._rotate_if_needed(len(line.encode("utf-8")))
        self._fh.write(line)
        self._fh.flush()
        self._size += len(line.encode("utf-8"))

    def close(self) -> None:
        self._fh.close()


class ModbusHoneypot:
    """Passive Modbus/TCP probe responder around the pure :func:`process_frame` core.

    It binds, listens and accepts; for each inbound frame it logs the probe and
    replies with stub data. It **never** initiates an outbound connection. Single
    connection at a time (minimal by design); a per-connection recv timeout keeps a
    silent client from blocking the listener indefinitely.
    """

    def __init__(self, config: HoneypotConfig) -> None:
        config.validate()
        self.config = config
        self.device = StubDevice()
        self._log = _ProbeLog(config.log_path, max_bytes=config.max_log_bytes)
        self._conn_seq = 0

    def _next_uid(self, peer: tuple[str, int]) -> str:
        self._conn_seq += 1
        key = f"{peer[0]}:{peer[1]}>{self.config.bind_host}:{self.config.port}#{self._conn_seq}"
        return _zeek_uid(key)

    def _handle_connection(self, sock: socket.socket, peer: tuple[str, int]) -> None:
        uid = self._next_uid(peer)
        sock.settimeout(self.config.recv_timeout)
        # The actual interface that accepted this probe — not the configured bind
        # string — so a wildcard bind (e.g. 0.0.0.0) records the true destination in
        # conn.resp_h instead of collapsing every local address into the wildcard.
        sockname = sock.getsockname()
        local_host, local_port = str(sockname[0]), int(sockname[1])
        buffer = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except (TimeoutError, OSError):
                return
            if not chunk:
                return  # peer closed
            buffer.extend(chunk)
            # A scanner may pipeline several frames; drain every complete ADU.
            # NB: the probe and its reply share one observation timestamp (the
            # honeypot answers in-process, sub-millisecond) — unlike the
            # simulator, which models an explicit outstation turnaround delay.
            for raw in _split_adus(buffer):
                reply, events = process_frame(
                    raw,
                    orig_h=peer[0],
                    orig_p=peer[1],
                    resp_h=local_host,
                    resp_p=local_port,
                    uid=uid,
                    ts=time.time(),
                    device=self.device,
                )
                for event in events:
                    self._log.write(event)
                if reply is not None:
                    # Replying on the already-accepted inbound socket — passive by
                    # construction. The honeypot never opens an outbound connection.
                    sock.sendall(reply)

    def serve_forever(self) -> None:
        """Bind, listen and serve probes until interrupted (Ctrl-C)."""
        # Match the socket family to the bind address so an IPv6 loopback (``::1``,
        # which validate() accepts) actually binds instead of failing on AF_INET.
        family = socket.AF_INET6 if ":" in self.config.bind_host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.config.bind_host, self.config.port))
            listener.listen(self.config.backlog)
            scope = "loopback-only" if self.config.bind_host in _LOOPBACK_HOSTS else "EXTERNAL"
            print(
                f"[honeypot] passive Modbus probe logger listening on "
                f"{self.config.bind_host}:{self.config.port} ({scope}); "
                f"logging to {self.config.log_path}. Deploy network-isolated only. "
                "Ctrl-C to stop."
            )
            while True:
                try:
                    conn, peer = listener.accept()
                except KeyboardInterrupt:
                    raise
                except OSError:
                    continue
                with conn:
                    try:
                        self._handle_connection(conn, peer)
                    except OSError:
                        # A misbehaving client must never crash the listener.
                        continue
        except KeyboardInterrupt:
            print("\n[honeypot] stopped.")
        finally:
            listener.close()
            self._log.close()


def _split_adus(buffer: bytearray) -> Iterator[bytes]:
    """Yield complete Modbus/TCP ADUs from ``buffer``, consuming them in place.

    Frames are length-delimited by the MBAP length field. A trailing partial frame
    is left in the buffer for the next ``recv``; an absurd declared length is
    dropped so a malformed probe cannot wedge the parser.
    """
    while len(buffer) >= _MBAP_LEN:
        length = struct.unpack(">H", buffer[4:6])[0]
        if length < 2 or length > _MAX_PDU + 1:
            buffer.clear()  # not a sane Modbus frame; discard the buffer
            return
        total = 6 + length
        if total > _MAX_ADU:
            buffer.clear()
            return
        if len(buffer) < total:
            return  # wait for the rest of this frame
        yield bytes(buffer[:total])
        del buffer[:total]
