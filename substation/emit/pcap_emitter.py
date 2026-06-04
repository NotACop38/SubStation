"""PCAP emitter: shared Modbus events -> Modbus/TCP ``.pcap`` via scapy.

Consumes the **same** :class:`~substation.protocols.modbus.ModbusEvent` list as
the JSON emitter (PRD §6.1: one model, dual emit, no drift). Each event becomes a
Modbus/TCP segment on a synthetic but well-formed TCP stream — SYN handshake,
PSH/ACK request and response carrying the Modbus ADU, then a FIN teardown — with
sequence/acknowledgement numbers tracked per connection so the capture parses
cleanly in Zeek/Wireshark for the Tier-2 fidelity check (PRD §6.4).

scapy assembles the Modbus PDUs (spike 02 verdict: ``scapy.contrib.modbus`` covers
every Modbus PDU we need; the exact class/field names were verified there and in
this module's empirical checks — never invented from memory). Output is
deterministic: identical input yields byte-identical PCAP. Writing uses scapy's
``PcapWriter`` (ordinary file I/O); no socket is ever opened — see
:mod:`substation.emit.guard`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from scapy.contrib import modbus as mb
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from substation.protocols.modbus import (
    EXCEPTION_CODE_BYTES,
    READ_COILS,
    READ_DISCRETE_INPUTS,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    WRITE_MULTIPLE_COILS,
    WRITE_MULTIPLE_REGISTERS,
    WRITE_SINGLE_COIL,
    WRITE_SINGLE_REGISTER,
    ModbusError,
    ModbusEvent,
    is_standard_function,
)

# Modbus sets the high bit of the function code in an exception reply (e.g. an
# undefined request 0x42 draws a 0xC2 exception PDU carrying the exception byte).
_EXCEPTION_FUNCTION_BIT = 0x80

__all__ = ["write_pcap"]

_DLT_EN10MB = 1  # Ethernet link-type for the PCAP global header.
_COIL_ON = 0xFF00  # Modbus on-the-wire coil "on" value (off is 0x0000).
# Small per-direction time offsets so handshake/teardown frames order around the
# Modbus segments without colliding with their event timestamps.
_HANDSHAKE_GAP = 0.003
_TEARDOWN_GAP = 0.003


def _pack_bits(bits: tuple[int, ...]) -> list[int]:
    """Pack coil/discrete bits LSB-first into a list of byte values."""
    packed: list[int] = []
    for start in range(0, len(bits), 8):
        byte = 0
        for offset, bit in enumerate(bits[start : start + 8]):
            if bit:
                byte |= 1 << offset
        packed.append(byte)
    return packed


def _abnormal_request_pdu(event: ModbusEvent) -> Any:
    """Raw PDU for an undefined request function code (scapy has no class for it).

    The PDU is the function-code byte followed by the optional address/quantity
    span; scapy decodes it as a User-Defined Function Code Request and the MBAP
    length is computed automatically.
    """
    body = bytes([event.func_code])
    if event.address is not None:
        body += int(event.address).to_bytes(2, "big")
        body += int(event.quantity if event.quantity is not None else 1).to_bytes(2, "big")
    return Raw(load=body)


def _exception_response_pdu(event: ModbusEvent) -> Any:
    """Raw exception PDU: (func_code | 0x80) then the exception code byte."""
    name = event.exception_code or event.error or ""
    exc_byte = EXCEPTION_CODE_BYTES.get(name)
    if exc_byte is None:
        raise ModbusError(f"no on-the-wire exception byte for {name!r}")
    return Raw(load=bytes([event.func_code | _EXCEPTION_FUNCTION_BIT, exc_byte]))


def _request_pdu(event: ModbusEvent) -> Any:
    code = event.func_code
    if not is_standard_function(code):
        return _abnormal_request_pdu(event)
    if code in (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        return _READ_REQUEST[code](startAddr=event.address, quantity=event.quantity)
    if code == WRITE_SINGLE_REGISTER:
        return mb.ModbusPDU06WriteSingleRegisterRequest(
            registerAddr=event.address, registerValue=event.request_values[0]
        )
    if code == WRITE_SINGLE_COIL:
        return mb.ModbusPDU05WriteSingleCoilRequest(
            outputAddr=event.address,
            outputValue=_COIL_ON if event.request_values[0] else 0x0000,
        )
    if code == WRITE_MULTIPLE_REGISTERS:
        values = list(event.request_values)
        return mb.ModbusPDU10WriteMultipleRegistersRequest(
            startAddr=event.address,
            quantityRegisters=len(values),
            byteCount=2 * len(values),
            outputsValue=values,
        )
    if code == WRITE_MULTIPLE_COILS:
        packed = _pack_bits(event.request_values)
        return mb.ModbusPDU0FWriteMultipleCoilsRequest(
            startAddr=event.address,
            quantityOutput=len(event.request_values),
            byteCount=len(packed),
            outputsValue=packed,
        )
    raise ModbusError(f"no request encoder for function code {code:#04x}")


def _response_pdu(event: ModbusEvent) -> Any:
    code = event.func_code
    if event.is_exception:
        return _exception_response_pdu(event)
    if code in (READ_COILS, READ_DISCRETE_INPUTS):
        packed = _pack_bits(event.response_values)
        cls, status_field = _READ_BIT_RESPONSE[code]
        return cls(byteCount=len(packed), **{status_field: packed})
    if code in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        values = list(event.response_values)
        return _READ_REGISTER_RESPONSE[code](byteCount=2 * len(values), registerVal=values)
    if code == WRITE_SINGLE_REGISTER:
        return mb.ModbusPDU06WriteSingleRegisterResponse(
            registerAddr=event.address, registerValue=event.response_values[0]
        )
    if code == WRITE_SINGLE_COIL:
        return mb.ModbusPDU05WriteSingleCoilResponse(
            outputAddr=event.address,
            outputValue=_COIL_ON if event.response_values[0] else 0x0000,
        )
    if code == WRITE_MULTIPLE_REGISTERS:
        return mb.ModbusPDU10WriteMultipleRegistersResponse(
            startAddr=event.address, quantityRegisters=event.quantity
        )
    if code == WRITE_MULTIPLE_COILS:
        return mb.ModbusPDU0FWriteMultipleCoilsResponse(
            startAddr=event.address, quantityOutput=event.quantity
        )
    raise ModbusError(f"no response encoder for function code {code:#04x}")


# Function-code -> scapy PDU class tables for the uniform read shapes.
_READ_REQUEST: dict[int, Any] = {
    READ_COILS: mb.ModbusPDU01ReadCoilsRequest,
    READ_DISCRETE_INPUTS: mb.ModbusPDU02ReadDiscreteInputsRequest,
    READ_HOLDING_REGISTERS: mb.ModbusPDU03ReadHoldingRegistersRequest,
    READ_INPUT_REGISTERS: mb.ModbusPDU04ReadInputRegistersRequest,
}
_READ_BIT_RESPONSE: dict[int, tuple[Any, str]] = {
    READ_COILS: (mb.ModbusPDU01ReadCoilsResponse, "coilStatus"),
    READ_DISCRETE_INPUTS: (mb.ModbusPDU02ReadDiscreteInputsResponse, "inputStatus"),
}
_READ_REGISTER_RESPONSE: dict[int, Any] = {
    READ_HOLDING_REGISTERS: mb.ModbusPDU03ReadHoldingRegistersResponse,
    READ_INPUT_REGISTERS: mb.ModbusPDU04ReadInputRegistersResponse,
}


def _modbus_adu(event: ModbusEvent) -> Any:
    """Build the Modbus ADU (MBAP header + PDU) for one event."""
    if event.is_orig:
        return mb.ModbusADURequest(transId=event.tid, unitId=event.unit) / _request_pdu(event)
    return mb.ModbusADUResponse(transId=event.tid, unitId=event.unit) / _response_pdu(event)


def _mac(ipv4: str) -> str:
    """Deterministic locally-administered MAC derived from an IPv4 address."""
    octets = ipv4.split(".")
    return "02:00:" + ":".join(f"{int(o):02x}" for o in octets)


def _isn(key: str) -> int:
    """Deterministic 32-bit TCP initial sequence number."""
    return int.from_bytes(hashlib.blake2b(key.encode("utf-8"), digest_size=4).digest(), "big")


class _TcpFlow:
    """Tracks one connection's TCP state and emits well-formed segments.

    Sequence/acknowledgement numbers advance as real TCP does (SYN/FIN consume one
    number; data consumes its length), so the resulting stream reassembles cleanly.
    """

    def __init__(self, first: ModbusEvent) -> None:
        self.orig_h, self.orig_p = first.orig_h, first.orig_p
        self.resp_h, self.resp_p = first.resp_h, first.resp_p
        self.client_mac, self.server_mac = _mac(first.orig_h), _mac(first.resp_h)
        self.client_seq = _isn(f"{first.uid}>client")
        self.server_seq = _isn(f"{first.uid}>server")
        self.packets: list[Any] = []

    def _emit(
        self, *, from_client: bool, flags: str, when: float, payload: Any | None = None
    ) -> None:
        if from_client:
            frame = (
                Ether(src=self.client_mac, dst=self.server_mac)
                / IP(src=self.orig_h, dst=self.resp_h)
                / TCP(
                    sport=self.orig_p,
                    dport=self.resp_p,
                    flags=flags,
                    seq=self.client_seq,
                    ack=self.server_seq,
                )
            )
        else:
            frame = (
                Ether(src=self.server_mac, dst=self.client_mac)
                / IP(src=self.resp_h, dst=self.orig_h)
                / TCP(
                    sport=self.resp_p,
                    dport=self.orig_p,
                    flags=flags,
                    seq=self.server_seq,
                    ack=self.client_seq,
                )
            )
        consumed = 1 if ("S" in flags or "F" in flags) else 0
        if payload is not None:
            frame = frame / payload
            consumed += len(bytes(payload))
        frame.time = max(0.0, when)
        self.packets.append(frame)
        if from_client:
            self.client_seq = (self.client_seq + consumed) & 0xFFFFFFFF
        else:
            self.server_seq = (self.server_seq + consumed) & 0xFFFFFFFF

    def build(self, events: list[ModbusEvent]) -> list[Any]:
        start = events[0].ts
        end = events[-1].ts
        # Three-way handshake just before the first Modbus segment.
        self._emit(from_client=True, flags="S", when=start - _HANDSHAKE_GAP)
        self._emit(from_client=False, flags="SA", when=start - 2 * _HANDSHAKE_GAP / 3)
        self._emit(from_client=True, flags="A", when=start - _HANDSHAKE_GAP / 3)
        # One PSH/ACK per Modbus event, carrying the ADU; acks piggyback on data.
        for event in events:
            self._emit(
                from_client=event.is_orig,
                flags="PA",
                when=event.ts,
                payload=_modbus_adu(event),
            )
        # Graceful FIN teardown just after the last segment.
        self._emit(from_client=True, flags="FA", when=end + _TEARDOWN_GAP / 3)
        self._emit(from_client=False, flags="FA", when=end + 2 * _TEARDOWN_GAP / 3)
        self._emit(from_client=True, flags="A", when=end + _TEARDOWN_GAP)
        return self.packets


def write_pcap(events: Iterable[ModbusEvent], path: str | Path) -> int:
    """Write ``events`` as a Modbus/TCP capture to ``path``; return packet count.

    Events are grouped into per-connection TCP flows (by uid), each framed with a
    handshake, data segments and teardown, then all packets are written in
    timestamp order. An empty event list still yields a valid (header-only) PCAP.
    """
    by_connection: dict[str, list[ModbusEvent]] = {}
    for event in events:
        by_connection.setdefault(event.uid, []).append(event)

    packets: list[Any] = []
    for flow_events in by_connection.values():
        packets.extend(_TcpFlow(flow_events[0]).build(flow_events))
    # Stable sort by time keeps each flow's internal ordering on timestamp ties.
    packets.sort(key=lambda pkt: float(pkt.time))

    writer = PcapWriter(str(path), linktype=_DLT_EN10MB, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()
    return len(packets)
