"""PCAP emitter: shared DNP3 events -> hand-built DNP3/TCP ``.pcap``.

Consumes the **same** :class:`~substation.protocols.dnp3.Dnp3Event` list as the JSON
emitter (PRD §6.1: one model, dual emit, no drift). scapy ships no DNP3 layer (spike
05), so this module assembles the DNP3 data-link / transport / application bytes
itself — with the CRC verified against a real capture
(:func:`substation.protocols.dnp3.dnp3_crc`) — and frames them on a synthetic but
well-formed TCP stream (SYN handshake, PSH/ACK segments, FIN teardown) via scapy's
generic ``Ether``/``IP``/``TCP``. Output is deterministic: identical input yields
byte-identical PCAP. Writing uses scapy's ``PcapWriter`` (ordinary file I/O); no
socket is ever opened — see :mod:`substation.emit.guard`.

NB: the synthetic-TCP-stream framing mirrors the Modbus emitter's ``_TcpFlow``; the
duplication is intentional and flagged as friction for ``docs/adding-a-protocol.md``
(a shared ``emit/_tcp.py`` is the eventual home).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from substation.protocols.dnp3 import (
    READ,
    RESPONSE,
    UNSOLICITED_RESPONSE,
    Dnp3Event,
    dnp3_crc,
)

__all__ = ["write_pcap"]

_DLT_EN10MB = 1  # Ethernet link-type for the PCAP global header.
_DNP3_START = b"\x05\x64"
_HANDSHAKE_GAP = 0.003
_TEARDOWN_GAP = 0.003

# Inverse of the CROB label tables (dnp3.py) so the encoder can rebuild the wire
# control_code byte from the schema-clean detail.control labels.
_OP_CODE = {"Nul": 0, "Pulse_On": 1, "Pulse_Off": 2, "Latch_On": 3, "Latch_Off": 4}
_TRIP_CODE = {"Nul": 0, "Close": 1, "Trip": 2}


def _link_frame(*, from_master: bool, src_addr: int, dst_addr: int, user: bytes) -> bytes:
    """Assemble one DNP3 data-link frame: header (+CRC) and CRC'd 16-byte data blocks."""
    length = 5 + len(user)  # CTRL + DEST + SRC + user data (spike 05); excludes CRCs.
    if length > 255:
        # Single-segment frames only; our synthetic PDUs never approach this.
        raise ValueError("DNP3 link frame user data exceeds a single 255-byte frame")
    ctrl = 0xC4 if from_master else 0x44  # PRM=1, UNCONFIRMED_USER_DATA(4), DIR bit.
    header = (
        _DNP3_START
        + bytes([length, ctrl])
        + dst_addr.to_bytes(2, "little")
        + src_addr.to_bytes(2, "little")
    )
    header += dnp3_crc(header).to_bytes(2, "little")
    body = b""
    for i in range(0, len(user), 16):
        block = user[i : i + 16]
        body += block + dnp3_crc(block).to_bytes(2, "little")
    return header + body


def _read_request_objects() -> bytes:
    """A 'read all of group 1 var 0' object header (qualifier 0x06, no range)."""
    return bytes([0x01, 0x00, 0x06])


def _range_objects(event: Dnp3Event, *, group: int, var: int) -> bytes:
    """An 8-bit start/stop range object header for a READ response (qualifier 0x00)."""
    objs = event.objects or {}
    low = int(objs.get("range_low", 0)) & 0xFF
    high = int(objs.get("range_high", 0)) & 0xFF
    count = max(0, high - low + 1)
    # header + one status/value byte per index (deterministic 0x00 fill).
    return bytes([group, var, 0x00, low, high]) + bytes(count)


def _crob_objects(event: Dnp3Event) -> bytes:
    """A Control-Relay-Output-Block object (group 12 var 1, qualifier 0x17)."""
    ctl = event.control or {}
    op = _OP_CODE.get(str(ctl.get("operation_type", "Nul")), 0)
    trip = _TRIP_CODE.get(str(ctl.get("trip_control_code", "Nul")), 0)
    clear = 0x20 if ctl.get("clear_bit") else 0x00
    control_code = (trip << 6) | clear | op
    index = int(ctl.get("index_number", 0)) & 0xFF
    count = int(ctl.get("execute_count", 1)) & 0xFF
    on_time = int(ctl.get("on_time", 0)) & 0xFFFFFFFF
    off_time = int(ctl.get("off_time", 0)) & 0xFFFFFFFF
    crob = (
        bytes([control_code, count])
        + on_time.to_bytes(4, "little")
        + off_time.to_bytes(4, "little")
        + bytes([0x00])  # status (commanded request)
    )
    # qualifier 0x17: 1-byte object count, each prefixed by a 1-byte index.
    return bytes([0x0C, 0x01, 0x17, 0x01, index]) + crob


def _app_bytes(event: Dnp3Event) -> bytes:
    """Application-layer bytes: app control + function code + (iin) + objects."""
    # FIR+FIN application fragment (single-fragment messages); seq left 0 for
    # determinism — Zeek's fc logging keys on the header, not the sequence.
    app_control = 0xC0
    out = bytes([app_control, event.func_code])
    if not event.is_orig:  # responses (RESPONSE / UNSOLICITED_RESPONSE) carry IIN.
        out += int(event.iin or 0).to_bytes(2, "little")
    if event.is_orig and event.func_code == READ:
        out += _read_request_objects()
    elif event.func_code in (RESPONSE, UNSOLICITED_RESPONSE) and event.objects:
        out += _range_objects(event, group=0x01, var=0x02)
    elif event.is_orig and event.control is not None:
        out += _crob_objects(event)
    return out


def _dnp3_pdu(event: Dnp3Event) -> bytes:
    """Full DNP3 frame (link + transport + application) for one event."""
    transport = 0xC0  # FIR+FIN single-segment transport header.
    user = bytes([transport]) + _app_bytes(event)
    return _link_frame(
        from_master=event.is_orig, src_addr=event.src_addr, dst_addr=event.dst_addr, user=user
    )


def _mac(ipv4: str) -> str:
    octets = ipv4.split(".")
    return "02:00:" + ":".join(f"{int(o):02x}" for o in octets)


def _isn(key: str) -> int:
    return int.from_bytes(hashlib.blake2b(key.encode("utf-8"), digest_size=4).digest(), "big")


class _TcpFlow:
    """Tracks one connection's TCP state and emits well-formed segments.

    Sequence/acknowledgement numbers advance as real TCP does (SYN/FIN consume one;
    data consumes its length), so the stream reassembles cleanly for Tier-2 Zeek.
    """

    def __init__(self, first: Dnp3Event) -> None:
        self.orig_h, self.orig_p = first.orig_h, first.orig_p
        self.resp_h, self.resp_p = first.resp_h, first.resp_p
        self.client_mac, self.server_mac = _mac(first.orig_h), _mac(first.resp_h)
        self.client_seq = _isn(f"{first.uid}>client")
        self.server_seq = _isn(f"{first.uid}>server")
        self.packets: list[Any] = []

    def _emit(
        self, *, from_client: bool, flags: str, when: float, payload: bytes | None = None
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
            frame = frame / Raw(load=payload)
            consumed += len(payload)
        frame.time = max(0.0, when)
        self.packets.append(frame)
        if from_client:
            self.client_seq = (self.client_seq + consumed) & 0xFFFFFFFF
        else:
            self.server_seq = (self.server_seq + consumed) & 0xFFFFFFFF

    def build(self, events: list[Dnp3Event]) -> list[Any]:
        start = events[0].ts
        end = events[-1].ts
        self._emit(from_client=True, flags="S", when=start - _HANDSHAKE_GAP)
        self._emit(from_client=False, flags="SA", when=start - 2 * _HANDSHAKE_GAP / 3)
        self._emit(from_client=True, flags="A", when=start - _HANDSHAKE_GAP / 3)
        for event in events:
            self._emit(
                from_client=event.is_orig, flags="PA", when=event.ts, payload=_dnp3_pdu(event)
            )
        self._emit(from_client=True, flags="FA", when=end + _TEARDOWN_GAP / 3)
        self._emit(from_client=False, flags="FA", when=end + 2 * _TEARDOWN_GAP / 3)
        self._emit(from_client=True, flags="A", when=end + _TEARDOWN_GAP)
        return self.packets


def write_pcap(events: Iterable[Dnp3Event], path: str | Path) -> int:
    """Write ``events`` as a DNP3/TCP capture to ``path``; return packet count.

    Events are grouped into per-connection TCP flows (by uid), each framed with a
    handshake, data segments and teardown, then written in timestamp order. An empty
    event list still yields a valid (header-only) PCAP.
    """
    by_connection: dict[str, list[Dnp3Event]] = {}
    for event in events:
        by_connection.setdefault(event.uid, []).append(event)

    packets: list[Any] = []
    for flow_events in by_connection.values():
        packets.extend(_TcpFlow(flow_events[0]).build(flow_events))
    packets.sort(key=lambda pkt: float(pkt.time))

    writer = PcapWriter(str(path), linktype=_DLT_EN10MB, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()
    return len(packets)
