"""Shared synthetic-TCP-stream PCAP framing for every protocol emitter.

Each protocol's PCAP emitter (Modbus, DNP3, S7comm) frames its protocol bytes on
the same synthetic but well-formed TCP stream: a SYN handshake just before the
first data segment, one PSH/ACK per protocol message, and a graceful FIN
teardown — with sequence/acknowledgement numbers tracked per connection so the
capture reassembles cleanly in Zeek/Wireshark for the Tier-2 fidelity check
(PRD §6.4). That framing used to be duplicated per emitter; this module is the
single home the per-protocol docstrings promised (``emit/_tcp.py``).

The per-protocol modules supply only a ``payload_for(event)`` callable mapping
one shared-model event to its wire payload (raw ``bytes`` or an assembled scapy
layer). Everything here is deterministic — MACs/ISNs are derived from the
connection uid via blake2b — so identical input yields byte-identical PCAP.
Writing uses scapy's ``PcapWriter`` (ordinary file I/O); no socket is ever
opened — see :mod:`substation.emit.guard`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Protocol, TypeVar

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

__all__ = ["FlowEvent", "write_flow_pcap"]

_DLT_EN10MB = 1  # Ethernet link-type for the PCAP global header.
# Small per-direction time offsets so handshake/teardown frames order around the
# protocol segments without colliding with their event timestamps.
_HANDSHAKE_GAP = 0.003
_TEARDOWN_GAP = 0.003


class FlowEvent(Protocol):
    """The envelope attributes every protocol's shared-model event carries."""

    @property
    def ts(self) -> float: ...
    @property
    def uid(self) -> str: ...
    @property
    def orig_h(self) -> str: ...
    @property
    def orig_p(self) -> int: ...
    @property
    def resp_h(self) -> str: ...
    @property
    def resp_p(self) -> int: ...
    @property
    def is_orig(self) -> bool: ...


_E = TypeVar("_E", bound=FlowEvent)


def _mac(ipv4: str) -> str:
    """Deterministic locally-administered MAC derived from an IPv4 address."""
    octets = ipv4.split(".")
    return "02:00:" + ":".join(f"{int(o):02x}" for o in octets)


def _isn(key: str) -> int:
    """Deterministic 32-bit TCP initial sequence number."""
    return int.from_bytes(hashlib.blake2b(key.encode("utf-8"), digest_size=4).digest(), "big")


class _TcpFlow:
    """Tracks one connection's TCP state and emits well-formed segments.

    Sequence/acknowledgement numbers advance as real TCP does (SYN/FIN consume
    one number; data consumes its length), so the stream reassembles cleanly.
    """

    def __init__(self, first: FlowEvent) -> None:
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
            layer = Raw(load=payload) if isinstance(payload, (bytes, bytearray)) else payload
            frame = frame / layer
            consumed += len(bytes(layer))
        frame.time = max(0.0, when)
        self.packets.append(frame)
        if from_client:
            self.client_seq = (self.client_seq + consumed) & 0xFFFFFFFF
        else:
            self.server_seq = (self.server_seq + consumed) & 0xFFFFFFFF

    def build(self, events: list[_E], payload_for: Callable[[_E], Any]) -> list[Any]:
        start = events[0].ts
        end = events[-1].ts
        # Three-way handshake just before the first data segment.
        self._emit(from_client=True, flags="S", when=start - _HANDSHAKE_GAP)
        self._emit(from_client=False, flags="SA", when=start - 2 * _HANDSHAKE_GAP / 3)
        self._emit(from_client=True, flags="A", when=start - _HANDSHAKE_GAP / 3)
        # One PSH/ACK per protocol event; acks piggyback on data.
        for event in events:
            self._emit(
                from_client=event.is_orig, flags="PA", when=event.ts, payload=payload_for(event)
            )
        # Graceful FIN teardown just after the last segment.
        self._emit(from_client=True, flags="FA", when=end + _TEARDOWN_GAP / 3)
        self._emit(from_client=False, flags="FA", when=end + 2 * _TEARDOWN_GAP / 3)
        self._emit(from_client=True, flags="A", when=end + _TEARDOWN_GAP)
        return self.packets


def write_flow_pcap(
    events: Iterable[_E], path: str | Path, payload_for: Callable[[_E], Any]
) -> int:
    """Write ``events`` as a TCP capture to ``path``; return the packet count.

    Events are grouped into per-connection TCP flows (by uid), each framed with a
    handshake, data segments and teardown, then all packets are written in
    timestamp order. An empty event list still yields a valid (header-only) PCAP.
    """
    by_connection: dict[str, list[_E]] = {}
    for event in events:
        by_connection.setdefault(event.uid, []).append(event)

    packets: list[Any] = []
    for flow_events in by_connection.values():
        packets.extend(_TcpFlow(flow_events[0]).build(flow_events, payload_for))
    # Stable sort by time keeps each flow's internal ordering on timestamp ties.
    packets.sort(key=lambda pkt: float(pkt.time))

    writer = PcapWriter(str(path), linktype=_DLT_EN10MB, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()
    return len(packets)
