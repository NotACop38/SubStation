"""PCAP emitter: shared S7 events -> hand-built TPKT/COTP/S7comm ``.pcap``.

Consumes the **same** :class:`~substation.protocols.s7comm.S7Event` list as the JSON
emitter (PRD §6.1: one model, dual emit, no drift). scapy ships no S7/COTP/TPKT layer
(spike 07), so this module assembles the TPKT, COTP and S7comm/S7comm-plus bytes
itself — with the framing and S7 header layout verified against ICSNPP's example
captures — and frames them on a synthetic but well-formed TCP stream (SYN handshake,
PSH/ACK segments, FIN teardown) via scapy's generic ``Ether``/``IP``/``TCP``. Output
is deterministic: identical input yields byte-identical PCAP. Writing uses scapy's
``PcapWriter`` (ordinary file I/O); no socket is ever opened — see
:mod:`substation.emit.guard`.

NB: the synthetic-TCP-stream framing mirrors the Modbus/DNP3 emitters' ``_TcpFlow``;
the duplication is intentional and flagged as friction for ``docs/adding-a-protocol.md``
(a shared ``emit/_tcp.py`` is the eventual home — spike 07).
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

from substation.protocols.s7comm import S7Event

__all__ = ["write_pcap"]

_DLT_EN10MB = 1  # Ethernet link-type for the PCAP global header.
_HANDSHAKE_GAP = 0.003
_TEARDOWN_GAP = 0.003

_COTP_DT = b"\x02\xf0\x80"  # COTP DT (data) header: length 2, PDU type 0xf0, EOT 0x80.
# COTP connection params verified against s7ident.pcap (TPDU size + TSAP selectors).
_COTP_CONN_PARAMS = b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x01"
_S7_PROTO_ID = 0x32
_S7PLUS_PROTO_ID = 0x72


def _tpkt(payload: bytes) -> bytes:
    """Wrap ``payload`` in a TPKT (RFC 1006) header: ``03 00 LEN(2 big-endian)``."""
    total = len(payload) + 4
    return b"\x03\x00" + total.to_bytes(2, "big") + payload


def _cotp_cr_cc(event: S7Event) -> bytes:
    """A COTP Connection Request / Confirm PDU (verified layout, spike 07)."""
    pdu = int(event.cotp_pdu or 0)  # 0xe0 (CR) / 0xd0 (CC)
    dst_ref = b"\x00\x00" if pdu == 0xE0 else b"\x00\x01"
    src_ref = b"\x00\x01"
    body = bytes([pdu]) + dst_ref + src_ref + b"\x00" + _COTP_CONN_PARAMS
    cotp = bytes([len(body)]) + body  # length indicator counts the bytes after itself
    return _tpkt(cotp)


def _s7_header(rosctr: int, pdu_ref: int, param: bytes, data: bytes, *, is_response: bool) -> bytes:
    """Assemble the S7comm header + parameter + data (10- or 12-byte header)."""
    header = (
        bytes([_S7_PROTO_ID, rosctr])
        + b"\x00\x00"  # redundancy identification
        + pdu_ref.to_bytes(2, "big")
        + len(param).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
    )
    if rosctr in (0x02, 0x03):  # ACK / ACK-Data carry a 2-byte error class/code.
        header += b"\x00\x00"
    return header + param + data


def _job_param_data(event: S7Event) -> tuple[bytes, bytes]:
    """Build the (parameter, data) bytes for a Job / ACK-Data S7comm message.

    Each parameter begins with the verified function-code byte — the field ICSNPP's
    s7comm.log keys function_name on (spike 06/07).
    """
    func = int(event.s7_function or 0)
    is_resp = not event.is_orig
    if func == 0xF0:  # Setup Communication
        return b"\xf0\x00\x00\x01\x00\x01\x01\xe0", b""
    if func == 0x04:  # Read Variable
        if is_resp:
            return b"\x04\x01", b"\xff\x04\x00\x10\x00\x00"
        return b"\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00", b""
    if func == 0x05:  # Write Variable
        if is_resp:
            return b"\x05\x01", b"\xff"
        return (
            b"\x05\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00",
            b"\x00\x04\x00\x10\x00\x01",
        )
    if func == 0x29:  # PLC Stop: function + 5 reserved + len + "P_PROGRAM"
        service = b"P_PROGRAM"
        return bytes([0x29, 0, 0, 0, 0, 0, len(service)]) + service, b""
    if func == 0x28:  # PLC Control: carries the control service string (spike 06)
        service = (event.plc_control or "P_PROGRAM").encode("ascii")
        param = (
            bytes([0x28, 0, 0, 0, 0, 0, 0, 0xFD]) + b"\x00\x00" + bytes([len(service)]) + service
        )
        return param + b"\x00", b""
    if func in (0x1A, 0x1B):  # Request Download / Download Block: block file spec
        head = bytes([func, 0, 0, 0, 0, 0, 0x01, 0x00])
        if event.block_filename:
            fn = event.block_filename.encode("ascii")
            return head + bytes([len(fn)]) + fn, b""
        return head, b""
    if func in (0x1C, 0x1D, 0x1E, 0x1F):  # Download Ended / uploads
        return bytes([func, 0, 0, 0, 0, 0, 0x01, 0x00]), b""
    # CPU Services / any other Job function: a bare function byte is enough to decode.
    return bytes([func]), b""


def _userdata_param_data(event: S7Event) -> tuple[bytes, bytes]:
    """Build the (parameter, data) bytes for a User-Data S7comm message.

    The Read-SZL request parameter/data match snap7.pcap exactly (spike 07).
    """
    func = int(event.s7_function or 0)
    subfunction = int(event.subfunction or 0)
    if event.is_orig:
        param = b"\x00\x01\x12\x04\x11" + bytes([func, subfunction, 0x00])
    else:
        param = b"\x00\x01\x12\x08\x12" + bytes([func, subfunction, 0x00, 0x00, 0x00, 0x00])
    if event.szl_id is not None:
        data = (
            b"\xff\x09\x00\x04"
            + int(event.szl_id).to_bytes(2, "big")
            + int(event.szl_index or 0).to_bytes(2, "big")
        )
    else:
        data = b"\xff\x09\x00\x00"
    return param, data


def _s7comm_pdu(event: S7Event) -> bytes:
    """Full TPKT + COTP DT + S7comm frame for one S7comm event."""
    if event.rosctr == 0x07:
        param, data = _userdata_param_data(event)
    else:
        param, data = _job_param_data(event)
    s7 = _s7_header(
        int(event.rosctr or 0),
        int(event.pdu_reference or 0),
        param,
        data,
        is_response=not event.is_orig,
    )
    return _tpkt(_COTP_DT + s7)


def _s7plus_pdu(event: S7Event) -> bytes:
    """Full TPKT + COTP DT + S7comm-plus frame (plaintext header, spike 07)."""
    opcode = int(event.plus_opcode or 0x31)
    function = int(event.plus_function or 0)
    # Plaintext s7comm-plus data: opcode(1) reserved(2) function(2) reserved(2) seq(2).
    inner = bytes([opcode]) + b"\x00\x00" + function.to_bytes(2, "big") + b"\x00\x00\x00\x00"
    body = (
        bytes([_S7PLUS_PROTO_ID, 0x03])
        + len(inner).to_bytes(2, "big")
        + inner
        + b"\x00\x72\x00\x00"
    )
    return _tpkt(_COTP_DT + body)


def _pdu_bytes(event: S7Event) -> bytes:
    if event.proto_kind == "cotp":
        return _cotp_cr_cc(event)
    if event.proto_kind == "s7comm_plus":
        return _s7plus_pdu(event)
    return _s7comm_pdu(event)


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

    def __init__(self, first: S7Event) -> None:
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

    def build(self, events: list[S7Event]) -> list[Any]:
        start = events[0].ts
        end = events[-1].ts
        self._emit(from_client=True, flags="S", when=start - _HANDSHAKE_GAP)
        self._emit(from_client=False, flags="SA", when=start - 2 * _HANDSHAKE_GAP / 3)
        self._emit(from_client=True, flags="A", when=start - _HANDSHAKE_GAP / 3)
        for event in events:
            self._emit(
                from_client=event.is_orig, flags="PA", when=event.ts, payload=_pdu_bytes(event)
            )
        self._emit(from_client=True, flags="FA", when=end + _TEARDOWN_GAP / 3)
        self._emit(from_client=False, flags="FA", when=end + 2 * _TEARDOWN_GAP / 3)
        self._emit(from_client=True, flags="A", when=end + _TEARDOWN_GAP)
        return self.packets


def write_pcap(events: Iterable[S7Event], path: str | Path) -> int:
    """Write ``events`` as a TPKT/COTP/S7comm capture to ``path``; return packet count.

    Events are grouped into per-connection TCP flows (by uid), each framed with a
    handshake, data segments and teardown, then written in timestamp order. An empty
    event list still yields a valid (header-only) PCAP.
    """
    by_connection: dict[str, list[S7Event]] = {}
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
