"""PCAP emitter: shared DNP3 events -> hand-built DNP3/TCP ``.pcap``.

Consumes the **same** :class:`~substation.protocols.dnp3.Dnp3Event` list as the JSON
emitter (PRD §6.1: one model, dual emit, no drift). scapy ships no DNP3 layer (spike
05), so this module assembles the DNP3 data-link / transport / application bytes
itself — with the CRC verified against a real capture
(:func:`substation.protocols.dnp3.dnp3_crc`). The synthetic TCP framing (handshake,
PSH/ACK segments, teardown) is the shared :mod:`substation.emit._tcp` scaffold.
Output is deterministic: identical input yields byte-identical PCAP. Writing uses
scapy's ``PcapWriter`` (ordinary file I/O); no socket is ever opened — see
:mod:`substation.emit.guard`.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from substation.emit import _tcp
from substation.protocols.dnp3 import (
    OBJECT_TYPES,
    RESPONSE,
    UNSOLICITED_RESPONSE,
    Dnp3Event,
    dnp3_crc,
)

__all__ = ["write_pcap"]

_DNP3_START = b"\x05\x64"

# Inverse of the CROB label tables (dnp3.py) so the encoder can rebuild the wire
# control_code byte from the schema-clean detail.control labels.
_OP_CODE = {"Nul": 0, "Pulse_On": 1, "Pulse_Off": 2, "Latch_On": 3, "Latch_Off": 4}
_TRIP_CODE = {"Nul": 0, "Close": 1, "Trip": 2}


def _object_group_var(event: Dnp3Event) -> tuple[int, int, int]:
    """Resolve (group, variation, point_size) for this event's object type.

    Derived from the **same** ``detail.objects.object_type`` string the JSON carries
    (validated against OBJECT_TYPES at build time), so the PCAP group/variation and
    the JSON object_type cannot drift (PR #9 review).
    """
    object_type = str((event.objects or {}).get("object_type", ""))
    return OBJECT_TYPES[object_type]  # build_events guarantees membership.


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


def _read_request_objects(event: Dnp3Event) -> bytes:
    """A 'read all' object header for the event's object type (qualifier 0x06)."""
    group, var, _ = _object_group_var(event)
    return bytes([group, var, 0x06])


def _range_objects(event: Dnp3Event) -> bytes:
    """A 2-byte start/stop range object header (qualifier 0x01) for a response.

    Uses a **2-byte** range so addresses/counts up to 65535 round-trip (PR #9
    review). The point count and data width come from the event's object type, so the
    emitted object body matches the JSON object_count exactly.
    """
    group, var, point_size = _object_group_var(event)
    objs = event.objects or {}
    low = int(objs.get("range_low", 0)) & 0xFFFF
    high = int(objs.get("range_high", 0)) & 0xFFFF
    count = max(0, high - low + 1)
    header = bytes([group, var, 0x01]) + low.to_bytes(2, "little") + high.to_bytes(2, "little")
    # One deterministic zero-filled point per index, at the variation's data width.
    return header + bytes(count * point_size)


def _crob_objects(event: Dnp3Event) -> bytes:
    """A Control-Relay-Output-Block object (group 12 var 1, qualifier 0x28).

    Qualifier 0x28 carries a **2-byte** object count and a **2-byte** index prefix, so
    control indices up to 65535 round-trip (PR #9 review).
    """
    ctl = event.control or {}
    op = _OP_CODE.get(str(ctl.get("operation_type", "Nul")), 0)
    trip = _TRIP_CODE.get(str(ctl.get("trip_control_code", "Nul")), 0)
    clear = 0x20 if ctl.get("clear_bit") else 0x00
    control_code = (trip << 6) | clear | op
    index = int(ctl.get("index_number", 0)) & 0xFFFF
    count = int(ctl.get("execute_count", 1)) & 0xFF
    on_time = int(ctl.get("on_time", 0)) & 0xFFFFFFFF
    off_time = int(ctl.get("off_time", 0)) & 0xFFFFFFFF
    crob = (
        bytes([control_code, count])
        + on_time.to_bytes(4, "little")
        + off_time.to_bytes(4, "little")
        + bytes([0x00])  # status (commanded request)
    )
    # qualifier 0x28: 2-byte object count, each prefixed by a 2-byte index.
    return (
        bytes([0x0C, 0x01, 0x28]) + (1).to_bytes(2, "little") + index.to_bytes(2, "little") + crob
    )


def _app_bytes(event: Dnp3Event) -> bytes:
    """Application-layer bytes: app control + function code + (iin) + objects."""
    # FIR+FIN application fragment (single-fragment messages); seq left 0 for
    # determinism — Zeek's fc logging keys on the header, not the sequence.
    app_control = 0xC0
    out = bytes([app_control, event.func_code])
    if not event.is_orig:  # responses (RESPONSE / UNSOLICITED_RESPONSE) carry IIN.
        out += int(event.iin or 0).to_bytes(2, "little")
    if event.is_orig and event.control is not None:
        out += _crob_objects(event)
    elif event.is_orig and event.objects is not None:
        # READ/WRITE/unsolicited-config requests: object header from the shared
        # OBJECT_TYPES mapping (same string the JSON detail carries).
        out += _read_request_objects(event)
    elif event.func_code in (RESPONSE, UNSOLICITED_RESPONSE) and event.objects:
        out += _range_objects(event)
    return out


def _dnp3_pdu(event: Dnp3Event) -> bytes:
    """Full DNP3 frame (link + transport + application) for one event."""
    transport = 0xC0  # FIR+FIN single-segment transport header.
    user = bytes([transport]) + _app_bytes(event)
    return _link_frame(
        from_master=event.is_orig, src_addr=event.src_addr, dst_addr=event.dst_addr, user=user
    )


def write_pcap(events: Iterable[Dnp3Event], path: str | Path) -> int:
    """Write ``events`` as a DNP3/TCP capture to ``path``; return packet count.

    Events are grouped into per-connection TCP flows (by uid), each framed with a
    handshake, data segments and teardown, then written in timestamp order. An empty
    event list still yields a valid (header-only) PCAP.
    """
    return _tcp.write_pcap(events, path, _dnp3_pdu)
