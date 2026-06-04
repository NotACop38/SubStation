"""S7comm/S7comm-plus semantics shared by the JSON and PCAP emitters (PRD §6.1, §6.4).

:func:`build_events` turns a loaded :class:`~substation.scenarios.Scenario` into an
ordered list of :class:`S7Event` — the **single intermediate model both emitters
consume**, so the PCAP and JSON artifacts cannot drift (the LOCKED core design
principle, PRD §6.1). This mirrors ``substation.protocols.dnp3`` exactly; only the
protocol semantics differ.

This module is pure Python and protocol-semantic only. :func:`event_to_dict` maps an
event to the ICSNPP-aligned envelope + S7 ``detail`` (``docs/schema.md``); the PCAP
emitter (:mod:`substation.emit.s7comm_pcap`) maps the same events to hand-built
TPKT/COTP/S7comm wire bytes (scapy ships no S7 layer — spike 07). Keeping the
semantic model here, importing no scapy, means JSON-only consumers never pull a
packet library.

Function/sub-function names, ROSCTR names, COTP PDU names, SZL-ID names, block types
and s7comm-plus opcodes/functions are the verified ICSNPP ``consts.zeek`` spellings
(``docs/spikes/06-icsnpp-s7comm-fields.md``) — taken from the authoritative source,
never invented from memory (CLAUDE.md VERIFY gate). S7comm/-plus have no open spec
(PRD §9), so the ICSNPP parser and the Wireshark dissector are the references.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from substation.scenarios import Actor, ActorRole, Protocol, Scenario

__all__ = [
    "S7Error",
    "S7Event",
    "build_events",
    "event_to_dict",
    "resolve_function",
    "S7COMM_FUNCTIONS",
    "ROSCTR_NAMES",
    "USERDATA_FUNCTIONS",
    "S7COMM_PLUS_OPCODES",
    "S7COMM_PLUS_FUNCTIONS",
    "SZL_ID_NAMES",
    "DEFAULT_S7_PORT",
    "RESPONSE_DELAY",
]

DEFAULT_S7_PORT = 102  # S7comm/COTP/TPKT well-known TCP port (ICSNPP main.zeek).
# Synthetic PLC turnaround between a request and its response (seconds).
RESPONSE_DELAY = 0.05
_EPHEMERAL_BASE = 49152  # IANA dynamic/ephemeral client-port range start.

# --- verified ICSNPP value tables (consts.zeek; spike 06) --------------------

# ROSCTR (Remote Operating Service Control) names (rosctr_types).
ROSCTR_JOB = 0x01
ROSCTR_ACK = 0x02
ROSCTR_ACK_DATA = 0x03
ROSCTR_USERDATA = 0x07
ROSCTR_NAMES: dict[int, str] = {
    0x01: "Job-Request",
    0x02: "ACK",
    0x03: "ACK-Data",
    0x07: "User-Data",
}

# Parameter function codes / names (s7comm_functions).
S7COMM_FUNCTIONS: dict[int, str] = {
    0x00: "CPU Services",
    0x04: "Read Variable",
    0x05: "Write Variable",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}

# User-Data function groups (s7comm_userdata_functions).
USERDATA_FUNCTIONS: dict[int, str] = {
    0x00: "Mode-Transition",
    0x01: "Programmer Controls",
    0x02: "Cyclic Services",
    0x03: "Block Functions",
    0x04: "CPU Functions",
    0x05: "Security",
    0x06: "PBC BSEND-BRECV",
    0x07: "Time Functions",
    0x0F: "NC Programming",
}

# COTP PDU type names keyed by the PDU-type high nibble (cotp_pdu_types).
COTP_PDU_NAMES: dict[int, str] = {
    0x0D: "CC Connection Confirm",
    0x0E: "CR Connection Request",
    0x0F: "DT Data",
}
_COTP_CR = 0x0E
_COTP_CC = 0x0D

# s7comm-plus opcodes / functions (s7comm_plus_opcodes / s7comm_plus_functions).
S7COMM_PLUS_OPCODES: dict[int, str] = {0x31: "Request", 0x32: "Response", 0x33: "Notification"}
S7COMM_PLUS_FUNCTIONS: dict[int, str] = {
    0x04BB: "Explore",
    0x04CA: "Create Object",
    0x04D4: "Delete Object",
    0x04F2: "Set Variable",
    0x0524: "Get Link",
    0x0542: "Set Multi Variables",
    0x054C: "Get Multi Variables",
}

# SZL-ID meanings (s7comm_szl_id), keyed by szl_id & 0xff. Subset our scenarios use.
SZL_ID_NAMES: dict[int, str] = {
    0x00: "List of all the SZL-IDs of a module",
    0x11: "Module identification",
    0x12: "CPU characteristics",
    0x13: "User memory areas",
    0x14: "System areas",
    0x15: "Block types",
    0x1C: "Component Identification",
    0x24: "Modes",
    0x91: "Module status information",
    0xA0: "Diagnostic buffer of the CPU",
}

# Block types (s7comm_block_types), keyed by the 2-char hex code ICSNPP logs.
BLOCK_TYPES: dict[str, str] = {
    "08": "Organization Block",
    "0A": "Data Block",
    "0B": "System Data Block",
    "0C": "Function",
    "0D": "System Function",
    "0E": "Function Block",
    "0F": "System Function Block",
}

# PLC Control services (s7comm_plc_control_services); the start/stop service S1 keys on.
PLC_CONTROL_SERVICES: dict[str, str] = {
    "P_PROGRAM": "PLC Start / Stop",
    "_MODU": "PLC Copy Ram to Rom",
    "_GARB": "Compress PLC memory",
    "_INSE": "Activates a PLC module",
    "_DELE": "Removes module from the PLC's passive file system",
}

# --- scenario function vocabulary --------------------------------------------

# Job functions: token -> (function_byte, func_name, action_class).
_JOB_OPS: dict[str, tuple[int, str, str]] = {
    "setupcommunication": (0xF0, "Setup Communication", "diagnostic"),
    "readvariable": (0x04, "Read Variable", "read"),
    "writevariable": (0x05, "Write Variable", "write"),
    "plcstop": (0x29, "PLC Stop", "control"),
    "plccontrol": (0x28, "PLC Control", "control"),
    "requestdownload": (0x1A, "Request Download", "write"),
    "downloadblock": (0x1B, "Download Block", "write"),
    "downloadended": (0x1C, "Download Ended", "write"),
    "startupload": (0x1D, "Start Upload", "read"),
    "upload": (0x1E, "Upload", "read"),
    "endupload": (0x1F, "End Upload", "read"),
}
# Job functions whose detail carries an upload_download sub-object (s7comm_upload_download.log).
_UPLOAD_DOWNLOAD_FUNCS = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
# Download functions carry a block spec (filename/type/number) in their request.
_DOWNLOAD_BLOCK_FUNCS = {0x1A, 0x1B}

# User-Data functions: token -> (ud_function_group, subfunction, subfunction_name, action_class).
_USERDATA_OPS: dict[str, tuple[int, int, str, str]] = {
    "readszl": (0x04, 0x01, "Read SZL", "diagnostic"),
    "listblocks": (0x03, 0x01, "List Blocks", "diagnostic"),
    "listblocksoftype": (0x03, 0x02, "List Blocks of Type", "diagnostic"),
    "getblockinfo": (0x03, 0x03, "Get Block Info", "diagnostic"),
}

# s7comm-plus functions: token -> (plus_function_code, action_class).
_PLUS_OPS: dict[str, tuple[int, str]] = {
    "explore": (0x04BB, "diagnostic"),
    "createobject": (0x04CA, "write"),
    "setvariable": (0x04F2, "write"),
    "deleteobject": (0x04D4, "write"),
}

_MASTER_ROLES = {ActorRole.MASTER, ActorRole.HMI, ActorRole.EWS}
_PLC_ROLES = {ActorRole.OUTSTATION, ActorRole.PLC}

_U16 = 0xFFFF


class S7Error(ValueError):
    """Raised when a scenario cannot be encoded as S7 telemetry."""


@dataclass(frozen=True, slots=True)
class S7Event:
    """One S7 message (COTP / S7comm / S7comm-plus) — the unit both emitters consume.

    A COTP handshake expands to two events (CR then CC); an application exchange
    expands to a request event and a matched response event sharing a connection
    (``uid`` + 4-tuple). Both emitters read the very same objects, which is what
    guarantees PCAP and JSON cannot drift. ``detail`` is the JSON-shaped detail dict;
    the remaining fields are the byte-level hints the PCAP encoder rebuilds the wire
    PDU from (both derived from one computation in :func:`build_events`).
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
    proto_kind: str  # "cotp" | "s7comm" | "s7comm_plus"
    detail: Mapping[str, Any]
    # --- PCAP wire hints (encoder only) ---
    rosctr: int | None = None
    s7_function: int | None = None
    subfunction: int | None = None
    szl_id: int | None = None
    szl_index: int | None = None
    plc_control: str | None = None
    block_filename: str | None = None
    plus_opcode: int | None = None
    plus_function: int | None = None
    cotp_pdu: int | None = None  # full COTP PDU-type byte for the wire (0xe0 / 0xd0)
    pdu_reference: int | None = None

    @property
    def direction(self) -> str:
        """``request`` when from the originator, else ``response`` (schema-aligned)."""
        return "request" if self.is_orig else "response"


# --- function-name resolution (mirrors dnp3.resolve_function) ----------------


def _normalize_function(name: str) -> str:
    """Collapse a function label to a comparison token (case/separator-insensitive)."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def resolve_function(function: str) -> str:
    """Resolve a scenario ``function`` string to a supported S7 operation token.

    Accepts spaced/CamelCase spellings (``Read SZL``, ``PlcStop``, ``Request
    Download``, ``Explore``). Raises :class:`S7Error` for anything not in the
    supported vocabulary.
    """
    token = _normalize_function(function)
    if token in _JOB_OPS or token in _USERDATA_OPS or token in _PLUS_OPS:
        return token
    supported = sorted({*_JOB_OPS, *_USERDATA_OPS, *_PLUS_OPS})
    raise S7Error(f"unsupported S7 function {function!r}; supported tokens: {', '.join(supported)}")


# --- param parsing -----------------------------------------------------------


def _opt_int(
    params: Mapping[str, object], key: str, where: str, lo: int, hi: int, default: int
) -> int:
    if key not in params:
        return default
    value = params[key]
    # bool is an int subclass; an SZL id / index is never a bool.
    if isinstance(value, bool) or not isinstance(value, int):
        raise S7Error(f"{where}.{key}: expected an integer")
    if not lo <= value <= hi:
        raise S7Error(f"{where}.{key}: {value} out of range ({lo}-{hi})")
    return value


def _opt_str(params: Mapping[str, object], key: str, where: str, default: str) -> str:
    if key not in params:
        return default
    value = params[key]
    if not isinstance(value, str) or not value:
        raise S7Error(f"{where}.{key}: expected a non-empty string")
    return value


# --- connection bookkeeping (mirrors dnp3) -----------------------------------

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
        raise S7Error(
            f"actor {actor_id!r} host {host!r} is not an IPv4 address "
            "(S7comm/TCP PCAP emission requires IPv4)"
        ) from None
    return host


@dataclass(slots=True)
class _Conn:
    """A simulated persistent S7comm/TCP connection (client/master originator)."""

    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    last_response_ts: float = float("-inf")
    pdu_ref: int = 0
    handshaken: bool = False

    def next_pdu_ref(self) -> int:
        # S7comm pdu reference is 16-bit; cycle 1..65535 per connection.
        self.pdu_ref = self.pdu_ref % _U16 + 1
        return self.pdu_ref


def _connection(conns: dict[tuple[str, str], _Conn], master: Actor, plc: Actor) -> _Conn:
    key = (master.id, plc.id)
    conn = conns.get(key)
    if conn is None:
        orig_h = _ipv4(master.host, master.id)
        resp_h = _ipv4(plc.host, plc.id)
        resp_p = plc.port if plc.port is not None else DEFAULT_S7_PORT
        orig_p = _EPHEMERAL_BASE + len(conns)
        if orig_p > _U16:
            raise S7Error("too many distinct connections for the ephemeral port range")
        conn = _Conn(
            uid=_zeek_uid(f"{orig_h}:{orig_p}>{resp_h}:{resp_p}"),
            orig_h=orig_h,
            orig_p=orig_p,
            resp_h=resp_h,
            resp_p=resp_p,
        )
        conns[key] = conn
    return conn


def _orient(src: Actor, dst: Actor, where: str) -> tuple[Actor, Actor, bool]:
    """Return (master, plc, src_is_master), classifying actors by role."""
    if src.role in _MASTER_ROLES and dst.role in _PLC_ROLES:
        return src, dst, True
    if src.role in _PLC_ROLES and dst.role in _MASTER_ROLES:
        return dst, src, False
    raise S7Error(
        f"{where}: an S7 exchange must be between a client-class actor "
        f"({', '.join(r.value for r in _MASTER_ROLES)}) and a PLC-class actor "
        f"({', '.join(r.value for r in _PLC_ROLES)}); got {src.role.value} -> {dst.role.value}"
    )


def build_events(scenario: Scenario) -> list[S7Event]:
    """Expand an S7 scenario into the ordered shared event list.

    Each (master, plc) connection opens with a COTP Connection Request / Confirm
    handshake (emitted once, on first use). Each scenario exchange then becomes a
    request event plus a matched response event. Both emitters consume the returned
    list verbatim, so the PCAP and JSON cannot drift (PRD §6.1).
    """
    if scenario.protocol is not Protocol.S7COMM:
        raise S7Error(f"build_events: expected an s7comm scenario, got {scenario.protocol.value}")
    actors = {a.id: a for a in scenario.actors}
    conns: dict[tuple[str, str], _Conn] = {}
    events: list[S7Event] = []
    prev_base_ts: float | None = None

    for idx, exchange in enumerate(scenario.exchanges):
        where = f"exchanges[{idx}] ({exchange.function})"
        token = resolve_function(exchange.function)
        src = actors[exchange.source]
        dst = actors[exchange.target]
        master, plc, src_is_master = _orient(src, dst, where)
        if not src_is_master:
            raise S7Error(
                f"{where}: an S7 request must originate from the client/master "
                f"({master.id}), not the PLC ({plc.id})"
            )
        conn = _connection(conns, master, plc)

        if exchange.offset is not None:
            base_ts = scenario.timing.start + exchange.offset
        elif prev_base_ts is None:
            base_ts = scenario.timing.start
        else:
            base_ts = prev_base_ts + scenario.timing.default_interval
        prev_base_ts = base_ts
        # Serialize per-connection so a message never precedes the previous one's
        # completion (keeps each flow causally ordered; same rule as Modbus/DNP3).
        msg_ts = max(base_ts, conn.last_response_ts)

        # On first use of a connection, open it with a COTP CR/CC handshake.
        if not conn.handshaken:
            cr_ts = msg_ts
            cc_ts = msg_ts + RESPONSE_DELAY / 2
            events.append(_cotp_event(conn, ts=cr_ts, is_orig=True, pdu=_COTP_CR))
            events.append(_cotp_event(conn, ts=cc_ts, is_orig=False, pdu=_COTP_CC))
            conn.handshaken = True
            conn.last_response_ts = cc_ts
            msg_ts = max(base_ts, conn.last_response_ts)

        if token in _JOB_OPS:
            _append_job(events, conn, token, exchange.params, msg_ts, where)
        elif token in _USERDATA_OPS:
            _append_userdata(events, conn, token, exchange.params, msg_ts, where)
        else:
            _append_plus(events, conn, token, exchange.params, msg_ts, where)

    return events


# --- COTP / S7comm / S7comm-plus event builders ------------------------------


def _cotp_event(conn: _Conn, *, ts: float, is_orig: bool, pdu: int) -> S7Event:
    """A COTP Connection Request / Confirm event (cotp.log)."""
    return S7Event(
        ts=ts,
        uid=conn.uid,
        orig_h=conn.orig_h,
        orig_p=conn.orig_p,
        resp_h=conn.resp_h,
        resp_p=conn.resp_p,
        is_orig=is_orig,
        func_code=pdu,
        func_name=COTP_PDU_NAMES[pdu],
        action_class="other",
        proto_kind="cotp",
        detail={"cotp": {"pdu_code": f"0x{pdu:02x}", "pdu_name": COTP_PDU_NAMES[pdu]}},
        cotp_pdu=(pdu << 4),  # wire PDU-type byte: 0xe -> 0xe0 (CR), 0xd -> 0xd0 (CC)
    )


def _append_job(
    events: list[S7Event],
    conn: _Conn,
    token: str,
    params: Mapping[str, object],
    ts: float,
    where: str,
) -> None:
    function, func_name, action_class = _JOB_OPS[token]
    pdu_ref = conn.next_pdu_ref()

    subfunction_code: str | None = None
    subfunction_name: str | None = None
    plc_control: str | None = None
    upload_download: dict[str, Any] | None = None
    block_filename: str | None = None

    if function == 0x28:  # PLC Control: subfunction carries the control service.
        plc_control = _opt_str(params, "service", where, "P_PROGRAM")
        subfunction_code = plc_control
        subfunction_name = PLC_CONTROL_SERVICES.get(plc_control, "unknown")
    if function in _UPLOAD_DOWNLOAD_FUNCS:
        upload_download = {"rosctr": ROSCTR_NAMES[ROSCTR_JOB], "function_name": func_name}
        if function in _DOWNLOAD_BLOCK_FUNCS:
            block_type_code = _opt_str(params, "block_type", where, "0A").upper()
            if block_type_code not in BLOCK_TYPES:
                raise S7Error(
                    f"{where}.block_type: unknown S7 block type {block_type_code!r}; "
                    f"valid: {', '.join(sorted(BLOCK_TYPES))}"
                )
            block_number = _opt_str(params, "block_number", where, "00001")
            block_filename = f"_{block_type_code}{block_number}P"
            upload_download.update(
                {
                    "filename": block_filename,
                    "block_type": BLOCK_TYPES[block_type_code],
                    "block_number": block_number,
                    "destination_filesystem": "Passive",
                }
            )

    req_detail = _s7_detail(
        rosctr=ROSCTR_JOB,
        pdu_reference=pdu_ref,
        function=function,
        function_name=func_name,
        subfunction_code=subfunction_code,
        subfunction_name=subfunction_name,
        upload_download=upload_download,
    )
    events.append(
        S7Event(
            ts=ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=True,
            func_code=function,
            func_name=func_name,
            action_class=action_class,
            proto_kind="s7comm",
            detail=req_detail,
            rosctr=ROSCTR_JOB,
            s7_function=function,
            plc_control=plc_control,
            block_filename=block_filename,
            pdu_reference=pdu_ref,
        )
    )

    # Matched ACK-Data response (rosctr 0x03). PLC Control's subfunction is request-only.
    resp_ud = None
    if upload_download is not None:
        resp_ud = {
            "rosctr": ROSCTR_NAMES[ROSCTR_ACK_DATA],
            "function_name": func_name,
            "function_status": "0x00",
        }
    resp_ts = ts + RESPONSE_DELAY
    resp_detail = _s7_detail(
        rosctr=ROSCTR_ACK_DATA,
        pdu_reference=pdu_ref,
        function=function,
        function_name=func_name,
        upload_download=resp_ud,
    )
    events.append(
        S7Event(
            ts=resp_ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=False,
            func_code=function,
            func_name=func_name,
            action_class=action_class,
            proto_kind="s7comm",
            detail=resp_detail,
            rosctr=ROSCTR_ACK_DATA,
            s7_function=function,
            pdu_reference=pdu_ref,
        )
    )
    conn.last_response_ts = resp_ts


def _append_userdata(
    events: list[S7Event],
    conn: _Conn,
    op_key: str,
    params: Mapping[str, object],
    ts: float,
    where: str,
) -> None:
    ud_group, subfunction, subfunction_name, action_class = _USERDATA_OPS[op_key]
    pdu_ref = conn.next_pdu_ref()
    req_func = 0x40 | ud_group  # request nibble (0x4) | group  -> e.g. 0x44 CPU Functions
    resp_func = 0x80 | ud_group  # response nibble (0x8) | group -> e.g. 0x84
    req_name = f"Request: {USERDATA_FUNCTIONS[ud_group]}"
    resp_name = f"Response: {USERDATA_FUNCTIONS[ud_group]}"

    szl_id = _opt_int(params, "szl_id", where, 0, _U16, 0x0011)
    szl_index = _opt_int(params, "szl_index", where, 0, _U16, 0x0000)
    is_read_szl = op_key == "readszl"

    req_read_szl = None
    resp_read_szl = None
    if is_read_szl:
        req_read_szl = _read_szl_detail(szl_id, szl_index, method="Request")
        resp_read_szl = _read_szl_detail(
            szl_id, szl_index, method="Response", return_code="0xff", return_code_name="Success"
        )

    req_detail = _s7_detail(
        rosctr=ROSCTR_USERDATA,
        pdu_reference=pdu_ref,
        function=req_func,
        function_name=req_name,
        subfunction_code=f"0x{subfunction:02x}",
        subfunction_name=subfunction_name,
        read_szl=req_read_szl,
    )
    events.append(
        S7Event(
            ts=ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=True,
            func_code=req_func,
            func_name=req_name,
            action_class=action_class,
            proto_kind="s7comm",
            detail=req_detail,
            rosctr=ROSCTR_USERDATA,
            s7_function=req_func,
            subfunction=subfunction,
            szl_id=szl_id if is_read_szl else None,
            szl_index=szl_index if is_read_szl else None,
            pdu_reference=pdu_ref,
        )
    )

    resp_ts = ts + RESPONSE_DELAY
    resp_detail = _s7_detail(
        rosctr=ROSCTR_USERDATA,
        pdu_reference=pdu_ref,
        function=resp_func,
        function_name=resp_name,
        subfunction_code=f"0x{subfunction:02x}",
        subfunction_name=subfunction_name,
        read_szl=resp_read_szl,
    )
    events.append(
        S7Event(
            ts=resp_ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=False,
            func_code=resp_func,
            func_name=resp_name,
            action_class=action_class,
            proto_kind="s7comm",
            detail=resp_detail,
            rosctr=ROSCTR_USERDATA,
            s7_function=resp_func,
            subfunction=subfunction,
            szl_id=szl_id if is_read_szl else None,
            szl_index=szl_index if is_read_szl else None,
            pdu_reference=pdu_ref,
        )
    )
    conn.last_response_ts = resp_ts


def _append_plus(
    events: list[S7Event],
    conn: _Conn,
    token: str,
    params: Mapping[str, object],
    ts: float,
    where: str,
) -> None:
    plus_function, action_class = _PLUS_OPS[token]
    func_name = S7COMM_PLUS_FUNCTIONS[plus_function]
    version = _opt_int(params, "version", where, 1, 3, 3)

    req_detail = _plus_detail(version, opcode=0x31, function=plus_function)
    events.append(
        S7Event(
            ts=ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=True,
            func_code=0x31,
            func_name=func_name,
            action_class=action_class,
            proto_kind="s7comm_plus",
            detail=req_detail,
            plus_opcode=0x31,
            plus_function=plus_function,
        )
    )
    resp_ts = ts + RESPONSE_DELAY
    resp_detail = _plus_detail(version, opcode=0x32, function=plus_function)
    events.append(
        S7Event(
            ts=resp_ts,
            uid=conn.uid,
            orig_h=conn.orig_h,
            orig_p=conn.orig_p,
            resp_h=conn.resp_h,
            resp_p=conn.resp_p,
            is_orig=False,
            func_code=0x32,
            func_name=func_name,
            action_class=action_class,
            proto_kind="s7comm_plus",
            detail=resp_detail,
            plus_opcode=0x32,
            plus_function=plus_function,
        )
    )
    conn.last_response_ts = resp_ts


# --- detail builders (JSON shape; ICSNPP-aligned, spike 06) ------------------


def _s7_detail(
    *,
    rosctr: int,
    pdu_reference: int,
    function: int,
    function_name: str,
    subfunction_code: str | None = None,
    subfunction_name: str | None = None,
    read_szl: dict[str, Any] | None = None,
    upload_download: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the s7comm.log-aligned detail dict (omitting absent optional fields)."""
    detail: dict[str, Any] = {
        "rosctr_code": rosctr,
        "rosctr_name": ROSCTR_NAMES[rosctr],
        "pdu_reference": pdu_reference,
        "function_code": f"0x{function:02x}",
        "function_name": function_name,
    }
    if subfunction_code is not None:
        detail["subfunction_code"] = subfunction_code
    if subfunction_name is not None:
        detail["subfunction_name"] = subfunction_name
    if read_szl is not None:
        detail["read_szl"] = read_szl
    if upload_download is not None:
        detail["upload_download"] = upload_download
    return detail


def _read_szl_detail(
    szl_id: int,
    szl_index: int,
    *,
    method: str,
    return_code: str | None = None,
    return_code_name: str | None = None,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "method": method,
        "szl_id": f"0x{szl_id:04x}",
        "szl_id_name": SZL_ID_NAMES.get(szl_id & 0xFF, "Unknown"),
        "szl_index": f"0x{szl_index:04x}",
    }
    if return_code is not None:
        detail["return_code"] = return_code
    if return_code_name is not None:
        detail["return_code_name"] = return_code_name
    return detail


def _plus_detail(version: int, *, opcode: int, function: int) -> dict[str, Any]:
    return {
        "plus": {
            "version": version,
            "opcode": f"0x{opcode:02x}",
            "opcode_name": S7COMM_PLUS_OPCODES[opcode],
            "function_code": f"0x{function:04x}",
            "function_name": S7COMM_PLUS_FUNCTIONS[function],
        }
    }


def event_to_dict(event: S7Event) -> dict[str, Any]:
    """Render one S7 event as the schema's envelope + S7 ``detail`` dict."""
    return {
        "ts": event.ts,
        "uid": event.uid,
        "conn": {
            "orig_h": event.orig_h,
            "orig_p": event.orig_p,
            "resp_h": event.resp_h,
            "resp_p": event.resp_p,
        },
        "proto": "s7comm",
        "is_orig": event.is_orig,
        "direction": event.direction,
        "func_code": event.func_code,
        "func_name": event.func_name,
        "action_class": event.action_class,
        "is_exception": False,  # S7 v1 surfaces errors via detail.error_*, not exceptions.
        "error": None,
        "detail": _deepcopy_detail(event.detail),
    }


def _deepcopy_detail(detail: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a detail mapping one level deep so the emitted dict owns its sub-objects."""
    out: dict[str, Any] = {}
    for key, value in detail.items():
        out[key] = dict(value) if isinstance(value, Mapping) else value
    return out
