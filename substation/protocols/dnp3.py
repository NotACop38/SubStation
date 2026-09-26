"""DNP3 semantics shared by the JSON and PCAP emitters (docs/design.md §6.1, §6.4).

:func:`build_events` turns a loaded :class:`~substation.scenarios.Scenario` into an
ordered list of :class:`Dnp3Event` — the **single intermediate model both emitters
consume**, with independent parser checks for agreement (docs/design.md §6.1).
This mirrors ``substation.protocols.modbus``; only the
protocol semantics differ.

This module is pure Python and protocol-semantic only. :func:`event_to_dict` maps an
event to the ICSNPP-aligned envelope + DNP3 ``detail`` (``docs/schema.md``); the PCAP
emitter (:mod:`substation.emit.dnp3_pcap`) maps the same events to hand-built DNP3
wire bytes (scapy ships no DNP3 layer — spike 05). Keeping the semantic model here,
importing no scapy, means JSON-only consumers never pull a packet library.

Function-code names are the verified Zeek ``DNP3::function_codes`` spellings
(``docs/spikes/04-icsnpp-dnp3-fields.md``); numeric codes are IEEE 1815 / DNP3 —
taken from the verified source, never invented from memory (AGENTS.md VERIFY gate).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from substation.protocols import _common
from substation.scenarios import Actor, ActorRole, Protocol, Scenario

__all__ = [
    "Dnp3Error",
    "Dnp3Event",
    "build_events",
    "event_to_dict",
    "resolve_function",
    "function_name",
    "control_code",
    "FUNCTION_NAMES",
    "CLASS_OBJECTS",
    "CONTROL_STATUS",
    "ACTION_CLASS",
    "OBJECT_TYPES",
    "DEFAULT_DNP3_PORT",
    "RESPONSE_DELAY",
    "dnp3_crc",
    "object_payload_size",
]

DEFAULT_DNP3_PORT = 20000  # DNP3/TCP well-known port (Zeek base/protocols/dnp3).
# Synthetic outstation turnaround between a request and its response (seconds).
RESPONSE_DELAY = 0.05

# DNP3 application function codes (Zeek DNP3::function_codes, consts.zeek — spike 04).
CONFIRM = 0x00
READ = 0x01
WRITE = 0x02
SELECT = 0x03
OPERATE = 0x04
DIRECT_OPERATE = 0x05
DIRECT_OPERATE_NR = 0x06
COLD_RESTART = 0x0D
WARM_RESTART = 0x0E
ENABLE_UNSOLICITED = 0x14
DISABLE_UNSOLICITED = 0x15
ASSIGN_CLASS = 0x16
DELAY_MEASURE = 0x17
RECORD_CURRENT_TIME = 0x18
AUTHENTICATE_REQ = 0x20
RESPONSE = 0x81
UNSOLICITED_RESPONSE = 0x82
AUTHENTICATE_RESP = 0x83
# Request codes run 0x00-0x7F; codes absent from the table are named "unknown-N"
# as Zeek's DNP3::function_codes does. An outstation answers them with IIN2.0.
_MAX_REQUEST_CODE = 0x7F
IIN_NO_FUNC_CODE_SUPPORT = 0x0001  # IIN2.0 in Zeek's numeric IIN representation.

# Application-control octet (IEEE 1815 §4.2.2.4): FIR | FIN | CON | UNS | SEQ.
_FIR_FIN = 0xC0
_CON = 0x20
_UNS = 0x10

# code -> Zeek ``DNP3::function_codes`` name (verified, spike 04). The full table is
# carried so func_name resolves for any code a scenario references.
FUNCTION_NAMES: dict[int, str] = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x03: "SELECT",
    0x04: "OPERATE",
    0x05: "DIRECT_OPERATE",
    0x06: "DIRECT_OPERATE_NR",
    0x07: "IMMED_FREEZE",
    0x08: "IMMED_FREEZE_NR",
    0x09: "FREEZE_CLEAR",
    0x0A: "FREEZE_CLEAR_NR",
    0x0B: "FREEZE_AT_TIME",
    0x0C: "FREEZE_AT_TIME_NR",
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x0F: "INITIALIZE_DATA",
    0x10: "INITIALIZE_APPL",
    0x11: "START_APPL",
    0x12: "STOP_APPL",
    0x13: "SAVE_CONFIG",
    0x14: "ENABLE_UNSOLICITED",
    0x15: "DISABLE_UNSOLICITED",
    0x16: "ASSIGN_CLASS",
    0x17: "DELAY_MEASURE",
    0x18: "RECORD_CURRENT_TIME",
    0x19: "OPEN_FILE",
    0x1A: "CLOSE_FILE",
    0x1B: "DELETE_FILE",
    0x1C: "GET_FILE_INFO",
    0x1D: "AUTHENTICATE_FILE",
    0x1E: "ABORT_FILE",
    0x1F: "ACTIVATE_CONFIG",
    0x20: "AUTHENTICATE_REQ",
    0x21: "AUTHENTICATE_REQ_NR",
    0x81: "RESPONSE",
    0x82: "UNSOLICITED_RESPONSE",
    0x83: "AUTHENTICATE_RESP",
}

# code -> normalized action_class for request functions (docs/schema.md
# "action_class mapping (DNP3)"). Output/process/device control and reporting-config
# commands all normalize to ``control``; the per-command detections (D1/D2/D3) key on
# the specific ``func_name``, so the broad class never over-fires.
ACTION_CLASS: dict[int, str] = {
    READ: "read",
    WRITE: "write",
    SELECT: "control",
    OPERATE: "control",
    DIRECT_OPERATE: "control",
    DIRECT_OPERATE_NR: "control",
    COLD_RESTART: "control",
    WARM_RESTART: "control",
    ENABLE_UNSOLICITED: "control",
    DISABLE_UNSOLICITED: "control",
    DELAY_MEASURE: "diagnostic",
    RECORD_CURRENT_TIME: "diagnostic",
    0x07: "read",  # IMMED_FREEZE — freeze counters for subsequent reading.
    0x09: "write",  # FREEZE_CLEAR — clears frozen counters.
    0x11: "control",  # START_APPL
    0x12: "control",  # STOP_APPL
    0x16: "control",  # ASSIGN_CLASS — configures event-class assignment.
    0x1C: "read",  # GET_FILE_INFO
    UNSOLICITED_RESPONSE: "read",  # standalone telemetry: data-bearing, like a read.
}

# Application response function codes: these may never be authored as a bare scenario
# exchange. ``UNSOLICITED_RESPONSE`` is the one outstation-initiated message and is
# handled specially; ``RESPONSE``/``AUTHENTICATE_RESP`` are only ever synthesized as
# the reply to a master request. Any other code 0x00-0x7F is a master request,
# including undefined ones, so D4 scenarios can model a scanner probing them.
_RESPONSE_CODES = {RESPONSE, UNSOLICITED_RESPONSE, AUTHENTICATE_RESP}
# Request functions a compliant outstation does NOT answer with a RESPONSE — the
# ``*_NR`` ("no response") variants (Zeek consts.zeek, spike 04).
_NO_RESPONSE = {CONFIRM, DIRECT_OPERATE_NR, 0x08, 0x0A, 0x0C, 0x21}
# Functions whose request carries a Control-Relay-Output-Block (detail.control).
_CONTROL_BLOCK_FUNCS = {SELECT, OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR}
# CROB status codes an outstation returns in its echoed control block (ICSNPP
# control_block_status_codes).
CONTROL_STATUS = {"Success": 0x00, "No Select": 0x02, "Not Supported": 0x04}

_MASTER_ROLES = {ActorRole.MASTER, ActorRole.HMI, ActorRole.EWS}
_OUTSTATION_ROLES = {ActorRole.OUTSTATION, ActorRole.PLC}

# CROB control-code sub-fields (verified value strings, spike 04 / ICSNPP README).
_OPERATION_TYPES = {  # operation_type string -> low nibble of control_code.
    "NUL": 0,
    "PULSE_ON": 1,
    "PULSE_OFF": 2,
    "LATCH_ON": 3,
    "LATCH_OFF": 4,
}
_TRIP_CODES = {  # trip_control_code string -> top two bits of control_code.
    "NUL": 0,
    "CLOSE": 1,
    "TRIP": 2,
}
# ICSNPP consts.zeek uses spaces (its README previously showed underscores).
# Scenario input accepts either spelling; output follows the parser's table.
_OPERATION_LABEL = {0: "Nul", 1: "Pulse On", 2: "Pulse Off", 3: "Latch On", 4: "Latch Off"}
_TRIP_LABEL = {0: "Nul", 1: "Close", 2: "Trip"}
# Interoperable CROB control codes, ignoring the clear bit: Nul, Pulse On, Latch
# On/Off, Close + Pulse On and Trip + Pulse On. Pulse Off and other Close/Trip
# combinations are non-interoperable; an outstation answers "Not Supported".
# Source: opendnp3 ControlCode.h (citing IEEE 1815 pp. 506-510), checked 2026-09-26.
_INTEROPERABLE_CONTROL_CODES = {0x00, 0x01, 0x03, 0x04, 0x41, 0x81}

# DNP3 object groups/variations for the object types our scenarios use. Keyed by the
# **exact ICSNPP `dnp3_objects` device-type name** (consts.zeek, keyed by
# group*256+variation — spike 04), so the JSON `object_type` string and the PCAP
# group/variation are derived from one source and a Zeek decode of the PCAP resolves
# the same name (no drift, docs/design.md §6.1). `point_size` is the per-point response data
# width in bytes for that variation, so the PCAP emits a well-formed object body.
#
# VERIFY (Tier-2 fidelity, 2026-06-04): the "with-flag" variations (groups 20/30
# var 1/2) carry a LEADING 1-octet flag before the value, so their per-point width
# is flag + value, NOT value alone. Zeek's DNP3 binpac decoder confirmed this by
# raising `out_of_bound: AnalogInput16wFlag` when the body was one octet short per
# point. Widths below are flag(1) + value: g30v2 16-bit = 3, g30v1 32-bit = 5,
# g20v2 16-bit counter = 3. g01v2 binary-input-with-flags is a single packed octet.
# name -> (group, variation, point_size)
OBJECT_TYPES: dict[str, tuple[int, int, int]] = {
    "Binary Input With Status": (0x01, 0x02, 1),  # 0x0102 (flags octet)
    "Binary Output": (0x0A, 0x01, 1),  # packed bits; see object_payload_size
    "16-Bit Binary Counter": (0x14, 0x02, 3),  # 0x1402 with flag: flag(1)+u16(2)
    "32-Bit Analog Input": (0x1E, 0x01, 5),  # 0x1E01 with flag: flag(1)+i32(4)
    "16-Bit Analog Input": (0x1E, 0x02, 3),  # 0x1E02 with flag: flag(1)+i16(2)
    # Analog output blocks (ICSNPP consts.zeek dnp3_objects, verified 2026-07-26).
    # Decoder fixtures read them; the control model itself only emits CROBs.
    "16-Bit Analog Output Block": (0x29, 0x02, 3),  # value(2) + status(1)
    "32-Bit Analog Output Block": (0x29, 0x01, 5),  # value(4) + status(1)
    # Class data (group 60): request-only headers, qualifier 0x06, no point data.
    # ICSNPP dnp3_objects 0x3C01-0x3C04 (verified 2026-09-26).
    "Class 0 Data": (0x3C, 0x01, 0),
    "Class 1 Data": (0x3C, 0x02, 0),
    "Class 2 Data": (0x3C, 0x03, 0),
    "Class 3 Data": (0x3C, 0x04, 0),
}
CLASS_OBJECTS = frozenset({"Class 0 Data", "Class 1 Data", "Class 2 Data", "Class 3 Data"})
_EVENT_CLASSES = CLASS_OBJECTS - {"Class 0 Data"}


def object_payload_size(object_type: str, count: int) -> int:
    """Encoded size of zero-valued fixture points, including packed/status data."""
    group, variation, width = OBJECT_TYPES[object_type]
    if (group, variation) == (0x0A, 0x01):
        return (count + 7) // 8
    return count * width


_DEFAULT_OBJECT_TYPE = "Binary Input With Status"
# Request functions that carry a DNP3 object header, with the object types each may
# name and its default. Unsolicited-reporting configuration and class assignment
# address event classes (IEEE 1815: group 60 variations 2-4); READ takes static or
# class objects; class objects cannot be written.
_OBJECT_REQUEST_FUNCS: dict[int, tuple[frozenset[str], str]] = {
    READ: (frozenset(OBJECT_TYPES), _DEFAULT_OBJECT_TYPE),
    WRITE: (frozenset(OBJECT_TYPES) - CLASS_OBJECTS, _DEFAULT_OBJECT_TYPE),
    ENABLE_UNSOLICITED: (_EVENT_CLASSES, "Class 1 Data"),
    DISABLE_UNSOLICITED: (_EVENT_CLASSES, "Class 1 Data"),
    ASSIGN_CLASS: (_EVENT_CLASSES, "Class 1 Data"),
}
# Params accepted on object-carrying exchanges (request + optional response range).
_OBJECT_PARAM_KEYS = {
    "object_type",
    "object_count",
    "range_low",
    "range_high",
    "iin",
}
# A class READ is answered with static data: name its type to model that data.
_READ_PARAM_KEYS = _OBJECT_PARAM_KEYS | {"response_object_type"}
_CONTROL_PARAM_KEYS = {
    "operation_type",
    "trip_control_code",
    "clear_bit",
    "index_number",
    "execute_count",
    "on_time",
    "off_time",
    "iin",
}

_U16 = 0xFFFF
_U8 = 0xFF
_U32 = 0xFFFFFFFF

# The DNP3 PCAP emitter intentionally emits one data-link frame per event. The
# link-frame length field is one octet and covers CTRL + DEST + SRC + user data,
# so synthetic response object bodies must fit within 250 bytes of user data.
# Response user data is transport(1) + app_control(1) + function(1) + IIN(2) +
# 2-byte range object header(7), leaving 238 bytes for point payloads.
_DNP3_SINGLE_LINK_MAX_USER_DATA = 250
_DNP3_RESPONSE_FIXED_USER_BYTES = 12
_DNP3_RESPONSE_MAX_POINT_BYTES = _DNP3_SINGLE_LINK_MAX_USER_DATA - _DNP3_RESPONSE_FIXED_USER_BYTES


class Dnp3Error(ValueError):
    """Raised when a scenario cannot be encoded as DNP3 telemetry."""


@dataclass(frozen=True, slots=True)
class Dnp3Event:
    """One DNP3 application message — the unit both emitters consume.

    A solicited exchange expands to two events (master request then outstation
    RESPONSE) sharing a connection (``uid`` + 4-tuple); an unsolicited response is a
    single outstation-originated event. Both emitters read the same objects;
    Tier 2 independently checks message identity and supported details.
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
    # DNP3 link-layer addresses and the application-control octet, for the PCAP
    # encoder only (neither appears in the JSON envelope).
    src_addr: int
    dst_addr: int
    app_control: int
    # detail (docs/schema.md DNP3 detail; all optional, mirroring Zeek/ICSNPP).
    fc_request: str | None = None
    fc_reply: str | None = None
    iin: int | None = None
    control: Mapping[str, Any] | None = None
    objects: Mapping[str, Any] | None = None

    @property
    def direction(self) -> str:
        """``request`` when from the originator, else ``response`` (schema-aligned)."""
        return "request" if self.is_orig else "response"


# --- function-name resolution (mirrors modbus.resolve_function) ---------------

_FUNCTION_BY_TOKEN: dict[str, int] = {
    _common.normalize_function(label): code for code, label in FUNCTION_NAMES.items()
}


def function_name(code: int) -> str:
    """Zeek's name for a function code: the table name, else ``unknown-N``."""
    return FUNCTION_NAMES.get(code, f"unknown-{code}")


def resolve_function(function: str) -> int:
    """Resolve a scenario ``function`` string to a DNP3 application function code.

    Accepts the Zeek name (``COLD_RESTART``), a CamelCase/spaced spelling
    (``ColdRestart``), or a numeric code (``13`` / ``0x0d``). A numeric code may
    also be an undefined request code (``0x22``-``0x7f``), which Zeek names
    ``unknown-N``. Raises :class:`Dnp3Error` for anything else.
    """
    token = _common.normalize_function(function)
    if token in _FUNCTION_BY_TOKEN:
        return _FUNCTION_BY_TOKEN[token]
    raw = function.strip().lower()
    try:
        code = int(raw, 16) if raw.startswith("0x") else int(raw)
    except ValueError:
        code = -1
    if code in FUNCTION_NAMES or 0 <= code <= _MAX_REQUEST_CODE:
        return code
    raise Dnp3Error(
        f"unsupported DNP3 function {function!r}; use a name "
        f"({', '.join(FUNCTION_NAMES[c] for c in sorted(FUNCTION_NAMES))}) or a numeric "
        f"request code 0..{_MAX_REQUEST_CODE}"
    )


# --- DNP3 data-link CRC (verified against real frames, spike 05) --------------


def dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16 over ``data`` (reflected poly 0xA6BC, init 0, final XOR 0xFFFF).

    Verified against four real frames from ICSNPP's ``dnp3_example.pcap``
    (``docs/spikes/05-scapy-dnp3-capability.md``). Result is transmitted low-byte
    first by the encoder.
    """
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & _U16


# --- param parsing ------------------------------------------------------------


def _opt_int(
    params: Mapping[str, object], key: str, where: str, lo: int, hi: int, default: int
) -> int:
    return _common.opt_int(params, key, where, lo, hi, default, error=Dnp3Error)


def _opt_str(params: Mapping[str, object], key: str, where: str, default: str) -> str:
    return _common.opt_str(params, key, where, default, error=Dnp3Error)


def _opt_bool(params: Mapping[str, object], key: str, where: str, default: bool) -> bool:
    return _common.opt_bool(params, key, where, default, error=Dnp3Error)


def _enum(value: str, table: dict[str, int], where: str) -> int:
    key = value.strip().upper().replace(" ", "_")
    if key not in table:
        raise Dnp3Error(f"{where}: unknown value {value!r}; valid: {', '.join(sorted(table))}")
    return table[key]


def _control_detail(params: Mapping[str, object], func_name: str, where: str) -> dict[str, Any]:
    """Build the detail.control (CROB) sub-object from scenario params.

    Field names + value strings mirror ICSNPP ``dnp3_control.log`` (spike 04).
    """
    op_code = _enum(
        _opt_str(params, "operation_type", where, "LATCH_ON"),
        _OPERATION_TYPES,
        f"{where}.operation_type",
    )
    trip_code = _enum(
        _opt_str(params, "trip_control_code", where, "NUL"),
        _TRIP_CODES,
        f"{where}.trip_control_code",
    )
    clear = _opt_bool(params, "clear_bit", where, False)
    return {
        "block_type": "Control Relay Output Block",
        "function_code": func_name,
        "index_number": _opt_int(params, "index_number", where, 0, _U16, 0),
        "trip_control_code": _TRIP_LABEL[trip_code],
        "operation_type": _OPERATION_LABEL[op_code],
        "clear_bit": clear,
        "execute_count": _opt_int(params, "execute_count", where, 0, _U8, 1),
        "on_time": _opt_int(params, "on_time", where, 0, _U32, 0),
        "off_time": _opt_int(params, "off_time", where, 0, _U32, 0),
    }


def _reject_unknown_params(params: Mapping[str, object], allowed: set[str], where: str) -> None:
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise Dnp3Error(f"{where}: unknown/unused param(s) {unknown}; allowed: {sorted(allowed)}")


def _object_type(
    params: Mapping[str, object], key: str, where: str, allowed: frozenset[str], default: str
) -> str:
    """Read an object-type param and check it is valid for this message."""
    object_type = _opt_str(params, key, where, default)
    if object_type not in OBJECT_TYPES:
        raise Dnp3Error(
            f"{where}.{key}: unknown DNP3 object type {object_type!r}; "
            f"supported: {', '.join(sorted(OBJECT_TYPES))}"
        )
    if object_type not in allowed:
        raise Dnp3Error(
            f"{where}.{key}: {object_type!r} is not valid here; valid: {', '.join(sorted(allowed))}"
        )
    return object_type


_DATA_OBJECTS = frozenset(OBJECT_TYPES) - CLASS_OBJECTS


def _response_objects(
    params: Mapping[str, object], func_name: str, object_type: str, where: str
) -> dict[str, Any]:
    """Build the detail.objects sub-object for a data-bearing response.

    Field names follow ICSNPP ``dnp3_objects.log`` (spike 04). ``object_count`` is the
    range span (``range_high - range_low + 1``); an explicit ``object_count`` that
    disagrees is rejected rather than emitted, so the JSON count and the PCAP object
    body always agree.
    """
    range_low = _opt_int(params, "range_low", where, 0, _U16, 0)
    range_high = _opt_int(params, "range_high", where, 0, _U16, 0)
    if range_high < range_low:
        raise Dnp3Error(f"{where}: range_high ({range_high}) must be >= range_low ({range_low})")
    span = range_high - range_low + 1
    object_count = _opt_int(params, "object_count", where, 0, _U16, span)
    if object_count != span:
        raise Dnp3Error(
            f"{where}.object_count ({object_count}) must equal the range span "
            f"range_high - range_low + 1 = {span}; the PCAP object body is derived "
            "from the range, so an inconsistent count cannot be emitted"
        )
    if object_payload_size(object_type, span) > _DNP3_RESPONSE_MAX_POINT_BYTES:
        raise Dnp3Error(
            f"{where}: range span {span} point(s) for {object_type!r} exceeds "
            f"the single-frame DNP3 PCAP limit of {_DNP3_RESPONSE_MAX_POINT_BYTES} "
            "point payload bytes; split the response into smaller ranges"
        )
    return {
        "function_code": func_name,
        "object_type": object_type,
        "object_count": object_count,
        "range_low": range_low,
        "range_high": range_high,
    }


# --- connection bookkeeping (mirrors modbus) ----------------------------------


def _ipv4(host: str, actor_id: str) -> str:
    return _common.ipv4_host(host, actor_id, proto="DNP3/TCP", error=Dnp3Error)


@dataclass(slots=True)
class _Conn:
    """A simulated persistent DNP3/TCP connection (master originator)."""

    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    master_addr: int
    outstation_addr: int
    last_response_ts: float = float("-inf")
    # Application sequence numbers (mod 16): the master's next request, the
    # outstation's next unsolicited response, and the last solicited fragment.
    request_seq: int = 0
    unsolicited_seq: int = 0
    last_seq: int = 0
    # (sequence, control block) of a SELECT that the next request may OPERATE.
    selected: tuple[int, tuple[tuple[str, Any], ...]] | None = None


_OUTSTATION_ADDRESS_BASE = 5  # the ICSNPP example capture: outstation 5, master 100.
_MASTER_ADDRESS_BASE = 100


def _link_addresses(actors: tuple[Actor, ...]) -> dict[str, int]:
    """Give every actor one DNP3 link address, in declaration order per role class."""
    outstations = [a.id for a in actors if a.role in _OUTSTATION_ROLES]
    masters = [a.id for a in actors if a.role in _MASTER_ROLES]
    if len(outstations) > _MASTER_ADDRESS_BASE - _OUTSTATION_ADDRESS_BASE:
        raise Dnp3Error("too many outstations for the synthetic link-address plan")
    addresses = {actor: _OUTSTATION_ADDRESS_BASE + i for i, actor in enumerate(outstations)}
    addresses.update({actor: _MASTER_ADDRESS_BASE + i for i, actor in enumerate(masters)})
    return addresses


def _connection(
    conns: dict[tuple[str, str], _Conn],
    master: Actor,
    outstation: Actor,
    addresses: Mapping[str, int],
) -> _Conn:
    key = (master.id, outstation.id)
    conn = conns.get(key)
    if conn is None:
        orig_h = _ipv4(master.host, master.id)
        resp_h = _ipv4(outstation.host, outstation.id)
        resp_p = outstation.port if outstation.port is not None else DEFAULT_DNP3_PORT
        orig_p = _common.ephemeral_port(len(conns), error=Dnp3Error)
        # Link addresses belong to actors, not connections: every master reaches an
        # outstation at that outstation's one address.
        conn = _Conn(
            uid=_common.zeek_uid(f"{orig_h}:{orig_p}>{resp_h}:{resp_p}"),
            orig_h=orig_h,
            orig_p=orig_p,
            resp_h=resp_h,
            resp_p=resp_p,
            master_addr=addresses[master.id],
            outstation_addr=addresses[outstation.id],
        )
        conns[key] = conn
    return conn


def control_code(control: Mapping[str, Any]) -> int:
    """Rebuild the CROB control-code octet from its detail.control labels."""
    operation = {label: code for code, label in _OPERATION_LABEL.items()}
    trip = {label: code for code, label in _TRIP_LABEL.items()}
    # Accept pre-correction underscore spellings in stored events as well.
    op = operation[str(control.get("operation_type", "Nul")).replace("_", " ")]
    tcc = trip.get(str(control.get("trip_control_code", "Nul")), 0)
    return (tcc << 6) | (0x20 if control.get("clear_bit") else 0) | op


def _control_status(conn: _Conn, code: int, seq: int, block: tuple[tuple[str, Any], ...]) -> str:
    """The status an outstation returns for a control request (echoed CROB)."""
    if control_code(dict(block)) & ~0x20 not in _INTEROPERABLE_CONTROL_CODES:
        return "Not Supported"
    # Select-before-operate: OPERATE must directly follow a SELECT of the same block.
    if code == OPERATE and conn.selected != ((seq - 1) % 16, block):
        return "No Select"
    return "Success"


def _orient(src: Actor, dst: Actor, where: str) -> tuple[Actor, Actor, bool]:
    """Return (master, outstation, src_is_master), classifying actors by role."""
    if src.role in _MASTER_ROLES and dst.role in _OUTSTATION_ROLES:
        return src, dst, True
    if src.role in _OUTSTATION_ROLES and dst.role in _MASTER_ROLES:
        return dst, src, False
    raise Dnp3Error(
        f"{where}: a DNP3 exchange must be between a master-class actor "
        f"({', '.join(r.value for r in _MASTER_ROLES)}) and an outstation-class actor "
        f"({', '.join(r.value for r in _OUTSTATION_ROLES)}); got "
        f"{src.role.value} -> {dst.role.value}"
    )


def build_events(scenario: Scenario) -> list[Dnp3Event]:
    """Expand a DNP3 scenario into the ordered shared event list.

    A master request becomes a request event plus (for solicited functions) a matched
    response; an outstation ``UnsolicitedResponse`` becomes an unsolicited response
    that requests confirmation, followed by the master's CONFIRM. Connections are
    persistent per (master, outstation) with the master as the TCP originator. Both
    emitters consume the returned list verbatim.
    """
    if scenario.protocol is not Protocol.DNP3:
        raise Dnp3Error(f"build_events: expected a dnp3 scenario, got {scenario.protocol.value}")
    actors = {a.id: a for a in scenario.actors}
    addresses = _link_addresses(scenario.actors)
    conns: dict[tuple[str, str], _Conn] = {}
    events: list[Dnp3Event] = []
    prev_base_ts: float | None = None

    for idx, exchange in enumerate(scenario.exchanges):
        where = f"exchanges[{idx}] ({exchange.function})"
        params = exchange.params
        code = resolve_function(exchange.function)
        func_name = function_name(code)
        src = actors[exchange.source]
        dst = actors[exchange.target]
        master, outstation, src_is_master = _orient(src, dst, where)
        conn = _connection(conns, master, outstation, addresses)

        if exchange.offset is not None:
            base_ts = scenario.timing.start + exchange.offset
        elif prev_base_ts is None:
            base_ts = scenario.timing.start
        else:
            base_ts = prev_base_ts + scenario.timing.default_interval
        prev_base_ts = base_ts
        # Serialize per-connection so a message never precedes the previous one's
        # completion (keeps each flow causally ordered; same rule as Modbus).
        msg_ts = max(base_ts, conn.last_response_ts)

        if code == UNSOLICITED_RESPONSE:
            _reject_unknown_params(params, _OBJECT_PARAM_KEYS, where)
            if src_is_master:
                raise Dnp3Error(f"{where}: UNSOLICITED_RESPONSE must originate from the outstation")
            object_type = _object_type(
                params, "object_type", where, _DATA_OBJECTS, _DEFAULT_OBJECT_TYPE
            )
            useq = conn.unsolicited_seq
            conn.unsolicited_seq = (useq + 1) % 16
            events.append(
                _make_event(
                    conn,
                    ts=msg_ts,
                    is_orig=False,
                    code=code,
                    func_name=func_name,
                    action_class=ACTION_CLASS[code],
                    app_control=_FIR_FIN | _CON | _UNS | useq,
                    fc_reply=func_name,
                    iin=_opt_int(params, "iin", where, 0, _U16, 0),
                    objects=_response_objects(params, func_name, object_type, where),
                )
            )
            # CON asks for confirmation: the master confirms with UNS set and the
            # unsolicited sequence number (IEEE 1815 application confirmation).
            confirm_ts = msg_ts + RESPONSE_DELAY
            events.append(
                _make_event(
                    conn,
                    ts=confirm_ts,
                    is_orig=True,
                    code=CONFIRM,
                    func_name="CONFIRM",
                    action_class=ACTION_CLASS.get(CONFIRM, "other"),
                    app_control=_FIR_FIN | _UNS | useq,
                    fc_request="CONFIRM",
                )
            )
            conn.last_response_ts = confirm_ts
            continue

        if code in _RESPONSE_CODES:
            raise Dnp3Error(
                f"{where}: {func_name} is a response function; a scenario exchange must "
                "be a master request or an UnsolicitedResponse (the only outstation-"
                "originated message)"
            )
        if not src_is_master:
            raise Dnp3Error(f"{where}: request {func_name} must originate from the master")
        if code in _NO_RESPONSE and "iin" in params:
            raise Dnp3Error(f"{where}: iin is unused by a function with no response")

        action_class = ACTION_CLASS.get(code, "other")
        control: dict[str, Any] | None = None
        req_objects: dict[str, Any] | None = None
        response_type: str | None = None
        if code in _CONTROL_BLOCK_FUNCS:
            _reject_unknown_params(params, _CONTROL_PARAM_KEYS, where)
            control = _control_detail(params, func_name, where)
        elif code in _OBJECT_REQUEST_FUNCS:
            allowed, default = _OBJECT_REQUEST_FUNCS[code]
            keys = _READ_PARAM_KEYS if code == READ else {"object_type", "iin"}
            _reject_unknown_params(params, keys, where)
            object_type = _object_type(params, "object_type", where, allowed, default)
            req_objects = {"function_code": func_name, "object_type": object_type}
            if code == READ and object_type in CLASS_OBJECTS:
                # A class poll returns whatever static/event data the class holds.
                if "response_object_type" in params:
                    response_type = _object_type(
                        params, "response_object_type", where, _DATA_OBJECTS, _DEFAULT_OBJECT_TYPE
                    )
                elif params.keys() & {"range_low", "range_high", "object_count"}:
                    raise Dnp3Error(
                        f"{where}: a class READ needs response_object_type to return a range"
                    )
            elif code == READ:
                if "response_object_type" in params:
                    raise Dnp3Error(f"{where}: response_object_type applies to class READs only")
                response_type = object_type
        elif params:
            # Non-object, non-control requests accept only a response iin override.
            _reject_unknown_params(params, {"iin"}, where)

        # CONFIRM acknowledges the last solicited fragment and takes no new sequence
        # number; every other request takes the master's next one.
        if code == CONFIRM:
            seq = conn.last_seq
        else:
            seq = conn.request_seq
            conn.request_seq = (seq + 1) % 16
            conn.last_seq = seq
        events.append(
            _make_event(
                conn,
                ts=msg_ts,
                is_orig=True,
                code=code,
                func_name=func_name,
                action_class=action_class,
                app_control=_FIR_FIN | seq,
                fc_request=func_name,
                control=control,
                objects=req_objects,
            )
        )
        last_ts = msg_ts
        block = tuple(sorted((k, v) for k, v in (control or {}).items() if k != "function_code"))
        if code not in _NO_RESPONSE:
            resp_ts = msg_ts + RESPONSE_DELAY
            resp_code = AUTHENTICATE_RESP if code == AUTHENTICATE_REQ else RESPONSE
            resp_name = function_name(resp_code)
            # An outstation reports an undefined function code with IIN2.0.
            default_iin = 0 if code in FUNCTION_NAMES else IIN_NO_FUNC_CODE_SUPPORT
            resp_control = None
            if control is not None:
                resp_control = {
                    **control,
                    "function_code": resp_name,
                    "status_code": _control_status(conn, code, seq, block),
                }
            events.append(
                _make_event(
                    conn,
                    ts=resp_ts,
                    is_orig=False,
                    code=resp_code,
                    func_name=resp_name,
                    action_class=action_class,  # inherit the request's verb
                    app_control=_FIR_FIN | seq,
                    fc_reply=resp_name,
                    iin=_opt_int(params, "iin", where, 0, _U16, default_iin),
                    control=resp_control,
                    objects=(
                        _response_objects(params, resp_name, response_type, where)
                        if response_type is not None
                        else None
                    ),
                )
            )
            last_ts = resp_ts
        if code != CONFIRM:
            conn.selected = (seq, block) if code == SELECT else None
        conn.last_response_ts = last_ts

    return [replace(event, ts=_common.quantize_ts(event.ts)) for event in events]


def _make_event(
    conn: _Conn,
    *,
    ts: float,
    is_orig: bool,
    code: int,
    func_name: str,
    action_class: str,
    app_control: int,
    **detail: Any,
) -> Dnp3Event:
    """Construct a :class:`Dnp3Event` on ``conn``, setting link addresses by direction."""
    src_addr = conn.master_addr if is_orig else conn.outstation_addr
    dst_addr = conn.outstation_addr if is_orig else conn.master_addr
    return Dnp3Event(
        ts=ts,
        uid=conn.uid,
        orig_h=conn.orig_h,
        orig_p=conn.orig_p,
        resp_h=conn.resp_h,
        resp_p=conn.resp_p,
        is_orig=is_orig,
        func_code=code,
        func_name=func_name,
        action_class=action_class,
        src_addr=src_addr,
        dst_addr=dst_addr,
        app_control=app_control,
        fc_request=detail.get("fc_request"),
        fc_reply=detail.get("fc_reply"),
        iin=detail.get("iin"),
        control=detail.get("control"),
        objects=detail.get("objects"),
    )


def event_to_dict(event: Dnp3Event) -> dict[str, Any]:
    """Render one DNP3 event as the schema's envelope + DNP3 ``detail`` dict."""
    detail: dict[str, Any] = {}
    if event.fc_request is not None:
        detail["fc_request"] = event.fc_request
    if event.fc_reply is not None:
        detail["fc_reply"] = event.fc_reply
    if event.iin is not None:
        detail["iin"] = event.iin
    if event.control is not None:
        detail["control"] = dict(event.control)
    if event.objects is not None:
        detail["objects"] = dict(event.objects)

    return {
        "ts": event.ts,
        "uid": event.uid,
        "conn": {
            "orig_h": event.orig_h,
            "orig_p": event.orig_p,
            "resp_h": event.resp_h,
            "resp_p": event.resp_p,
        },
        "proto": "dnp3",
        "is_orig": event.is_orig,
        "direction": event.direction,
        "func_code": event.func_code,
        "func_name": event.func_name,
        "action_class": event.action_class,
        "is_exception": False,  # DNP3 v1 surfaces IIN bits via detail.iin, not exceptions.
        "error": None,
        "detail": detail,
    }
