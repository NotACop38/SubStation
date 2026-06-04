# Event-log JSON schema

**Status:** **FROZEN for Modbus** (Phase 1) **and DNP3** (Phase 3). The S7 `detail`
shape freezes in Phase 4. This document is the binding contract every emitter,
detection, and test binds to (`PRD.md` §6.3).

The machine-readable contract is
[`substation/schema/event-log.schema.json`](../substation/schema/event-log.schema.json)
(JSON Schema draft 2020-12). This document is its prose companion; on any
disagreement, **the JSON Schema wins** because `make ci` enforces it.

## Format

The event log is **newline-delimited JSON** (`.jsonl`): **one event object per
line**, no enclosing array, UTF-8. This matches how Zeek logs stream and is
trivial to process line-by-line. Blank lines are ignored. The JSON Schema
validates a **single line** (one event); the validator applies it to every
non-blank line of a file. Blank lines are ignored; a non-JSON line — including
the non-standard `NaN`/`Infinity` barewords that Python's `json.dumps` emits by
default — fails the gate rather than slipping through numeric checks.

## Design: ICSNPP-aligned detail + a thin normalized envelope

Every event is a small **normalized envelope** (uniform across all three
protocols, so cross-protocol logic like X1 and shared Sigma rules work uniformly)
wrapping a per-protocol **`detail`** object whose field names mirror **Zeek +
ICSNPP** so detections authored here transfer to production Zeek deployments with
minimal change (`PRD.md` §6.3).

> **VERIFY provenance.** The Modbus `detail` field names below are taken from the
> ICSNPP Modbus parser, **not** memory — `cisagov/icsnpp-modbus`
> `scripts/main.zeek` (`Modbus_Detailed` and the extended-log records), recorded
> in [`spikes/01-icsnpp-modbus-fields.md`](spikes/01-icsnpp-modbus-fields.md).
> Re-pull against a pinned ICSNPP commit + pinned Zeek `consts.zeek` before
> extending; the spike notes the exact version anchor used for this freeze.

## The normalized envelope (every event, every protocol)

| Field          | Type                | Req | Meaning |
| -------------- | ------------------- | --- | ------- |
| `ts`           | number              | yes | Event timestamp, Unix epoch seconds (Zeek `ts`). |
| `uid`          | string (non-empty)  | yes | Zeek-style connection uid (ICSNPP `uid`). |
| `conn`         | object              | yes | Zeek conn tuple — see below. |
| `proto`        | enum                | yes | `modbus` \| `dnp3` \| `s7comm`. Selects the `detail` shape. |
| `is_orig`      | boolean             | yes | ICSNPP `is_orig`: true when the event is from the connection originator (request side). |
| `direction`    | enum                | yes | `request` \| `response`, derived from `is_orig` (true → request). The schema **enforces** this agreement — a line where `direction` and `is_orig` disagree fails the gate. |
| `func_code`    | integer 0–255       | yes | Raw one-byte function/command code. Modbus exception responses carry `function_code \| 0x80`. |
| `func_name`    | string (non-empty)  | yes | Decoded, normalized function name (Modbus: Zeek `Modbus::function_codes[func_code]`, `_EXCEPTION` suffix on exceptions). |
| `action_class` | enum                | yes | Normalized verb: `read` \| `write` \| `control` \| `diagnostic` \| `scan_indicator` \| `other`. Drives X1 + shared logic. |
| `is_exception` | boolean             | yes | True when this event is an error/exception response. |
| `error`        | string \| null      | no  | Decoded exception/error name when `is_exception` (Modbus mirrors `detail.exception_code`, e.g. `ILLEGAL_DATA_ADDRESS`); null/absent otherwise. |
| `detail`       | object              | yes | Per-protocol detail (constrained per `proto`). |

The envelope rejects unknown top-level properties (`additionalProperties: false`)
so emitter mistakes fail loudly.

### `conn` (Zeek conn tuple)

| Field    | Type            | Meaning |
| -------- | --------------- | ------- |
| `orig_h` | string          | Originator host (`id.orig_h`). |
| `orig_p` | integer 0–65535 | Originator port (`id.orig_p`). |
| `resp_h` | string          | Responder host (`id.resp_h`). |
| `resp_p` | integer 0–65535 | Responder port (`id.resp_p`). |

All four are required. The tuple is **originator/responder**, not per-direction
source/destination: Zeek's `id` never swaps roles, so on a response/exception the
originator is still the client. ICSNPP's extended logs add explicit
`source_*`/`destination_*` derived **through `is_orig`** (spike 01). We do **not**
duplicate those in the envelope — a detection that needs a stable "who is the
writer/master" identity (e.g. M1's allow-list) derives source/destination from
`conn` **and** `is_orig`:

```
is_orig == true  -> source = conn.orig_*,  destination = conn.resp_*
is_orig == false -> source = conn.resp_*,  destination = conn.orig_*
```

Assuming `source == client` would invert endpoints on responses/exceptions and
skew allow-list and exception detections.

## Modbus `detail` (FROZEN)

Modeled on ICSNPP **`modbus_detailed.log`** (the `Modbus_Detailed` record), with
optional sub-objects for the three function-code-specific extended logs pulled in
when those codes appear. All fields are **optional** (mirroring Zeek's optional
record fields); unknown fields are rejected.

| Field                       | Type             | ICSNPP source / meaning |
| --------------------------- | ---------------- | ----------------------- |
| `tid`                       | integer 0–65535  | Modbus transaction id. |
| `unit`                      | integer 0–255    | Modbus unit identifier. (ICSNPP README spells it `uint` for some logs; `main.zeek` says `unit` — code wins.) |
| `func`                      | string           | ICSNPP `func` (Zeek function name); mirrors envelope `func_name`. |
| `address`                   | integer 0–65535  | Starting address of the value(s) field. |
| `quantity`                  | integer ≥ 0      | Number of coils / discrete inputs / registers. |
| `request_values`            | array<integer>   | Request value(s). |
| `response_values`           | array<integer>   | Response value(s). |
| `modbus_detailed_link_id`   | string           | Links to the extended sub-logs (mask-write / read-write-multiple / read-device-id). |
| `matched`                   | boolean          | Request/response were paired. |
| `request_subfunction_code`  | string           | Diagnostics subfunction (func `0x08`), request side. |
| `response_subfunction_code` | string           | Diagnostics subfunction (func `0x08`), response side. |
| `request_data`              | string           | Extra/padding bytes in the request. |
| `response_data`             | string           | Extra/padding bytes in the response. |
| `exception_code`            | string           | Exception name on an exception response. Drives envelope `is_exception`/`error` and **M2**. |
| `mei_type`                  | string           | MEI type (encapsulated interface transport). |
| `mask_write`                | object           | MASK_WRITE_REGISTER (`0x16`) sub-shape — see below. |
| `read_write_multiple`       | object           | READ_WRITE_MULTIPLE_REGISTERS (`0x17`) sub-shape. |
| `read_device_identification`| object           | READ_DEVICE_IDENTIFICATION (`0x2B`/MEI 14) sub-shape. |

### Function-code-specific sub-shapes

`detail.mask_write` (ICSNPP `modbus_mask_write_register.log`; `address` stays on
the parent `detail`):

| Field      | Type            |
| ---------- | --------------- |
| `and_mask` | integer 0–65535 |
| `or_mask`  | integer 0–65535 |

`detail.read_write_multiple` (ICSNPP `modbus_read_write_multiple_registers.log`):

| Field                 | Type            |
| --------------------- | --------------- |
| `write_start_address` | integer 0–65535 |
| `write_registers`     | array<integer>  |
| `read_start_address`  | integer 0–65535 |
| `read_quantity`       | integer ≥ 0     |
| `read_registers`      | array<integer>  |

`detail.read_device_identification` (ICSNPP
`modbus_read_device_identification.log`; Zeek ≥ 6.1):

| Field                   | Type        |
| ----------------------- | ----------- |
| `conformity_level_code` | integer ≥ 0 |
| `conformity_level`      | string      |
| `device_id_code`        | integer ≥ 0 |
| `object_id_code`        | integer ≥ 0 |
| `object_id`             | string      |
| `object_value`          | string      |

### Envelope ↔ ICSNPP mapping

| Envelope         | Source |
| ---------------- | ------ |
| `func_code`      | raw Modbus `function_code` (exceptions: `\| 0x80`). |
| `func_name`      | ICSNPP `func` (Zeek `Modbus::function_codes`). |
| `is_exception`   | true when `func_name` ends in `_EXCEPTION` / `detail.exception_code` present. |
| `error`          | decoded `detail.exception_code`. |

When `is_exception` is true on a Modbus event the schema **requires** a non-null
`error` **and** `detail.exception_code` (M2 keys on the decoded name, so neither
may be absent on an exception event).
| `conn`           | ICSNPP `id`. |

### `action_class` mapping (Modbus)

A normalized verb derived from the function, so cross-protocol logic doesn't have
to special-case every code:

| `action_class`   | Modbus functions |
| ---------------- | ---------------- |
| `read`           | READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS |
| `write`          | WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER, WRITE_MULTIPLE_COILS, WRITE_MULTIPLE_REGISTERS, MASK_WRITE_REGISTER, READ_WRITE_MULTIPLE_REGISTERS, WRITE_FILE_RECORD |
| `diagnostic`     | DIAGNOSTICS (`0x08`), READ_EXCEPTION_STATUS, REPORT_SERVER_ID, READ_DEVICE_IDENTIFICATION |
| `control`        | (none for Modbus; used by DNP3/S7 run-state controls.) |
| `scan_indicator` | not intrinsic to a single code — set by the scenario/emitter to mark sweep/enumeration telemetry for M3. |
| `other`          | anything not classified above, incl. reserved/undefined codes (still surfaced for M2). |

> Sub-VERIFY at extension time: confirm exact `Modbus::function_codes` spellings
> against the **pinned** Zeek `base/protocols/modbus/consts.zeek` before any new
> detection keys on a name (spike 01).

## DNP3 `detail` (FROZEN)

Modeled on Zeek's **base** `dnp3.log` (`DNP3::Info`) plus ICSNPP's two extended
logs, **`dnp3_control.log`** (CROB/PCB control detail) and **`dnp3_objects.log`**
(object-header detail). All fields are **optional** (mirroring Zeek's optional
record fields); unknown fields are rejected.

> **VERIFY provenance.** The DNP3 field names below are taken from
> `zeek/zeek` `base/protocols/dnp3/{main,consts}.zeek` and `cisagov/icsnpp-dnp3`
> `scripts/main.zeek`, **not** memory — recorded in
> [`spikes/04-icsnpp-dnp3-fields.md`](spikes/04-icsnpp-dnp3-fields.md).

| Field        | Type            | Zeek/ICSNPP source / meaning |
| ------------ | --------------- | ---------------------------- |
| `fc_request` | string          | `dnp3.log` `fc_request` — request function name (`DNP3::function_codes[fc]`); mirrors envelope `func_name` on requests. |
| `fc_reply`   | string          | `dnp3.log` `fc_reply` — reply function name; mirrors envelope `func_name` on responses (`RESPONSE`/`UNSOLICITED_RESPONSE`). |
| `iin`        | integer 0–65535 | `dnp3.log` `iin` — response internal-indication bits (2-byte field). |
| `control`    | object          | `dnp3_control.log` CROB/PCB sub-shape (SELECT/OPERATE) — see below. |
| `objects`    | object          | `dnp3_objects.log` object-header sub-shape (READ/RESPONSE) — see below. |

`detail.control` (ICSNPP `dnp3_control.log`; values from the parser's
`control_block_*` tables):

| Field               | Type            |
| ------------------- | --------------- |
| `block_type`        | string (`Control Relay Output Block` / `Pattern Control Block`) |
| `function_code`     | string (this row's function, e.g. `OPERATE`) |
| `index_number`      | integer 0–65535 |
| `trip_control_code` | string (`Nul` / `Close` / `Trip`) |
| `operation_type`    | string (`Nul` / `Pulse_On` / `Pulse_Off` / `Latch_On` / `Latch_Off`) |
| `clear_bit`         | boolean         |
| `execute_count`     | integer 0–255   |
| `on_time`           | integer 0–2³²−1 |
| `off_time`          | integer 0–2³²−1 |
| `status_code`       | string (RESPONSE only) |

`detail.objects` (ICSNPP `dnp3_objects.log`; range/count populated on the RESPONSE,
per the parser):

| Field           | Type            |
| --------------- | --------------- |
| `function_code` | string (`READ` / `RESPONSE`) |
| `object_type`   | string (device/object type, e.g. `Binary Input With Status`) |
| `object_count`  | integer 0–65535 |
| `range_low`     | integer 0–65535 |
| `range_high`    | integer 0–65535 |

> **Single-source / no-drift (PR #9 review).** `object_type` must be one of the
> verified ICSNPP `dnp3_objects` device-type names the simulator supports
> (`substation.protocols.dnp3.OBJECT_TYPES`: `Binary Input With Status`,
> `Binary Output`, `16-Bit Binary Counter`, `32-Bit Analog Input`,
> `16-Bit Analog Input`). The simulator derives the DNP3 object **group/variation**
> for the PCAP from that same string, so a Zeek decode of the PCAP resolves the
> identical `object_type` — the JSON and PCAP cannot drift (PRD §6.1). On a response
> `object_count` **must equal** the range span (`range_high − range_low + 1`); an
> inconsistent count is rejected at build time rather than emitted. Ranges and
> control `index_number` are carried on the wire as 2-byte fields, so values up to
> 65535 round-trip.

We do **not** duplicate ICSNPP's `id` / `source_*` / `destination_*` into `detail`
— the envelope `conn` + `is_orig` carry them (same choice as Modbus, spike 04). A
detection needing a stable "who is the master" identity (D1/D2/D3 allow-lists)
derives source from `conn` **and** `is_orig`.

### `action_class` mapping (DNP3)

| `action_class`   | DNP3 functions |
| ---------------- | -------------- |
| `read`           | READ; IMMED_FREEZE, GET_FILE_INFO; UNSOLICITED_RESPONSE (data-bearing telemetry) |
| `write`          | WRITE; FREEZE_CLEAR |
| `control`        | SELECT, OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR (output control); COLD_RESTART, WARM_RESTART (device control); ENABLE_UNSOLICITED, DISABLE_UNSOLICITED (reporting control); START_APPL, STOP_APPL, ASSIGN_CLASS |
| `diagnostic`     | DELAY_MEASURE, RECORD_CURRENT_TIME |
| `other`          | anything not classified above |

A solicited **response** (`RESPONSE`, 0x81) inherits the action_class of the request
it answers (so a response to a READ is `read`, to an OPERATE is `control`). DNP3
lumps output, device and reporting control all under `control`; the per-command
detections (D1/D2/D3) therefore key on the specific **`func_name`**, never on
`action_class` alone, so the broad class never over-fires.

> DNP3 carries no Modbus-style application exception: envelope `is_exception` is
> always `false` for DNP3 and IIN error bits are surfaced via `detail.iin`. The base
> `dnp3.log` separates request/reply function names (`fc_request`/`fc_reply`), so a
> DNP3 exchange's request and response carry **different** `func_code`/`func_name`
> (e.g. `READ` → `RESPONSE`), unlike Modbus where the response echoes the request.

## Example events

A benign read request/response pair and an illegal-address exception (one line
each in the `.jsonl`):

```json
{"ts": 1717372800.123, "uid": "CwT9aQ1z8pPnabc01", "conn": {"orig_h": "10.0.0.10", "orig_p": 51234, "resp_h": "10.0.0.50", "resp_p": 502}, "proto": "modbus", "is_orig": true, "direction": "request", "func_code": 3, "func_name": "READ_HOLDING_REGISTERS", "action_class": "read", "is_exception": false, "error": null, "detail": {"tid": 1, "unit": 1, "func": "READ_HOLDING_REGISTERS", "address": 100, "quantity": 10}}
{"ts": 1717372810.222, "uid": "CnXyz93c4lR5ghi03", "conn": {"orig_h": "10.0.0.99", "orig_p": 40001, "resp_h": "10.0.0.50", "resp_p": 502}, "proto": "modbus", "is_orig": false, "direction": "response", "func_code": 132, "func_name": "READ_INPUT_REGISTERS_EXCEPTION", "action_class": "read", "is_exception": true, "error": "ILLEGAL_DATA_ADDRESS", "detail": {"tid": 7, "unit": 1, "func": "READ_INPUT_REGISTERS_EXCEPTION", "exception_code": "ILLEGAL_DATA_ADDRESS", "matched": true}}
```

More live, validated examples:
[`tests/data/events/modbus/valid.jsonl`](../tests/data/events/modbus/valid.jsonl).

A DNP3 operate command and an unauthorized cold-restart (one line each):

```json
{"ts": 1717372802.0, "uid": "COt4RSFMt8R6TYXLdv", "conn": {"orig_h": "10.0.1.10", "orig_p": 49152, "resp_h": "10.0.1.50", "resp_p": 20000}, "proto": "dnp3", "is_orig": true, "direction": "request", "func_code": 4, "func_name": "OPERATE", "action_class": "control", "is_exception": false, "error": null, "detail": {"fc_request": "OPERATE", "control": {"block_type": "Control Relay Output Block", "function_code": "OPERATE", "index_number": 2, "trip_control_code": "Close", "operation_type": "Latch_On", "clear_bit": false, "execute_count": 1, "on_time": 0, "off_time": 0}}}
{"ts": 1717372806.0, "uid": "COt4RSFMt8R6TYXLdv", "conn": {"orig_h": "10.0.1.77", "orig_p": 49153, "resp_h": "10.0.1.50", "resp_p": 20000}, "proto": "dnp3", "is_orig": true, "direction": "request", "func_code": 13, "func_name": "COLD_RESTART", "action_class": "control", "is_exception": false, "error": null, "detail": {"fc_request": "COLD_RESTART"}}
```

More live, validated DNP3 examples:
[`tests/data/events/dnp3/valid.jsonl`](../tests/data/events/dnp3/valid.jsonl).

## Validation (the gate)

`make ci` runs the **`schema`** step, which validates committed golden events
under `tests/data/events/` (and any path you pass) against the JSON Schema:

```sh
make schema                                   # validate the golden events
python -m substation.schema artifacts/        # validate emitted artifacts
python -m substation.schema path/to/run.jsonl # validate one file
```

Any event that violates the schema makes the step — and therefore `make ci` —
fail (`PRD.md` §6.3). Validation is **dependency-free**: `substation.schema` ships
a small validator for the JSON-Schema subset this contract uses, so the Tier-1
headline path needs only Python (`PRD.md` §6.2). The schema file is standard
draft-2020-12 and also works with any external validator (e.g. `jsonschema`).

## Other protocols (not yet frozen)

S7 (`proto: s7comm`) uses the **same envelope** now, but its `detail` object is
**unconstrained** until its schema freezes (Phase 4), verified against the current
ICSNPP S7 parser fields before freeze. Modbus (Phase 1) and DNP3 (Phase 3) `detail`
are frozen above.

## Sigma offline evaluation (recorded)

Tier-1 detections are authored as Sigma and evaluated over this `.jsonl` by
walking the pySigma-parsed condition AST in pytest — no SIEM required
([`spikes/03-sigma-offline-evaluation.md`](spikes/03-sigma-offline-evaluation.md)).
Because `detail` mirrors ICSNPP, the same rules compile to production Zeek/SIEM
backends unchanged.
