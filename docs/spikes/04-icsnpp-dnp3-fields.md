# Spike 4 — ICSNPP DNP3 parser field names & detail-log shapes

**Status:** RESOLVED (verified against authoritative source — frozen for Phase 3).
**VERIFY gate:** `PRD.md` §6.3 / §7 — "ICSNPP field names / detail shapes."
**Date:** 2026-06-04

## Goal

Confirm the **current** Zeek + ICSNPP DNP3 field names and detail-log shapes so the
DNP3 `detail` object in `docs/schema.md` is drawn from real names, not memory
(`ENGINEERING_CHECKLIST.md` Phase 3; `CLAUDE.md` VERIFY gate).

## Sources (authoritative)

- **Zeek core** `zeek/zeek` `master` — base DNP3 parser (the `dnp3.log` source):
  - `scripts/base/protocols/dnp3/main.zeek` → `DNP3::Info` record.
  - `scripts/base/protocols/dnp3/consts.zeek` → `DNP3::function_codes` table.
- **cisagov/icsnpp-dnp3** `main` — the extended logs:
  - `scripts/main.zeek` → `Control` and `Objects` record types (source of truth in
    code).
  - `README.md` → "Logging Capabilities" (field tables + value enumerations).
- Fetched live over HTTPS from `raw.githubusercontent.com` / `codeload.github.com`
  on the date above. (`api.github.com` was rate-limited HTTP 403 — same as spike 01;
  use raw / codeload tarball endpoints for ICSNPP pulls here.)

## What Zeek + ICSNPP produce

- Zeek's **built-in** DNP3 parser writes **`dnp3.log`** (unchanged by ICSNPP) — the
  primary source for our normalized envelope (`fc_request` / `fc_reply` / `iin`).
- ICSNPP-DNP3 adds **two** extended logs (README "adding two new DNP3 log files"):
  - **`dnp3_control.log`** — SELECT / OPERATE / RESPONSE Control-Relay-Output-Block
    (CROB) and Pattern-Control-Block (PCB) detail → our `detail.control`.
  - **`dnp3_objects.log`** — READ / RESPONSE object-header detail → our
    `detail.objects`. (README calls the stream `dnp3_objects.log`; the prose also
    says "dnp3_read_objects.log" — the **code** `$path="dnp3_objects"` wins.)

## `dnp3.log` — verified base fields (`DNP3::Info`, Zeek `main.zeek`)

| Field        | Zeek type         | Notes                                              |
| ------------ | ----------------- | -------------------------------------------------- |
| `ts`         | time              | event timestamp                                    |
| `uid`        | string            | Zeek connection uid                                |
| `id`         | conn_id           | `{orig_h, orig_p, resp_h, resp_p}`                 |
| `fc_request` | string (optional) | request function name — `function_codes[fc]`       |
| `fc_reply`   | string (optional) | reply function name — `function_codes[fc]`         |
| `iin`        | count  (optional) | response "internal indication" bits (2-byte field) |

`fc` is logged as `DNP3::function_codes[fc]` (Zeek's built-in name table), exactly
like Modbus's `func` (spike 01). Default for an unknown code is `fmt("unknown-%d")`.

### `DNP3::function_codes` (Zeek `consts.zeek`, verified — the names our detections key on)

Requests: `0x00 CONFIRM, 0x01 READ, 0x02 WRITE, 0x03 SELECT, 0x04 OPERATE,
0x05 DIRECT_OPERATE, 0x06 DIRECT_OPERATE_NR, 0x07 IMMED_FREEZE,
0x08 IMMED_FREEZE_NR, 0x09 FREEZE_CLEAR, 0x0a FREEZE_CLEAR_NR, 0x0b FREEZE_AT_TIME,
0x0c FREEZE_AT_TIME_NR, 0x0d COLD_RESTART, 0x0e WARM_RESTART, 0x0f INITIALIZE_DATA,
0x10 INITIALIZE_APPL, 0x11 START_APPL, 0x12 STOP_APPL, 0x13 SAVE_CONFIG,
0x14 ENABLE_UNSOLICITED, 0x15 DISABLE_UNSOLICITED, 0x16 ASSIGN_CLASS,
0x17 DELAY_MEASURE, 0x18 RECORD_CURRENT_TIME, 0x19 OPEN_FILE, 0x1a CLOSE_FILE,
0x1b DELETE_FILE, 0x1c GET_FILE_INFO, 0x1d AUTHENTICATE_FILE, 0x1e ABORT_FILE,
0x1f ACTIVATE_CONFIG, 0x20 AUTHENTICATE_REQ, 0x21 AUTHENTICATE_REQ_NR`.
Responses: `0x81 RESPONSE, 0x82 UNSOLICITED_RESPONSE, 0x83 AUTHENTICATE_RESP`.

> The detections key on these exact spellings: **D1** COLD_RESTART / WARM_RESTART,
> **D2** DISABLE_UNSOLICITED, **D3** SELECT / OPERATE / DIRECT_OPERATE /
> DIRECT_OPERATE_NR.

## `dnp3_control.log` — verified fields (`Control` record, ICSNPP `main.zeek`)

`ts, uid, id, is_orig, source_h, source_p, destination_h, destination_p,
block_type, function_code, index_number, trip_control_code, operation_type,
clear_bit, execute_count, on_time, off_time, status_code`.

Value enumerations (from `main.zeek` logic + README):
- `block_type` ∈ {`Control Relay Output Block`, `Pattern Control Block`}.
- `operation_type` (= `control_block_operation_type[control_code & 0x0f]`) ∈
  {`Nul`, `Pulse_On`, `Pulse_Off`, `Latch_On`, `Latch_Off`}.
- `trip_control_code` (= `control_block_trip_code[(control_code & 0xc0)/64]`) ∈
  {`Nul`, `Close`, `Trip`}.
- `clear_bit` = `((control_code & 0x20) >> 5) == 1`.
- `status_code` only set when `function_code == "RESPONSE"`.

## `dnp3_objects.log` — verified fields (`Objects` record, ICSNPP `main.zeek`)

`ts, uid, id, is_orig, source_h, source_p, destination_h, destination_p,
function_code, object_type, object_count, range_low, range_high`.

Per `main.zeek`: on a **request** only `function_code` (READ) + `object_type` are
logged; `object_count` / `range_low` / `range_high` are populated only on the
**RESPONSE** side. `object_type` is `dnp3_objects[obj_type]` — a group→device-type
string (e.g. `Binary Input`); rows whose type resolves to `unknown` are dropped.

## Source/Destination fields caveat (identical to Modbus, spike 01)

ICSNPP's extended logs add `source_*`/`destination_*` derived **through `is_orig`**
(`is_orig==F` ⇒ source is the responder). Zeek's `id` never swaps
originator/responder roles. Our envelope therefore carries Zeek's `id` as `conn`
plus `is_orig`, and any detection needing a stable "who is the master" identity
(D1/D2/D3 allow-lists) derives source from `conn` **and** `is_orig` — never assumes
source==client (`docs/schema.md` → `conn`).

## Decision / impact (frozen for DNP3)

Model the DNP3 `detail` on `dnp3.log` (`fc_request`, `fc_reply`, `iin`) with a
`detail.control` sub-object (`dnp3_control.log`) and a `detail.objects` sub-object
(`dnp3_objects.log`), all field names taken verbatim from the verified records
above. We do **not** duplicate `id` / `source_*` / `destination_*` into `detail`
(the envelope `conn` + `is_orig` carry them — same choice as Modbus). DNP3 carries
no Modbus-style application exception, so envelope `is_exception` is always `false`
for DNP3 v1 (IIN error bits are surfaced via `detail.iin`, not as exceptions).

## Nothing blocked

Network access was available; fields were taken from the authoritative source, not
guessed. No escalation needed.
