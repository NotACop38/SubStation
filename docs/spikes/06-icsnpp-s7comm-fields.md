# Spike 6 — ICSNPP S7comm parser field names & detail-log shapes

**Status:** RESOLVED (verified against authoritative source — frozen for Phase 4).
**VERIFY gate:** `PRD.md` §6.3 / §7 — "ICSNPP field names / detail shapes" (S7).
**Date:** 2026-06-04

## Goal

Confirm the **current** ICSNPP S7comm field names, log shapes and value
enumerations so the S7 `detail` object in `docs/schema.md` is drawn from real names,
not memory (`ENGINEERING_CHECKLIST.md` Phase 4; `CLAUDE.md` VERIFY gate). S7comm /
S7comm-plus have **no open specification** (`PRD.md` §9), so the ICSNPP parser and
the Wireshark S7comm dissector are the authoritative references.

## Sources (authoritative)

- **cisagov/icsnpp-s7comm** `main` — the Zeek plugin that parses s7comm, s7comm-plus
  and COTP:
  - `scripts/icsnpp/s7comm/main.zeek` → the six `&log` record types (source of truth
    in code) and the logging logic that resolves each value.
  - `scripts/consts.zeek` → every value enumeration the detections key on
    (`rosctr_types`, `s7comm_functions`, `s7comm_userdata_functions`, the
    sub-function tables, `s7comm_szl_id`, `s7comm_block_types`, `cotp_pdu_types`,
    `s7comm_plus_opcodes`, `s7comm_plus_functions`, `s7comm_plc_control_services`).
  - `README.md` → "Logging Capabilities" (field tables) + "Source and Destination
    Fields" (the `is_orig` caveat, identical to Modbus/DNP3).
- Fetched live over HTTPS via the `codeload` tarball
  (`codeload.github.com/cisagov/icsnpp-s7comm/tar.gz/refs/heads/main`) on the date
  above. (`api.github.com` is rate-limited, same as spikes 01/04; raw single-file
  paths under `scripts/icsnpp/s7comm/` resolve fine. NB the parser scripts live at
  `scripts/icsnpp/s7comm/main.zeek`, **not** `scripts/main.zeek` as DNP3/Modbus.)

## What ICSNPP-S7comm produces (six log streams, `main.zeek` `zeek_init`)

- **`cotp.log`** — one row per COTP packet (`COTP` record).
- **`s7comm.log`** — one row per S7comm header (`S7COMM` record); the primary source
  for our envelope (`rosctr`, `function_*`, `subfunction_*`, `error_*`).
- **`s7comm_read_szl.log`** — Read-SZL detail (`S7COMM_READ_SZL` record).
- **`s7comm_upload_download.log`** — upload/download detail for the six
  program/block transfer functions (`S7COMM_UPLOAD_DOWNLOAD` record).
- **`s7comm_plus.log`** — S7comm-plus header (`S7COMM_PLUS` record).
- **`s7comm_known_devices.log`** — accreted device identity (`S7COMM_KNOWN_DEVICES`),
  written at connection teardown. Not modelled in our `detail` v1 (it is a derived
  per-connection summary, not a per-message field shape).

## `s7comm.log` — verified base fields (`S7COMM` record, `main.zeek`)

`ts, uid, id, is_orig, source_h, source_p, destination_h, destination_p,
rosctr_code, rosctr_name, pdu_reference, function_code, function_name,
subfunction_code, subfunction_name, error_class, error_code`.

- `rosctr_name = rosctr_types[rosctr]` — `Job-Request` (0x01), `ACK` (0x02),
  `ACK-Data` (0x03), `User-Data` (0x07).
- `function_code` is logged as a **hex string** (`fmt("0x%02x", …)`); `function_name`
  is `s7comm_functions[function_code]` for Job/Ack messages, or
  `"Request:"/"Response:" + s7comm_userdata_functions[fc & 0x0f]` for User-Data
  (`rosctr == 0x07`).
- `subfunction_name` for User-Data is selected by `(function_code & 0x0f)` from the
  matching sub-function table; for **PLC Control** (`function_code == 0x28 &&
  rosctr == 0x01`) `subfunction_code` is the control service string and
  `subfunction_name = s7comm_plc_control_services[service]`.

### Value tables the detections key on (`consts.zeek`, verified verbatim)

`s7comm_functions`: `0x00 CPU Services, 0x04 Read Variable, 0x05 Write Variable,
0x1a Request Download, 0x1b Download Block, 0x1c Download Ended, 0x1d Start Upload,
0x1e Upload, 0x1f End Upload, 0x28 PLC Control, 0x29 PLC Stop,
0xf0 Setup Communication`.

`s7comm_plc_control_services`: includes `"P_PROGRAM" -> "PLC Start / Stop"` (the
start/stop service S1 keys on).

`s7comm_userdata_functions`: `0x00 Mode-Transition, 0x01 Programmer Controls,
0x02 Cyclic Services, 0x03 Block Functions, 0x04 CPU Functions, 0x05 Security,
0x07 Time Functions, …`. `s7comm_cpu_functions_subfunctions[0x01] = "Read SZL"`;
`s7comm_block_functions_subfunctions = {0x01 List Blocks, 0x02 List Blocks of Type,
0x03 Get Block Info}` (the S3 enumeration set).

> The detections key on these exact spellings: **S1** `PLC Stop` / `PLC Control`
> (+ subfunction `PLC Start / Stop`); **S2** `Request Download` / `Download Block` /
> `Download Ended`; **S3** `Read SZL` (+ `s7comm_szl_id` names) / `List Blocks` /
> s7comm-plus `Explore`.

## `cotp.log` — verified fields (`COTP` record)

`ts, uid, id, is_orig, source_h, source_p, destination_h, destination_p, pdu_code,
pdu_name`. `pdu_code = fmt("0x%02x", pdu)` where `pdu` is the COTP PDU type **high
nibble**; `pdu_name = cotp_pdu_types[pdu]` — `0x0e CR Connection Request`,
`0x0d CC Connection Confirm`, `0x0f DT Data`, etc.

## `s7comm_read_szl.log` — verified fields (`S7COMM_READ_SZL` record)

`ts, uid, id, is_orig, source_h…destination_p, pdu_reference, method, szl_id,
szl_id_name, szl_index, return_code, return_code_name`. `szl_id`/`szl_index`/
`return_code` are hex strings; `szl_id_name = s7comm_szl_id[szl_id & 0xff]`
(e.g. `0x0011 → "Module identification"`, `0x001c → "Component Identification"`);
`return_code_name = s7comm_userdata_return_codes[…]` (`0xff → "Success"`).

## `s7comm_upload_download.log` — verified fields (`S7COMM_UPLOAD_DOWNLOAD` record)

`ts, uid, id, is_orig, source_h…destination_p, rosctr, pdu_reference, function_name,
function_status, session_id, blocklength, filename, block_type, block_number,
destination_filesystem`. `block_type = s7comm_block_types[…]` (`"0A" → "Data Block"`,
`"08" → "Organization Block"`, `"0E" → "Function Block"`, …);
`destination_filesystem = s7comm_destination_filesystem[…]` (`"P" → "Passive"`,
`"A" → "Active"`).

> README caveat (same class as Modbus spike 01): the README field table lists
> `function_code`/`function_status` as `count`, but the **code** (`S7COMM_UPLOAD_DOWNLOAD`
> record) logs `function_name: string` + `function_status: string`. **Code wins.**

## `s7comm_plus.log` — verified fields (`S7COMM_PLUS` record)

`ts, uid, id, is_orig, source_h…destination_p, version, opcode, opcode_name,
function_code, function_name`. `opcode_name = s7comm_plus_opcodes[opcode]`
(`0x31 Request, 0x32 Response, 0x33 Notification`);
`function_name = s7comm_plus_functions[function_code]` (`0x04bb Explore,
0x04ca Create Object, 0x04f2 Set Variable, 0x04d4 Delete Object, …`).

## Source/Destination fields caveat (identical to Modbus/DNP3)

ICSNPP derives `source_*`/`destination_*` **through `is_orig`** in every record;
Zeek's `id` never swaps originator/responder. Our envelope carries Zeek's `id` as
`conn` + `is_orig` and never duplicates `source_*`/`destination_*` into `detail`
(same choice as spikes 01/04). S1/S2 allow-lists derive the source from `conn` **and**
`is_orig` (`docs/schema.md` → `conn`).

## Decision / impact (frozen for S7)

Model the S7 `detail` on `s7comm.log` (`rosctr_*`, `pdu_reference`, `function_*`,
`subfunction_*`, `error_*`) with four sub-objects taken verbatim from the records
above: `detail.cotp` (`cotp.log`), `detail.read_szl` (`s7comm_read_szl.log`),
`detail.upload_download` (`s7comm_upload_download.log`), and `detail.plus`
(`s7comm_plus.log`). The normalized envelope `func_code`/`func_name` carry the
s7comm `function_code` byte / ICSNPP `function_name` (and for COTP/s7comm-plus events,
the COTP PDU type / s7comm-plus function name). S7 carries no Modbus-style
application exception, so envelope `is_exception` is `false` for S7 v1; S7comm error
class/code are surfaced via `detail.error_class`/`detail.error_code` when present.

## Nothing blocked

Network access was available; fields/value tables were taken from the authoritative
ICSNPP source, not guessed. No escalation needed.
