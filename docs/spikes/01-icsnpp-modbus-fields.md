# Spike 1 — ICSNPP Modbus parser field names & detail-log shapes

**Status:** RESOLVED (verified against authoritative source — not frozen).
**VERIFY gate:** `PRD.md` §6.3 / §7 — "ICSNPP field names / detail shapes."
**Date:** 2026-06-03

## Goal

Confirm the **current** ICSNPP Modbus parser field names and detail-log shapes so
the Modbus `detail` object in `docs/schema.md` is drawn from real names, not memory
(`ENGINEERING_CHECKLIST.md` Phase 0 + Phase 1 freeze gate).

## Source (authoritative)

- Repo: **cisagov/icsnpp-modbus**, `main` branch (CISA ICSNPP).
  - `README.md` → "Logging Capabilities" (field tables).
  - `scripts/main.zeek` → Zeek `record` type definitions (source of truth in code).
  - `scripts/consts.zeek` → diagnostic subfunction-code strings.
- Fetched live over HTTPS from `raw.githubusercontent.com` on the date above.
  Version anchor (README ETag): `31e1aa0ff1f7dffa91f4659285dd265ed913223313b8782a7471c9502b720d60`.
  Re-confirm against the pinned commit before the schema is frozen in Phase 1.

> Method note: GitHub's unauthenticated **REST API** (`api.github.com`) was rate-limited
> (HTTP 403) in this environment; the **raw** file endpoint worked. Use raw URLs for
> future ICSNPP pulls here.

## What ICSNPP adds

Zeek's built-in parser writes `modbus.log` (**unchanged** by ICSNPP). ICSNPP adds
**five** extended logs:

- `modbus_detailed.log` ← **primary source for our Modbus `detail` object**
- `modbus_mask_write_register.log` (func 0x16)
- `modbus_read_write_multiple_registers.log` (func 0x17)
- `modbus_read_device_identification.log` (func 0x2B / MEI 14; **Zeek ≥ 6.1 only**)

## `modbus_detailed.log` — verified fields

From the `Modbus_Detailed` record in `scripts/main.zeek` (authoritative; the README
table matches except for a doc typo noted below):

| Field                       | Zeek type        | Notes                                              |
| --------------------------- | ---------------- | -------------------------------------------------- |
| `ts`                        | time             | event timestamp                                    |
| `uid`                       | string           | Zeek connection uid                                |
| `id`                        | conn_id          | `{orig_h, orig_p, resp_h, resp_p}`                 |
| `tid`                       | count (optional) | Modbus transaction id                              |
| `unit`                      | count (optional) | Modbus unit identifier                             |
| `func`                      | string (optional)| function name (see below)                          |
| `address`                   | count (optional) | starting address of the value(s) field            |
| `quantity`                  | count (optional) | # of coils / discrete inputs / registers          |
| `request_values`            | vector of count  | request value(s)                                   |
| `response_values`           | vector of count  | response value(s)                                  |
| `modbus_detailed_link_id`   | string (optional)| links to the other extended logs                   |
| `matched`                   | bool (optional)  | request/response were paired                       |
| `request_subfunction_code`  | string (optional)| diagnostics (func 0x08)                            |
| `response_subfunction_code` | string (optional)| diagnostics (func 0x08)                            |
| `request_data`              | string (optional)| extra/padding bytes in request                     |
| `response_data`             | string (optional)| extra/padding bytes in response                    |
| `exception_code`            | string (optional)| **exception responses** — drives M2 / `is_exception` |
| `mei_type`                  | string (optional)| MEI type (encap. interface transport)             |

### `func` values (important for M1/M2 Sigma rules)

`func` is populated as `Modbus::function_codes[function_code]` — i.e. **Zeek's
built-in** function-code name strings, not an ICSNPP table. Exception responses get
the same name with an `_EXCEPTION` suffix. Names enumerated in `main.zeek` include:

```
READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS,
WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER, WRITE_MULTIPLE_COILS,
WRITE_MULTIPLE_REGISTERS, READ_WRITE_MULTIPLE_REGISTERS, MASK_WRITE_REGISTER,
WRITE_FILE_RECORD, …  (+ matching *_EXCEPTION variants)
```

> Sub-VERIFY for Phase 1: the **full** `Modbus::function_codes` map lives in Zeek
> core (`base/protocols/modbus/consts.zeek`); confirm the exact spelling of every
> code our detections key on against the **pinned Zeek version** before freezing.

## Other extended logs (field highlights)

- **`modbus_mask_write_register.log`** (0x16): `ts, uid, id, is_orig, source_h,
  source_p, destination_h, destination_p, modbus_detailed_link_id, tid, unit, func,
  request_response, address, and_mask, or_mask`.
- **`modbus_read_write_multiple_registers.log`** (0x17): `… tid, unit, func,
  request_response, write_start_address, write_registers, read_start_address,
  read_quantity, read_registers`.
- **`modbus_read_device_identification.log`** (0x2B/MEI 14): `… mei_type,
  conformity_level_code, conformity_level, device_id_code, object_id_code,
  object_id, object_value`.

> **Doc-vs-code discrepancy (recorded):** the README field tables for the mask-write,
> read/write-multiple, and read-device-id logs spell the unit field **`uint`**; the
> `main.zeek` record types spell it **`unit`**. **Code wins** — use `unit`.

## Source/Destination fields caveat

ICSNPP's extended logs add explicit `source_h/source_p/destination_h/destination_p`
that are **swapped on responses** so they always reflect the true Modbus
client→server direction (see README "Source and Destination Fields"). Our normalized
envelope's `is_orig`/`direction` should follow the same convention.

## Decision / impact

- Model the Modbus `detail` object on **`modbus_detailed.log`** field names above,
  with `mask_write` / `read_write_multiple` sub-shapes pulled in when those function
  codes appear. `exception_code` → envelope `is_exception`/`error`; `func` → envelope
  `func_name`; `function_code` (raw) → envelope `func_code`.
- **Nothing frozen here.** `docs/schema.md` freeze happens in Phase 1 after a final
  re-pull against a pinned ICSNPP commit + pinned Zeek `consts.zeek`.

## Nothing blocked

Network access was available; fields were taken from the authoritative source, not
guessed. No escalation needed.
