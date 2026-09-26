# Scenario format

A **scenario** is the single source of truth for one simulator run (`docs/design.md`
§6.1, §6.4). It is human-editable YAML under `scenarios/<proto>/`, loaded into a
typed, immutable model (`substation/scenarios/model.py`) that drives **both** the
PCAP and the JSON emitters. The canonical, fully commented example is
[`scenarios/modbus/benign-poll.yaml`](../scenarios/modbus/benign-poll.yaml).

```yaml
name: modbus-benign-poll
protocol: modbus
label: benign
actors:
  - {id: hmi-1, role: hmi, host: 10.0.0.10}
  - {id: plc-1, role: plc, host: 10.0.0.50, port: 502}
exchanges:
  - {source: hmi-1, target: plc-1, function: ReadHoldingRegisters, params: {address: 0, quantity: 10}}
exercises:
  quiet: [M1, M2]
```

## Top-level keys

| Key           | Required | Type             | Notes |
|---------------|----------|------------------|-------|
| `name`        | yes      | string           | Filesystem-safe (`[A-Za-z0-9._-]`); names the artifacts `<name>.pcap` and `<name>.jsonl`. By convention it starts with the protocol (`modbus-`, `dnp3-`, `s7-`). |
| `description` | no       | string           | Free-form prose. |
| `protocol`    | yes      | enum             | `modbus` \| `dnp3` \| `s7comm`. |
| `label`       | yes      | enum             | `benign` \| `anomalous` — ground-truth intent. |
| `actors`      | yes      | list (non-empty) | Network participants; see below. |
| `exchanges`   | yes      | list             | Ordered protocol exchanges; may be empty. |
| `timing`      | no       | mapping          | Scenario-level timing. |
| `exercises`   | no       | mapping          | Detection IDs this scenario must fire or keep quiet. |

Unknown keys are rejected at every level, as are duplicate keys and malformed
values. Errors name the file and the path to the offending field.

### `actors`

Roles are first-class because credible detections need the legitimate writer or
master modeled, not just the attacker (`docs/design.md` §8).

| Key    | Required | Type    | Notes |
|--------|----------|---------|-------|
| `id`   | yes      | string  | Unique within the scenario; referenced by exchanges. |
| `role` | yes      | enum    | `master` \| `hmi` \| `ews` \| `outstation` \| `plc`. |
| `host` | yes      | string  | IPv4 address (PCAP emission builds IPv4 packets). |
| `port` | no       | integer | Server port; defaults to 502 (Modbus), 20000 (DNP3) or 102 (S7). |

Each client/server pair shares one TCP connection. Client ports are assigned
deterministically from 49152 upward, so emission is byte-reproducible.

### `exchanges`

| Key        | Required | Type    | Notes |
|------------|----------|---------|-------|
| `source`   | yes      | string  | A declared actor `id`; the client for requests. |
| `target`   | yes      | string  | A declared actor `id`. |
| `function` | yes      | string  | Protocol function; see the vocabularies below. |
| `offset`   | no       | number  | Seconds from `timing.start`. Omitted: `timing.default_interval` after the previous exchange. |
| `params`   | no       | mapping | Per-function parameters; unknown or unused keys are rejected. |

Each exchange becomes a request and its matched response (except where the
protocol has none). A connection never sends a message before its previous
response, so exchanges on one connection stay causally ordered. The JSON log is
sorted by timestamp across connections; timestamps have microsecond resolution.

### `timing` and `exercises`

| Key                        | Default | Notes |
|----------------------------|---------|-------|
| `timing.start`             | `0.0`   | Offset of the first exchange, in seconds. |
| `timing.default_interval`  | `1.0`   | Spacing for exchanges that omit `offset`. |
| `exercises.fires`          | `[]`    | Detection IDs that must fire (the Detection Contract, §6.6). |
| `exercises.quiet`          | `[]`    | Detection IDs that must stay silent. |

A detection ID in both lists is rejected. Tier-1 Sigma rules are checked by the
test harness and `substation demo`; Tier-2 Zeek rules by `make verify`.

## Function vocabularies

Functions accept the Zeek name (`READ_HOLDING_REGISTERS`), a CamelCase or spaced
spelling (`ReadHoldingRegisters`) or, where noted, a numeric code.

### Modbus

| Function | Params |
|---|---|
| Read coils / discrete inputs (1, 2) | `address`, `quantity` (1–2000) |
| Read holding / input registers (3, 4) | `address`, `quantity` (1–125) |
| Write single coil (5) | `address`, `value` (0 or 1) |
| Write single register (6) | `address`, `value` (0–65535) |
| Write multiple coils (15) | `address`, `values` (≤ 1968 bits) |
| Write multiple registers (16) | `address`, `values` (≤ 123 registers) |
| An undefined numeric code (e.g. `0x42`) | optional `address`, `quantity`; answered with `ILLEGAL_FUNCTION` |

Every function also accepts `unit_id` (0–255, default 1). A span must stay within
the 16-bit address space. Defined functions this emitter does not encode are
rejected rather than mis-emitted as undefined probes.

### DNP3

| Function | Params |
|---|---|
| `READ` | `object_type` (any, including `Class 0 Data`–`Class 3 Data`); response side: `range_low`, `range_high`, `object_count`, `iin`, and for class polls `response_object_type` |
| `WRITE` | `object_type` (a data object), `iin` |
| `ENABLE_UNSOLICITED`, `DISABLE_UNSOLICITED`, `ASSIGN_CLASS` | `object_type` (`Class 1 Data`–`Class 3 Data`, default `Class 1 Data`), `iin` |
| `SELECT`, `OPERATE`, `DIRECT_OPERATE`, `DIRECT_OPERATE_NR` | `index_number`, `operation_type`, `trip_control_code`, `on_time`, `off_time`, `execute_count`, `clear_bit`, `iin` |
| `UNSOLICITED_RESPONSE` (from the outstation) | `object_type`, `range_low`, `range_high`, `object_count`, `iin` |
| Any other request, or a numeric code 0–127 | `iin` (not on functions without a response) |

Requests come from the master and are answered with `RESPONSE`; `CONFIRM` and
the no-response functions get none. An unsolicited response is confirmed by the
master automatically. Responses echo control blocks with a status: a code outside
the interoperable set (IEEE 1815, per opendnp3: `Nul`, `Pulse On`, `Latch On`,
`Latch Off`, and `Pulse On` with `Close` or `Trip`) is answered `Not Supported`,
and an `OPERATE` is answered `No Select` unless it directly follows a `SELECT` of
the same block. Undefined function codes are answered with IIN2.0 (function not
supported).

### S7

| Function | Params |
|---|---|
| `SetupCommunication`, `ReadVariable`, `WriteVariable`, `PlcStop`, `DownloadEnded`, `StartUpload`, `Upload`, `EndUpload` | none |
| `PlcControl` | `service` (`P_PROGRAM`, `_MODU`, `_GARB`, `_INSE`, `_DELE`; default `P_PROGRAM`); for `_INSE`/`_DELE` also `block_type`, `block_number` |
| `RequestDownload`, `DownloadBlock` | `block_type` (e.g. `0A` = Data Block; default `0A`), `block_number` (five digits; default `00001`) |
| `ReadSZL` | `szl_id`, `szl_index` |
| `ListBlocks`, `ListBlocksOfType`, `GetBlockInfo` | none |
| `Explore`, `CreateObject`, `SetVariable`, `DeleteObject` (S7comm-plus) | `version` |

Each client connection opens with a COTP connection request and confirm, emitted
as their own events.

## Loading

```python
from substation.scenarios import load_scenario, load_scenarios

scenario = load_scenario("scenarios/modbus/benign-poll.yaml")
all_modbus = load_scenarios("scenarios/modbus")  # every *.yaml / *.yml, sorted
```

Malformed or inconsistent scenarios raise `substation.scenarios.ScenarioError`;
protocol-level problems (unknown functions, bad params) raise the protocol's
error when the scenario is emitted, before any file is written.
