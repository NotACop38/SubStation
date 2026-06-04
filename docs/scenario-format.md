# Scenario format

A **scenario** is the single source of truth for one simulator run (`PRD.md`
§6.1). It is human-editable YAML under `scenarios/<proto>/`, loaded into a typed,
immutable model (`substation/scenarios/model.py`) that — in later phases — drives
**both** the PCAP and JSON emitters so the two outputs can never drift.

The canonical, fully commented example is
[`scenarios/modbus/benign-poll.yaml`](../scenarios/modbus/benign-poll.yaml). This
document is the reference for the fields and validation rules.

> **Status (Phase 0):** the format is defined and loaded; exchanges describe
> *intent* only. The per-protocol encoders that turn exchanges into PCAP/JSON
> bytes land in Phase 1. The `params` bag shape is frozen per protocol then.

## Top-level keys

| Key           | Required | Type             | Notes                                                        |
|---------------|----------|------------------|--------------------------------------------------------------|
| `name`        | yes      | string           | Filesystem-safe basename (`[A-Za-z0-9._-]`, no path separators); names the generated artifacts. |
| `description` | no       | string           | Free-form prose.                                             |
| `protocol`    | yes      | enum             | `modbus` \| `dnp3` \| `s7comm` (closed v1 set, `PRD.md` §5). |
| `label`       | yes      | enum             | `benign` \| `anomalous` — ground-truth intent.               |
| `actors`      | yes      | list (non-empty) | Network participants; see below.                             |
| `exchanges`   | yes      | list             | Ordered protocol exchanges; may be empty.                    |
| `timing`      | no       | mapping          | Scenario-level timing.                                       |
| `exercises`   | no       | mapping          | Detection IDs this scenario fires / keeps quiet.             |

Unknown top-level keys are rejected.

### `label` and the Detection Contract

- `benign` → every detection in `exercises.quiet` **must stay silent**.
- `anomalous` → every detection in `exercises.fires` **must fire**.

This is what the test harness (Phase 1+) enforces as the Detection Contract
(`PRD.md` §6.6).

### `actors`

Each actor is a mapping. Roles are first-class because credible detections
require modelling a legitimate writer/master, not just the attacker (`PRD.md`
§6.4, §8).

| Key    | Required | Type    | Notes                                                          |
|--------|----------|---------|----------------------------------------------------------------|
| `id`   | yes      | string  | Unique within the scenario; referenced by exchanges.           |
| `role` | yes      | enum    | `master` \| `hmi` \| `ews` \| `outstation` \| `plc`.           |
| `host` | yes      | string  | IP/hostname of the actor.                                      |
| `port` | no       | integer | TCP port (e.g. Modbus/TCP 502).                                |

Duplicate actor ids are rejected.

### `exchanges`

An ordered list; order is significant. Each exchange is a mapping.

| Key        | Required | Type    | Notes                                                       |
|------------|----------|---------|-------------------------------------------------------------|
| `source`   | yes      | string  | Must be a declared actor `id`.                              |
| `target`   | yes      | string  | Must be a declared actor `id`.                              |
| `function` | yes      | string  | Protocol function name (free-form in Phase 0).              |
| `offset`   | no       | number  | Seconds from `timing.start`. If omitted, the exchange is auto-spaced `timing.default_interval` after the previous one (an explicit value, including `0.0`, always wins). |
| `params`   | no       | mapping | Opaque per-protocol payload bag (frozen per protocol later).|

Exchanges referencing an undeclared actor id are rejected.

### `timing`

| Key                | Required | Type   | Default | Notes                                  |
|--------------------|----------|--------|---------|----------------------------------------|
| `start`            | no       | number | `0.0`   | Offset of the first exchange (seconds).|
| `default_interval` | no       | number | `1.0`   | Spacing applied to exchanges that omit `offset`.|

### `exercises`

| Key     | Required | Type            | Notes                                       |
|---------|----------|-----------------|---------------------------------------------|
| `fires` | no       | list of strings | Detection IDs that must alert (anomalous).  |
| `quiet` | no       | list of strings | Detection IDs that must stay silent (benign).|

A detection ID may not appear in both `fires` and `quiet` (unsatisfiable) — the
loader rejects it.

## Loading

```python
from substation.scenarios import load_scenario, load_scenarios

scenario = load_scenario("scenarios/modbus/benign-poll.yaml")
all_modbus = load_scenarios("scenarios/modbus")  # every *.yaml / *.yml, sorted
```

Malformed or inconsistent scenarios raise `substation.scenarios.ScenarioError`
with a path-prefixed message.
