# D2 — DNP3 disable unsolicited responses (alarm/telemetry blinding)

A DNP3 `DISABLE_UNSOLICITED` request from a source that is **not** the allow-listed
master. Disabling unsolicited responses suppresses the outstation's spontaneous
event/telemetry reporting — blinding the operator to alarms (`PRD.md` §5.2).

| | |
|---|---|
| **Detection ID** | D2 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/dnp3_d2_disable_unsolicited.yml`](../sigma/dnp3_d2_disable_unsolicited.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

DNP3 outstations report events spontaneously via **unsolicited responses** (function
`UNSOLICITED_RESPONSE`, 0x82) — this is how a master learns about alarms and state
changes between integrity polls. A `DISABLE_UNSOLICITED` (0x15) command tells the
outstation to stop sending them. An attacker who disables unsolicited reporting
**blinds the operator**: alarms and telemetry no longer flow, masking subsequent
process manipulation. The detection keys on the disable command from a
non-allow-listed source.

## Engine choice + rationale

**Sigma.** The signal is on a **single event**: `direction: request`, `func_name`
= `DISABLE_UNSOLICITED`, and `conn.orig_h` = the issuer. No state or correlation is
needed — Sigma-first per `PRD.md` §6.5. The same rule compiles to production
Zeek/SIEM unchanged.

**Why allow-list, not "any disable" (the OT-realism guardrail, `PRD.md` §8).** A
master may legitimately disable unsolicited mode (e.g. while reconfiguring event
classes during maintenance). Allow-listing the permitted master keeps that quiet
while still catching a disable from any other source — the blinding signal.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`):

- `proto` = `dnp3`, `direction` = `request`, `func_name` = `DISABLE_UNSOLICITED`
  (Zeek `DNP3::function_codes[fc]`, spike 04 — maps to production `dnp3.log`
  `fc_request`).
- `conn.orig_h` — the issuing source on the request (`is_orig: true`; derive source
  through `is_orig`, `docs/schema.md` → `conn`).

## Detection logic

```
disable_unsolicited: proto=dnp3 AND direction=request AND func_name == DISABLE_UNSOLICITED
authorized_source:   conn.orig_h == 10.0.1.10 (master-1)
fire when:           disable_unsolicited AND NOT authorized_source
```

## Scenarios

- **Fires:** [`dnp3-anomalous-d2-disable-unsolicited.yaml`](../../scenarios/dnp3/anomalous-d2-disable-unsolicited.yaml)
  — `rogue-1` (10.0.1.77) sends `DISABLE_UNSOLICITED` amid normal polling and
  unsolicited responses. Validated: D2 fires on exactly the rogue disable.
- **Quiet:** [`dnp3-benign-baseline.yaml`](../../scenarios/dnp3/benign-baseline.yaml)
  — the allow-listed master **enables** unsolicited reporting and never disables it;
  the outstation sends unsolicited responses freely. Validated: 0 hits. Also quiet on
  the D1/D3/D4 anomalous scenarios.

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Block Operational Technology Message: Reporting Message | **T1691.002** | Inhibit Response Function (TA0107) |
| Related | Alarm Suppression | T0878 | Inhibit Response Function (TA0107) |

Disabling unsolicited responses *blocks a reporting message from reaching its
intended target* — reporting messages carry telemetry about current equipment state
(T1691.002). By stopping event-driven alarms it also suppresses alarms (T0878).

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04. Note the matrix was **restructured**: the former *T0804 Block
> Reporting Message* is now **T1691.002** *Block Operational Technology Message:
> Reporting Message* (sub-technique of T1691). Sources:
> <https://attack.mitre.org/techniques/T1691/002/>,
> <https://attack.mitre.org/techniques/T0878/>, tactic
> <https://attack.mitre.org/tactics/TA0107/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Maintenance reconfiguration** where the allow-listed master disables unsolicited
  mode to re-assign event classes — handled by the allow-list (the master is listed,
  so its disables stay quiet). Mitigation: keep the allow-list current.
- **Redundant/standby master** re-negotiating unsolicited mode from an unlisted
  address — pre-authorize it.

**Policy values** (the permitted master address) are demo-scenario specifics, edited
per environment.
