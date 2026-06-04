# M1 — Unauthorized Modbus register/coil write

A Modbus write-class function issued from a source that is **not** on the
allow-list of permitted writers (HMI/EWS). The unauthorized-command-message
detection for the Modbus slice (`PRD.md` §5.1).

| | |
|---|---|
| **Detection ID** | M1 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/modbus_m1_unauthorized_write.yml`](../sigma/modbus_m1_unauthorized_write.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

An actor that is not a sanctioned writer sends a Modbus write command — write
single/multiple coils or registers, mask-write, or read/write-multiple — to a
PLC. A successful write can change a setpoint, force a coil, or otherwise move
the physical process. The detection keys on **who issued the write**, measured
against an allow-list of permitted writers.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: the envelope says
it is a Modbus write request (`action_class: write`, `direction: request`) and
`conn.orig_h` says who sent it. No durable state, correlation window, or
multi-event join is needed, so this is the simplest engine that expresses the
behavior correctly — Sigma-first per `PRD.md` §6.5. The same rule compiles to a
production SIEM (Elastic/Splunk) or Zeek via stock pySigma backends, so it
transfers unchanged to a real deployment.

**Why allow-list, not "any write" (the OT-realism guardrail, `PRD.md` §8).**
Engineers legitimately write setpoints; a rule that fires on every write is pure
false positives and discredits the project. The rule therefore stays quiet on
writes from allow-listed HMI/EWS sources and fires only on writes from everyone
else.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`), envelope fields only:

- `proto` = `modbus`, `action_class` = `write`, `direction` = `request`.
- `conn.orig_h` — the writer. On a **request** (`is_orig: true`) the originator
  *is* the source, so `conn.orig_h` is the writer; the rule scopes to
  `direction: request` so it reads the writer correctly and fires once per write
  (not again on the response). Deriving source through `is_orig` is the schema's
  rule (`docs/schema.md` → `conn`); assuming source==client would invert
  endpoints on responses.

In production this maps to Zeek `conn.log` + ICSNPP `modbus_detailed.log`
(`is_orig`, `func`) with no rule change.

## Detection logic

```
modbus_write_request:  proto=modbus AND direction=request AND action_class=write
allowlisted_writers:   conn.orig_h in { 10.0.0.10 (hmi-1), 10.0.0.11 (ews-1) }
fire when:             modbus_write_request AND NOT allowlisted_writers
```

## Scenarios

- **Fires:** [`anomalous-m1-unauthorized-write.yaml`](../../scenarios/modbus/anomalous-m1-unauthorized-write.yaml)
  — `rogue-1` (10.0.0.77, not allow-listed) writes a setpoint register and forces
  coils amid normal HMI/EWS traffic. Validated: M1 fires on exactly the two rogue
  write requests and stays silent on the surrounding legitimate traffic.
- **Quiet:** [`benign-baseline.yaml`](../../scenarios/modbus/benign-baseline.yaml)
  — continuous HMI polling plus **legitimate EWS setpoint writes** from an
  allow-listed source. Validated: 0 hits.

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Unauthorized Message: Command Message | **T1692.001** | Impair Process Control (TA0106) |
| Related | Modify Parameter | T0836 | Impair Process Control (TA0106) |

An unauthorized writer sending Modbus write commands is precisely a *command
message which instructs systems and devices on how to operate* (T1692.001). When
those writes target setpoint/holding registers, T0836 Modify Parameter also
applies — its live page cites *"modification of system settings by reading and
writing to registers via Modbus commands."*

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS
> matrix on 2026-06-04. Note the matrix has been restructured since older
> references: the former *T0855 Unauthorized Command Message* is now
> **T1692.001** *Unauthorized Message: Command Message*. Sources:
> <https://attack.mitre.org/techniques/T1692/001/>,
> <https://attack.mitre.org/techniques/T0836/>,
> tactic <https://attack.mitre.org/tactics/TA0106/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Legitimate setpoint writes** from the HMI/EWS — the most common benign write
  in OT. Handled: those sources are allow-listed, so the rule keys on *source*,
  not the act of writing. The benign baseline exercises exactly this and stays
  quiet.
- **Allow-list staleness** — a new, replaced, or relocated HMI/EWS whose address
  is not yet listed will fire until added. Operational mitigation: maintain the
  writer allow-list as assets change (treat it as configuration).
- **Sanctioned maintenance** from an unlisted laptop — pre-authorize by adding
  the address to the allow-list for the maintenance window.

**Scope note — the unit/register dimension.** M1's full policy is *allow-list by
source **and** in-policy unit/register* (`PRD.md` §5.1: "or to a register/unit
outside policy"). This rule implements and tests the **source** dimension, the
one the M1 scenario exercises. Extending the allow-list to also flag an
*allow-listed* source writing an *out-of-policy* register/unit (e.g. outside the
writable setpoint range 40–49) needs numeric range matching — a flagged follow-up
for the offline evaluator (`docs/spikes/03-sigma-offline-evaluation.md`) — plus a
scenario that exercises it. Tracked as the next increment, not faked here.
