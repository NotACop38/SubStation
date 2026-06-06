# M1 — Unauthorized Modbus register/coil write

A Modbus write-class function that is **not** an in-policy setpoint write — either
from a source that is **not** an allow-listed writer (HMI/EWS), or from an
allow-listed source straying to an **out-of-policy unit/register**. The
unauthorized-command-message detection for the Modbus slice (`PRD.md` §5.1).

| | |
|---|---|
| **Detection ID** | M1 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/modbus_m1_unauthorized_write.yml`](../sigma/modbus_m1_unauthorized_write.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

A Modbus write command reaches a PLC outside the write policy. The Tier-1 simulator
currently validates write single/multiple coils or registers; production
ICSNPP-aligned telemetry that classifies mask-write, read/write-multiple, or
write-file records as `action_class: write` is covered by the same rule. A
successful write can change a setpoint, force a coil, or otherwise move the
physical process. The detection keys on the **write policy**: who may write
(allow-listed HMI/EWS), to which **unit**, and which **registers**. A write that
violates any of those dimensions fires — including an allow-listed source straying
to an out-of-policy unit/register.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: the envelope says
it is a Modbus write request (`action_class: write`, `direction: request`),
`conn.orig_h` says who sent it, and `detail.unit` / `detail.address` say what it
targets — everything the policy needs is on the one event. No durable state,
correlation window, or multi-event join is needed, so this is the simplest engine
that expresses the behavior correctly — Sigma-first per `PRD.md` §6.5. The same
rule compiles to a production SIEM (Elastic/Splunk) or Zeek via stock pySigma
backends, so it transfers unchanged to a real deployment. The writable-register
policy is written as an explicit value list (not a range modifier) so the Tier-1
offline evaluator (`docs/spikes/03-sigma-offline-evaluation.md`) can match it with
no new machinery.

**Why allow-list, not "any write" (the OT-realism guardrail, `PRD.md` §8).**
Engineers legitimately write setpoints; a rule that fires on every write is pure
false positives and discredits the project. The rule therefore stays quiet on
**in-policy** writes (allow-listed source, permitted unit, writable register) and
fires on everything else.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`):

- `proto` = `modbus`, `action_class` = `write`, `direction` = `request`.
- `conn.orig_h` — the writer. On a **request** (`is_orig: true`) the originator
  *is* the source, so `conn.orig_h` is the writer; the rule scopes to
  `direction: request` so it reads the writer correctly and fires once per write
  (not again on the response). Deriving source through `is_orig` is the schema's
  rule (`docs/schema.md` → `conn`); assuming source==client would invert
  endpoints on responses.
- `detail.unit` / `detail.address` — the write's target unit and starting
  register, checked against the permitted unit and the writable-register set.

In production this maps to Zeek `conn.log` + ICSNPP `modbus_detailed.log`
(`is_orig`, `func`, `unit`, `address`) with no rule change.

## Detection logic

```
modbus_write_request:  proto=modbus AND direction=request AND action_class=write
in_policy_write:       conn.orig_h in { 10.0.0.10 (hmi-1), 10.0.0.11 (ews-1) }
                       AND detail.unit == 1
                       AND detail.address in { 40..49 }   # writable setpoints
fire when:             modbus_write_request AND NOT in_policy_write
```

A write is in-policy only if **all three** hold (allow-listed source, permitted
unit, writable register); failing any one fires.

## Scenarios

- **Fires:** [`anomalous-m1-unauthorized-write.yaml`](../../scenarios/modbus/anomalous-m1-unauthorized-write.yaml)
  — `rogue-1` (10.0.0.77, not allow-listed) writes a setpoint register and forces
  coils amid normal HMI/EWS traffic. Validated: M1 fires on exactly the two rogue
  write requests and stays silent on the surrounding legitimate traffic.
- **Fires:** [`anomalous-m1-out-of-policy-write.yaml`](../../scenarios/modbus/anomalous-m1-out-of-policy-write.yaml)
  — the allow-listed `ews-1` (10.0.0.11) writes a non-permitted unit (2) and an
  out-of-range register (5). Validated: M1 fires on both off-policy writes and
  stays silent on the EWS's in-policy write to register 40.
- **Quiet:** [`benign-baseline.yaml`](../../scenarios/modbus/benign-baseline.yaml)
  — continuous HMI polling plus **legitimate EWS setpoint writes** from an
  allow-listed source to in-policy registers. Validated: 0 hits.

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
  in OT. Handled: those sources are allow-listed **and** the benign writes target
  the permitted unit and registers, so they are in-policy and stay quiet. The
  benign baseline exercises exactly this and produces 0 hits.
- **Allow-list staleness** — a new, replaced, or relocated HMI/EWS whose address
  is not yet listed will fire until added. Operational mitigation: maintain the
  writer allow-list as assets change (treat it as configuration).
- **Process re-design** — a newly commissioned setpoint register outside 40–49,
  or a second legitimate unit, fires until policy is updated. Mitigation: update
  the in-policy unit/register set when the process design changes.
- **Sanctioned maintenance** from an unlisted laptop — pre-authorize by adding the
  address to the allow-list for the maintenance window.

**Unit/register policy (implemented).** M1 enforces all three dimensions of
`PRD.md` §5.1 — source, unit, and register — so an allow-listed source straying to
an out-of-policy unit/register fires, not just a rogue source. The register set is
written as explicit values so the Tier-1 evaluator matches it today (no
range-modifier dependency). Two known modelling simplifications, neither exercised
as a false positive by the current scenarios: (1) the register set is the
**holding-register setpoint** space — the demo policy sanctions no coil writes, so
coil writes are out-of-policy by design; (2) the check is on the **starting**
`detail.address`, so a write that starts in-policy but spans past register 49 (via
a large `quantity`) is not caught by a field-match rule — durable span arithmetic
is a Zeek-class concern. Policy values (writers, unit, register set) are
demo-scenario specifics, meant to be edited per environment.
