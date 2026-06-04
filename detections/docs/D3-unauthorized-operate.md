# D3 — Unauthorized DNP3 control (operate / direct-operate)

A DNP3 output-control request (`SELECT` / `OPERATE` / `DIRECT_OPERATE` /
`DIRECT_OPERATE_NR`) — typically a Control-Relay-Output-Block driving a breaker or
setpoint — from a master that is **not** on the allow-list. The
unauthorized-control detection for the DNP3 slice (`PRD.md` §5.2).

| | |
|---|---|
| **Detection ID** | D3 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/dnp3_d3_unauthorized_operate.yml`](../sigma/dnp3_d3_unauthorized_operate.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

DNP3 controls physical outputs with **CROB** (Control Relay Output Block) commands
carried in `SELECT`/`OPERATE` (the two-pass select-before-operate sequence) or
`DIRECT_OPERATE`/`DIRECT_OPERATE_NR` (single-pass). A successful operate can trip or
close a breaker, start/stop a pump, or move a setpoint — directly affecting the
process. The detection keys on the **write policy for control**: who may operate
(allow-listed master). An operate from any other source fires.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: `direction: request`,
`func_name` is one of the four output-control commands, and `conn.orig_h` is the
issuer. No durable state or correlation is needed — Sigma-first per `PRD.md` §6.5.
The same rule compiles to production Zeek/SIEM unchanged. (Richer per-command detail
— index, operation type, trip code — is available in `detail.control` from ICSNPP
`dnp3_control.log`, but is not needed for the authorization decision.)

**Why allow-list, not "any operate" (the OT-realism guardrail, `PRD.md` §8).**
Operators legitimately issue controls all the time; a control-only rule is pure
false positives and discredits the project. The rule stays quiet on controls from
the **allow-listed master** and fires on everything else.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`):

- `proto` = `dnp3`, `direction` = `request`, `func_name` ∈
  {`SELECT`, `OPERATE`, `DIRECT_OPERATE`, `DIRECT_OPERATE_NR`} (Zeek
  `DNP3::function_codes[fc]`, spike 04).
- `conn.orig_h` — the issuing master on the request (derive source through
  `is_orig`, `docs/schema.md` → `conn`; assuming source==client would invert
  endpoints on the outstation's response).

## Detection logic

```
output_control:    proto=dnp3 AND direction=request
                   AND func_name in { SELECT, OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR }
authorized_source: conn.orig_h == 10.0.1.10 (master-1)
fire when:         output_control AND NOT authorized_source
```

## Scenarios

- **Fires:** [`dnp3-anomalous-d3-unauthorized-operate.yaml`](../../scenarios/dnp3/anomalous-d3-unauthorized-operate.yaml)
  — `rogue-1` (10.0.1.77, not allow-listed) issues `OPERATE` and `DIRECT_OPERATE`
  CROB commands amid a **legitimate operate from the allow-listed master**.
  Validated: D3 fires on exactly the two rogue controls and stays silent on the
  master's legitimate operate.
- **Quiet:** [`dnp3-benign-baseline.yaml`](../../scenarios/dnp3/benign-baseline.yaml)
  — the allow-listed master polls and operates legitimately. Validated: 0 hits. Also
  quiet on the D1/D2/D4 anomalous scenarios (none issue an operate from a
  non-allow-listed source).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Unauthorized Message: Command Message | **T1692.001** | Impair Process Control (TA0106) |

A non-allow-listed master sending DNP3 operate commands is precisely a *command
message which instructs control system assets to perform actions outside of their
intended functionality* (T1692.001) — the same technique as the Modbus
unauthorized-write detection M1, here over DNP3 control.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04. Note the matrix was **restructured**: the former *T0855 Unauthorized
> Command Message* is now **T1692.001** *Unauthorized Message: Command Message*
> (sub-technique of T1692, under Impair Process Control). Sources:
> <https://attack.mitre.org/techniques/T1692/001/>, tactic
> <https://attack.mitre.org/tactics/TA0106/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Legitimate operator controls** from the allow-listed master — the most common
  benign operate in OT. Handled: that source is allow-listed, so its controls stay
  quiet. The benign baseline exercises exactly this and produces 0 hits.
- **Allow-list staleness** — a new, replaced, or relocated master/HMI whose address
  is not yet listed fires until added. Mitigation: maintain the control-source
  allow-list as assets change.
- **Sanctioned maintenance** from an unlisted laptop — pre-authorize by adding the
  address for the maintenance window.

**Modelling note.** Like M1, D3 allow-lists by **source**; per-index/per-point
control policy (which outputs a given master may operate) is a richer policy that a
field-match rule does not express — a Zeek-class concern. Policy values (the
permitted master address) are demo-scenario specifics, edited per environment.
