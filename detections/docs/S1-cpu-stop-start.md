# S1 — Unauthorized S7 CPU stop / start (run-state change)

An S7comm run-state change — `PLC Stop` (function `0x29`) or `PLC Control`
(function `0x28`, service `P_PROGRAM` = "PLC Start / Stop") — from a source that is
**not** on the allow-list of permitted engineering workstations. The run-state
detection for the S7 slice (`PRD.md` §5.3).

| | |
|---|---|
| **Detection ID** | S1 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/s7comm_s1_cpu_stop_start.yml`](../sigma/s7comm_s1_cpu_stop_start.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

A Siemens PLC runs its control program in RUN mode. An adversary who can reach the
PLC on TCP/102 can halt it with an S7comm **PLC Stop** (`0x29`) or change its
operating mode with **PLC Control** carrying the `P_PROGRAM` service ("PLC Start /
Stop"). Stopping the CPU halts the control logic — the process is no longer being
driven — and is a precursor to (or consequence of) a program download. The detection
keys on the **run-state command + a source allow-list**: who may legitimately change
the PLC's run-state (the engineering workstation). A run-state change from any other
source fires.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: `direction: request`,
`func_name` is `PLC Stop` or `PLC Control`, and `conn.orig_h` is the issuer. No
durable state or correlation is needed — Sigma-first per `PRD.md` §6.5. The same rule
compiles to production Zeek/SIEM unchanged. (`detail.subfunction_name` carries the
decoded PLC-control service — e.g. `PLC Start / Stop` — from ICSNPP's `s7comm.log`,
available for richer policy but not needed for the authorization decision.)

**Why allow-list, not "any stop" (the OT-realism guardrail, `PRD.md` §8).** Engineers
legitimately stop/start a PLC during maintenance and commissioning; a command-only
rule is pure false positives and discredits the project. The rule stays quiet on
run-state changes from the **allow-listed EWS** and fires on everything else.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`, S7 `detail` frozen against ICSNPP
`s7comm.log` — spike 06):

- `proto` = `s7comm`, `direction` = `request`, `func_name` ∈ {`PLC Stop`,
  `PLC Control`} (ICSNPP `s7comm_functions[function_code]`).
- `conn.orig_h` — the issuing source on the request (derive source through
  `is_orig`, `docs/schema.md` → `conn`; assuming source==client would invert
  endpoints on the PLC's response).

## Detection logic

```
run_state_command: proto=s7comm AND direction=request
                   AND func_name in { PLC Stop, PLC Control }
authorized_source: conn.orig_h == 10.0.4.10 (ews-1)
fire when:         run_state_command AND NOT authorized_source
```

## Scenarios

- **Fires:** [`s7-anomalous-s1-cpu-stop.yaml`](../../scenarios/s7/anomalous-s1-cpu-stop.yaml)
  — `rogue-1` (10.0.4.66, not allow-listed) issues a `PLC Stop` amid a **legitimate
  PLC Control (start) from the allow-listed EWS**. Validated: S1 fires on exactly the
  rogue stop and stays silent on the EWS's legitimate run-state change.
- **Quiet:** [`s7-benign-baseline.yaml`](../../scenarios/s7/benign-baseline.yaml)
  — the allow-listed EWS performs a sanctioned run-state change; the HMI only reads
  and writes process tags. Validated: 0 hits. Also quiet on the S2/S3 anomalous
  scenarios (neither issues a run-state change from a non-allow-listed source).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Change Operating Mode | **T0858** | Execution (TA0104) |

Issuing an S7 PLC Stop / PLC Control to halt or restart the CPU is precisely a change
of the controller's operating mode (T0858). ATT&CK places T0858 under **Execution**
(and Evasion); the *effect* of a stop also inhibits the device's response function
(cf. the DNP3 restart detection D1 → T0816), which the false-positive discipline below
accounts for.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0858 *Change Operating Mode* exists and is assigned to tactics
> Execution (TA0104) and Evasion (TA0103). Sources:
> <https://attack.mitre.org/techniques/T0858/>, tactic
> <https://attack.mitre.org/tactics/TA0104/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Sanctioned engineering stop/start** from the allow-listed EWS — the most common
  benign run-state change in OT (maintenance, commissioning, program loads). Handled:
  that source is allow-listed, so its run-state changes stay quiet. The benign
  baseline exercises exactly this and produces 0 hits.
- **Allow-list staleness** — a new, replaced, or relocated engineering station whose
  address is not yet listed fires until added. Mitigation: maintain the
  control-source allow-list as assets change.
- **Sanctioned maintenance** from an unlisted laptop — pre-authorize by adding the
  address for the maintenance window.

**Modelling note.** Like M1/D3, S1 allow-lists by **source**. Some sites restrict
run-state changes to a maintenance time-window or to a specific operating-mode
transition — richer policy a field-match rule does not express (a Zeek-class concern).
The permitted EWS address is a demo-scenario specific, edited per environment.
