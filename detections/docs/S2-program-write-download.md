# S2 — Unauthorized S7 program / data-block write or download

An S7comm program/data-block transfer — `Request Download` (`0x1a`),
`Download Block` (`0x1b`), `Download Ended` (`0x1c`) — or an S7comm-plus object write
(`Create Object` `0x04ca`, `Set Variable` `0x04f2`, `Delete Object` `0x04d4`) from a
source that is **not** on the allow-list of permitted engineering workstations. The
program-modification detection for the S7 slice (`PRD.md` §5.3).

| | |
|---|---|
| **Detection ID** | S2 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/s7comm_s2_program_write_download.yml`](../sigma/s7comm_s2_program_write_download.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

The control logic and data blocks running on a Siemens PLC are changed by
**downloading** a block: the classic S7comm sequence is `Request Download` →
`Download Block` → `Download Ended`, logged by ICSNPP in `s7comm_upload_download.log`
with the block type (e.g. `Data Block`, `Function Block`, `Organization Block`) and
number. On S7-1200/1500 the same effect is achieved with S7comm-plus object
operations (`Create Object` / `Set Variable`). Downloading or modifying program/data
blocks **replaces the logic the PLC executes** — a high-impact engineering action. The
detection keys on the **transfer command + a source allow-list**: who may legitimately
download program logic (the engineering workstation). A transfer from any other source
fires.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: `direction: request`,
`func_name` is one of the transfer/object-write commands, and `conn.orig_h` is the
issuer. No durable state or correlation is needed — Sigma-first per `PRD.md` §6.5. The
same rule compiles to production Zeek/SIEM unchanged.

**Why allow-list, and why plain `Write Variable` is excluded (the OT-realism
guardrail, `PRD.md` §8).** Operators legitimately write process **tags** all the time
via `Write Variable` (setpoints) — a "any write fires" rule is pure false positives.
S2 therefore matches **only the program/block-transfer and object-write commands**,
never plain `Write Variable`, and additionally allow-lists by source so a sanctioned
engineering download stays quiet. The benign baseline exercises both a legitimate EWS
download *and* routine HMI `Write Variable` tag writes and produces 0 hits.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`, S7 `detail` frozen against ICSNPP
`s7comm.log` / `s7comm_upload_download.log` / `s7comm_plus.log` — spike 06):

- `proto` = `s7comm`, `direction` = `request`, `func_name` ∈ {`Request Download`,
  `Download Block`, `Download Ended`, `Create Object`, `Set Variable`,
  `Delete Object`}.
- `conn.orig_h` — the issuing source on the request (derive source through
  `is_orig`, `docs/schema.md` → `conn`).

## Detection logic

```
program_transfer:  proto=s7comm AND direction=request
                   AND func_name in { Request Download, Download Block, Download Ended,
                                      Create Object, Set Variable, Delete Object }
authorized_source: conn.orig_h == 10.0.4.10 (ews-1)
fire when:         program_transfer AND NOT authorized_source
```

## Scenarios

- **Fires:** [`s7-anomalous-s2-program-download.yaml`](../../scenarios/s7/anomalous-s2-program-download.yaml)
  — `rogue-1` (10.0.4.66, not allow-listed) downloads a Data Block
  (`Request Download` → `Download Block` → `Download Ended`) and issues an S7comm-plus
  `Create Object`, amid legitimate EWS reads. Validated: S2 fires on the rogue
  transfers and stays silent on benign reads.
- **Quiet:** [`s7-benign-baseline.yaml`](../../scenarios/s7/benign-baseline.yaml)
  — the allow-listed EWS performs a sanctioned program download and the HMI issues a
  legitimate `Write Variable` setpoint. Validated: 0 hits. Also quiet on the S1/S3
  anomalous scenarios (neither issues a program transfer from a non-allow-listed
  source).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Program Download | **T0843** | Lateral Movement (TA0109) |

Downloading program/data blocks to a PLC from a non-allow-listed source is precisely
*Program Download* (T0843) — the technique adversaries use to push control logic onto
controllers. Writing data blocks specifically also relates to *Modify Parameter*
(T0836, Impair Process Control) and *Modify Program* (T0889, Persistence); S2 maps to
the marquee transfer technique and notes the others here rather than over-claiming a
second tactic in the coverage map.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0843 *Program Download* exists and is assigned to tactic Lateral
> Movement (TA0109). Sources: <https://attack.mitre.org/techniques/T0843/>, tactic
> <https://attack.mitre.org/tactics/TA0109/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Sanctioned engineering downloads** from the allow-listed EWS — the everyday
  benign program transfer. Handled: that source is allow-listed, so its downloads stay
  quiet. The benign baseline exercises exactly this and produces 0 hits.
- **Routine operator tag writes** (`Write Variable`) — intentionally **not** matched,
  so normal HMI setpoint writes never trip this detection.
- **Allow-list staleness** — a new/relocated engineering station fires on its
  legitimate downloads until added; maintain the control-source allow-list.

**Modelling note.** Like M1/D3, S2 allow-lists by **source**. Per-block policy (which
blocks a given station may download) is a richer policy that a field-match rule does
not express — a Zeek-class concern. The permitted EWS address is a demo-scenario
specific, edited per environment.
