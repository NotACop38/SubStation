# S2 — Unauthorized S7 program / data-block download

An S7comm block download — `Request Download` (`0x1a`), `Download Block` (`0x1b`),
`Download Ended` (`0x1c`) — or the `PLC Control` (`0x28`) PI service `_INSE` that
activates a downloaded block, from a source that is **not** on the allow-list of
permitted engineering workstations. The program-modification detection for the S7
slice (`docs/design.md` §5.3).

| | |
|---|---|
| **Detection ID** | S2 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/s7comm_s2_program_write_download.yml`](../sigma/s7comm_s2_program_write_download.yml) |
| **Status** | experimental · **Level** | high |

## Example policy and limits

The approved channel is `10.0.4.10` → `10.0.4.50:102`. A listed source
sending the matched command to another asset or port still fires. These are
synthetic addresses, not authenticated identities. Compromise of an approved
source and in-channel misuse require other signals. The rule has experimental
status; synthetic quiet tests do not measure a site's false-positive rate.

## Behavior

The control logic and data blocks running on a classic Siemens PLC (S7-300/400) are
changed by **downloading** a block: `Request Download` → `Download Block` →
`Download Ended`, logged by ICSNPP in `s7comm_upload_download.log` with the block
type (e.g. `Data Block`, `Function Block`, `Organization Block`) and number. The
engineering tool then issues `PLC Control` with the PI service `_INSE` to activate
the block in the CPU. Either step **replaces the logic the PLC executes** — a
high-impact engineering action. The detection keys on the **transfer or activation
command + a source allow-list**: who may legitimately download program logic (the
engineering workstation). The same command from any other source fires.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: `direction: request`,
the command is a block transfer or `_INSE`, and `conn.orig_h` is the issuer. No
durable state or correlation is needed — Sigma-first per `docs/design.md` §6.5. The
rule needs normalization and backend qualification for a SIEM deployment.

**Why allow-list, and why plain `Write Variable` is excluded (the OT-realism
guardrail, `docs/design.md` §8).** Operators legitimately write process **tags** all
the time via `Write Variable` (setpoints) — an "any write fires" rule is pure false
positives. S2 therefore matches **only the block-transfer commands and `_INSE`**,
never plain `Write Variable`, and additionally allow-lists by channel so a sanctioned
engineering download stays quiet. The benign baseline exercises a legitimate EWS
download *and* routine HMI `Write Variable` tag writes and produces 0 hits.

**Why S7comm-plus is not matched.** On S7-1200/1500 a download travels over
S7comm-plus as object operations, but the same function codes carry routine
traffic: every session opens with `Create Object` and closes with `Delete Object`,
and HMIs read and write tags with `Get/Set Variable`. Function codes alone cannot
separate a program download from normal operation; matching them fires on ordinary
HMI sessions. The benign baseline includes such a session (`hmi-2`) so that failure
mode stays tested.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`, S7 `detail` frozen against ICSNPP
`s7comm.log` / `s7comm_upload_download.log` — spike 06):

- `proto` = `s7comm`, `direction` = `request`, and either `func_name` ∈
  {`Request Download`, `Download Block`, `Download Ended`}, or `func_name` =
  `PLC Control` with `detail.subfunction_code` = `_INSE` (ICSNPP logs the PI service
  name in `subfunction_code`).
- `conn.orig_h` — the issuing source on the request (derive source through
  `is_orig`, `docs/schema.md` → `conn`).

## Detection logic

```
program_transfer:  proto=s7comm AND direction=request
                   AND ( func_name in { Request Download, Download Block, Download Ended }
                         OR (func_name = PLC Control AND detail.subfunction_code = _INSE) )
authorized_channel: conn.orig_h == 10.0.4.10 (ews-1)
                    AND conn.resp_h == 10.0.4.50 AND conn.resp_p == 102
fire when:         program_transfer AND NOT authorized_channel
```

## Scenarios

- **Fires:** [`s7-anomalous-s2-program-download.yaml`](../../scenarios/s7/anomalous-s2-program-download.yaml)
  — `rogue-1` (10.0.4.66, not allow-listed) downloads Data Block 2
  (`Request Download` → `Download Block` → `Download Ended`) and activates it with
  `_INSE`, amid legitimate EWS reads. S2 fires on exactly those four requests.
- **Quiet:** [`s7-benign-baseline.yaml`](../../scenarios/s7/benign-baseline.yaml)
  — the allow-listed EWS performs a sanctioned program download, the HMI writes a
  setpoint with `Write Variable`, and a second HMI runs an S7comm-plus session
  (`Create Object`, `Explore`, two `Set Variable`, `Delete Object`): 0 hits. Also
  quiet on the S1/S3 anomalous scenarios (neither transfers a block from a
  non-allow-listed source).

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

> **VERIFY (`AGENTS.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0843 *Program Download* exists and is assigned to tactic Lateral
> Movement (TA0109). Sources: <https://attack.mitre.org/techniques/T0843/>, tactic
> <https://attack.mitre.org/tactics/TA0109/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Sanctioned engineering downloads** from the allow-listed EWS — the everyday
  benign program transfer. Handled: that channel is allow-listed, so its downloads
  stay quiet. The benign baseline exercises exactly this and produces 0 hits.
- **Routine operator tag writes** (`Write Variable`) and **S7comm-plus sessions** —
  intentionally **not** matched, so normal HMI traffic never trips this detection.
- **Allow-list staleness** — a new/relocated engineering station fires on its
  legitimate downloads until added; maintain the control-source allow-list.

## Known gaps

- **S7comm-plus downloads** (S7-1200/1500) are not detected, for the reason above.
  Detecting them needs payload-level object semantics that function codes do not
  carry.
- **Block deletion** (`_DELE`) and **uploads** are not matched: deletion is
  destructive rather than a download, and an upload reads logic out of the PLC.
- **Per-block policy** (which blocks a given station may download) is richer than a
  field-match rule expresses — a Zeek-class concern. Like M1/D3, S2 allow-lists by
  **source, destination and service**; the permitted EWS address is demo-scenario
  specific and edited per environment.
