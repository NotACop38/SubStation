# D1 — Unauthorized DNP3 cold/warm restart

A DNP3 device-restart function (`COLD_RESTART` / `WARM_RESTART`) issued by a source
that is **not** the allow-listed master. Forcing an outstation to restart inhibits
its response and reporting function — the DNP3 restart detection for the DNP3 slice
(`PRD.md` §5.2).

| | |
|---|---|
| **Detection ID** | D1 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/dnp3_d1_unauthorized_restart.yml`](../sigma/dnp3_d1_unauthorized_restart.yml) |
| **Status** | experimental · **Level** | high |

## Behavior

A DNP3 master sends a `COLD_RESTART` (0x0d) or `WARM_RESTART` (0x0e) application
request to an outstation. A restart drops the device offline and clears its state —
during the restart the outstation cannot answer polls or send events, so the master
is blinded and the process loses its reporting channel. The detection keys on the
**restart command from a non-allow-listed source**: a restart from any source other
than the permitted master fires.

## Engine choice + rationale

**Sigma.** Authorization is decidable from a **single event**: the envelope says it
is a DNP3 request (`direction: request`), `func_name` is the restart command, and
`conn.orig_h` says who sent it. No durable state, correlation window, or multi-event
join is needed, so this is the simplest engine that expresses the behavior correctly
— Sigma-first per `PRD.md` §6.5. The same rule compiles to a production SIEM or Zeek
via stock pySigma backends, so it transfers unchanged.

**Why allow-list, not "any restart" (the OT-realism guardrail, `PRD.md` §8).**
Engineers legitimately restart outstations during maintenance/commissioning. A rule
that fires on every restart would be false positives during planned work. The rule
stays quiet on restarts from the **allow-listed master** and fires on everything
else.

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`):

- `proto` = `dnp3`, `direction` = `request`, `func_name` ∈
  {`COLD_RESTART`, `WARM_RESTART`}. `func_name` carries Zeek's
  `DNP3::function_codes[fc]` name (spike 04), so the rule transfers to production
  Zeek `dnp3.log` (`fc_request`) unchanged.
- `conn.orig_h` — the issuing source. On a **request** (`is_orig: true`) the
  originator *is* the source (`docs/schema.md` → `conn`), so `conn.orig_h` is the
  master that issued the restart.

## Detection logic

```
restart_command:   proto=dnp3 AND direction=request
                   AND func_name in { COLD_RESTART, WARM_RESTART }
authorized_source: conn.orig_h == 10.0.1.10 (master-1)
fire when:         restart_command AND NOT authorized_source
```

## Scenarios

- **Fires:** [`dnp3-anomalous-d1-restart.yaml`](../../scenarios/dnp3/anomalous-d1-restart.yaml)
  — `rogue-1` (10.0.1.77, not the allow-listed master) issues a `COLD_RESTART` amid
  normal master polling and unsolicited reporting. Validated: D1 fires on exactly
  the rogue restart and stays silent on the surrounding legitimate traffic.
- **Quiet:** [`dnp3-benign-baseline.yaml`](../../scenarios/dnp3/benign-baseline.yaml)
  — the allow-listed master polls, enables unsolicited reporting and operates; no
  restart is issued. Validated: 0 hits. Also stays quiet on the D2/D3/D4 anomalous
  scenarios (no restart in any of them).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Device Restart/Shutdown | **T0816** | Inhibit Response Function (TA0107) |
| Related | Denial of Service | T0814 | Inhibit Response Function (TA0107) |

Forcing a DNP3 outstation to restart is precisely *forcibly restart or shutdown a
device in an ICS environment to disrupt and potentially negatively impact physical
processes* (T0816). While the device is down its function is denied (T0814).

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0816 and T0814 are both listed under the Inhibit Response Function
> tactic (TA0107). Sources: <https://attack.mitre.org/techniques/T0816/>,
> <https://attack.mitre.org/techniques/T0814/>, tactic
> <https://attack.mitre.org/tactics/TA0107/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Sanctioned maintenance restart** from the allow-listed master — the most common
  benign restart. Handled: the master's address is allow-listed, so its restarts are
  in-policy and stay quiet. Operational mitigation: maintain the control-source
  allow-list as masters are added/relocated (treat it as configuration).
- **Redundant/standby master failover** issuing a restart from an unlisted address —
  pre-authorize it (add the standby to the allow-list).

**Policy values** (the permitted master address) are demo-scenario specifics, meant
to be edited per environment. In a deployment with several legitimate masters, list
all of them.
