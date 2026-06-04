# D4 — DNP3 function-code enumeration / scanning

A single source exercising an anomalously **diverse** set of DNP3 application
function codes against one outstation in a short window — mapping which functions the
device supports (`PRD.md` §5.2). The DNP3 slice's **Zeek** rail, mirroring Modbus M3.

| | |
|---|---|
| **Detection ID** | D4 |
| **Engine** | Zeek (Tier 2, over PCAP) |
| **Rule** | [`detections/zeek/dnp3_d4_function_enumeration.zeek`](../zeek/dnp3_d4_function_enumeration.zeek) |
| **Status** | tier2 · **Level** | medium |

## Behavior

An attacker profiling a DNP3 outstation walks through many application function codes
(read, write, freeze, class assignment, time, file info, …) to learn which the device
supports and how it responds — reconnaissance before targeted action. The signal is
**function-code diversity from one source**, deliberately **not** request volume:
SCADA masters poll constantly, so a volume threshold fires on normal operation
(`PRD.md` §8). D4 counts the number of **distinct** request function codes a source
sends to one outstation within a window and alerts when that exceeds a threshold
tuned above a legitimate master's working set.

## Engine choice + rationale

**Zeek.** Enumeration needs **durable per-source state** — the set of distinct
function codes accumulated over a window — plus a cardinality test. A stateless Sigma
field-match over a single event cannot express "this source has now touched ≥ N
distinct function codes." This is the DNP3 slice's mandated Zeek rail (the slice
ships Sigma **and** Zeek detections, `PRD.md` §6.5), directly analogous to Modbus M3.
Because it requires its engine, its fire/quiet is validated in **Tier 2** (Zeek over
PCAP); the Tier-1 harness still enforces its contract linkage (rule + a fire and a
quiet scenario).

**Why diversity, not volume (the OT-realism guardrail, `PRD.md` §8).** A master
polling one function thousands of times is normal; one source touching many
*different* functions in seconds is not. Keying on distinct-code cardinality (default
threshold 6) — reset per window — keeps routine multi-function operation quiet.

## Data source

Tier-2: Zeek's **base** DNP3 analyzer `dnp3_application_request_header` event
(`fc`, `c$id$orig_h`) — no ICSNPP dependency. The event/field names were verified
against `zeek/zeek` `base/protocols/dnp3` on 2026-06-04
(`docs/spikes/04-icsnpp-dnp3-fields.md`). In the Tier-1 `.jsonl` the same signal is
visible as the set of distinct `func_code` on `direction: request` events per
`conn.orig_h`, but the stateful threshold is a Zeek concern.

## Detection logic

```
per (source, outstation) within enum_window (60s from first contact):
    funcs <- set of distinct request function codes
fire when: |funcs| >= func_code_threshold (default 6), once per window
```

The per-window `alerted` flag lives in the same record as the diversity set and
expires with it (`&create_expire`), so a new sweep after the window re-alerts and is
not masked by a suppression timer that outlives the diversity reset (the Modbus M3
review fix, carried over).

## Scenarios

- **Fires:** [`dnp3-anomalous-d4-enumeration.yaml`](../../scenarios/dnp3/anomalous-d4-enumeration.yaml)
  — `scanner-1` (10.0.1.66) walks **nine** distinct function codes against the
  outstation in a tight window. Fire/quiet executes in the Tier-2 Zeek runner.
- **Quiet:** [`dnp3-benign-baseline.yaml`](../../scenarios/dnp3/benign-baseline.yaml)
  — the master uses a small working set (READ, ENABLE_UNSOLICITED, OPERATE), well
  below the threshold.

The enumeration scenario deliberately uses neutral discovery-class codes and avoids
the restart / disable-unsolicited / operate commands D1–D3 key on, so it fires D4
cleanly. A real enumeration that also issued those would, correctly, *additionally*
trip D1–D3 — verified: the Tier-1 Sigma rules stay quiet on this scenario.

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Remote System Information Discovery | **T0888** | Discovery (TA0102) |
| Related | Remote System Discovery | T0846 | Discovery (TA0102) |

Enumerating which DNP3 functions an outstation supports *gathers detailed information
about remote systems … including role and configuration* (T0888); probing the device
by logical function also contributes to remote system discovery (T0846).

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0888 and T0846 are both listed under the Discovery tactic (TA0102).
> Sources: <https://attack.mitre.org/techniques/T0888/>,
> <https://attack.mitre.org/techniques/T0846/>, tactic
> <https://attack.mitre.org/tactics/TA0102/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **A busy master using many functions** (read, write, operate, enable/disable
  unsolicited, an occasional restart) over a long run. Handled: the threshold is
  tuned above a legitimate working set, and diversity resets per `enum_window`, so a
  handful of codes spread over time never accrues a false sweep.
- **A commissioning/diagnostic tool** legitimately exercising many functions during
  acceptance testing — expected to be a known, time-boxed activity from a known host;
  tune `func_code_threshold` / `enum_window` or exclude the host for the window.

**Tuning values** (`func_code_threshold`, `enum_window`) are `&redef`-able Zeek
consts, set per environment.
