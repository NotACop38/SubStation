# M3 — Modbus function-code / unit-ID sweep

One source touching an anomalously **diverse** set of Modbus function codes
and/or unit IDs against a single PLC in a short window — the sweep/enumeration
detection for the Modbus slice (`PRD.md` §5.1). **Diversity, not volume.**

| | |
|---|---|
| **Detection ID** | M3 |
| **Engine** | Zeek (Tier 2, over the PCAP via the base Modbus analyzer) |
| **Rule** | [`detections/zeek/modbus_m3_unit_function_sweep.zeek`](../zeek/modbus_m3_unit_function_sweep.zeek) |
| **Status** | experimental · **Notice** | `ModbusSweep::Sweep` |

This is the Modbus slice's **mandated Zeek detection** — the slice ships at least
one Sigma and one Zeek example to prove both rails (`PRD.md` §6.5). M1 and M2 are
Sigma; M3 is Zeek.

## Behavior

A scanning host walks several Modbus function codes and/or sweeps unit IDs on a
PLC to map what is present and what it supports. The hallmark is **breadth from a
single source in a short window** — many distinct function codes, or many
distinct unit IDs — at low request volume.

## Engine choice + rationale

**Zeek**, because the signal is **stateful**: it is the *count of distinct*
function codes and unit IDs a source has touched **accumulated over a window**,
which requires durable per-source state (sets) and set-membership tests. A
stateless Sigma field-match cannot express "distinct things seen so far," and a
simple Sigma **count** correlation would key on request *volume* — exactly the
wrong signal: SCADA masters poll constantly, so a volume threshold fires on
normal operation (`PRD.md` §8). Counting *diversity* (distinct codes/units), not
*rate*, is what keeps this credible, and that needs the durable state Zeek
provides (`PRD.md` §6.5: "any scanning detection that needs durable state beyond
a correlation window").

## Data source

Zeek's **base** Modbus analyzer (no ICSNPP dependency required):

- `event modbus_message(c, headers, is_orig)` — fires per Modbus message.
- `headers$function_code` — the function code; `headers$uid` — the **unit
  identifier** (Zeek's own base script sets `c$modbus$unit = headers$uid`).
- `c$id$orig_h` / `c$id$resp_h` — source / PLC. Only `is_orig` (request) messages
  are counted; the matched response comes from the PLC and would inflate the
  source's apparent diversity.

> **VERIFY (`CLAUDE.md` gate).** The `modbus_message` signature and the
> `ModbusHeaders` field names (`function_code`, `uid`) were verified against the
> live `zeek/zeek` source (`base/protocols/modbus`) on 2026-06-04, not recalled
> from memory.

## Detection logic

Per `(source, PLC)` pair, within a sliding `sweep_window` (default 60 s):
accumulate the set of distinct function codes and the set of distinct unit IDs
seen on **request** messages, then raise the `ModbusSweep::Sweep` notice (once
per pair per window) when either crosses its threshold.

| Knob (`&redef`) | Default | Meaning |
|---|---|---|
| `sweep_window` | `60sec` | Window over which diversity accumulates (resets after). |
| `unit_id_threshold` | `3` | Distinct unit IDs that constitute a sweep (**primary, high-confidence** arm). |
| `func_code_threshold` | `8` | Distinct function codes that constitute a sweep (secondary; tuned conservatively above a busy master's working set). |

The unit-ID arm is primary because legitimate masters target a small, known set
of unit IDs (often one), so sweeping several is a strong enumeration signal. The
function-code arm is deliberately conservative so routine multi-function polling
does not trip it.

## Scenarios

- **Fires:** [`anomalous-m3-sweep.yaml`](../../scenarios/modbus/anomalous-m3-sweep.yaml)
  — `scanner-1` hits 4 distinct function codes across 4 distinct unit IDs in a
  tight window. This trips the **unit-ID arm** (4 ≥ 3). (The function-code arm,
  threshold 8, is exercised by a dedicated function-sweep-on-one-unit scenario —
  a tracked follow-up — to keep the FP profile credible.)
- **Quiet:** [`benign-baseline.yaml`](../../scenarios/modbus/benign-baseline.yaml)
  — each source uses 3 distinct function codes on a single unit (1): below both
  thresholds.

> **Status note.** M3 executes in **Tier 2** (containerized Zeek over the PCAP).
> The Tier-2 runner is a Phase-2 `ENGINEERING_CHECKLIST.md` item, so M3's
> fire/quiet test runs there; the rule here is authored against the verified base
> Zeek Modbus API.

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Remote System Discovery | **T0846** | Discovery (TA0102) |
| Related | Remote System Information Discovery | T0888 | Discovery (TA0102) |

Sweeping Modbus **unit IDs** enumerates devices by *logical identifier*, which is
exactly T0846 ("a listing of other systems by IP address, hostname, or other
logical identifier on a network"). The **function-code** breadth dimension
additionally relates to T0888 (enumerating supported functions), the same
technique M2 maps to.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS
> matrix on 2026-06-04. Sources: <https://attack.mitre.org/techniques/T0846/>,
> <https://attack.mitre.org/techniques/T0888/>,
> tactic <https://attack.mitre.org/tactics/TA0102/>.

## False-positive profile

- **Modbus/TCP→serial gateways.** A gateway IP can front many unit IDs (a
  multi-drop serial line), and a legitimate master polling all of them
  legitimately touches several unit IDs — the main M3 false positive. Mitigate by
  raising `unit_id_threshold` above the known device count behind a gateway, or by
  allow-listing the polling master.
- **Busy engineering sessions.** An EWS exercising many function codes during
  commissioning can accumulate function-code diversity. Handled by the
  conservative `func_code_threshold` (8) and the short window; raise the window or
  threshold for known commissioning windows.
- **Why benign polling stays quiet.** Steady-state masters use a small, stable
  set of codes against a small, stable set of units, so neither distinct-count
  crosses its threshold regardless of request volume — the volume of polling is
  explicitly *not* part of the signal.
