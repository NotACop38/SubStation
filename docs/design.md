# Substation design

**Status:** current as of 2026-09-26. This document is the source of truth for
Substation's scope, architecture and decisions. It replaces the
original product requirements and phased engineering checklist; their history
remains in git. Decisions marked **LOCKED** are deliberate and reversible only by
editing this document. **VERIFY** items must be checked against an authoritative
source, never recalled from memory.

Section numbers are stable: code comments, rules and scenarios cite them as
`docs/design.md §N`.

---

## 1. Overview

Substation is a defensive detection-content pack for industrial protocols —
**Modbus, DNP3 and Siemens S7** — mapped to **MITRE ATT&CK for ICS**, shipped with
a **files-only protocol simulator** that generates the benign and anomalous
traffic needed to test the rules without operational-technology (OT) hardware.

### Problem

OT detection content is scarce and hard to validate. Most defenders have no PLC
lab, so they cannot generate traffic that exercises a rule before relying on it.
Rules end up untested, naive about normal OT behavior, or copied without an
understanding of their false positives. Defenders need rule templates together
with a safe, repeatable way to produce the traffic that exercises them.

### What Substation provides

- Rules whose firing and silence are tested against scenarios that model both
  the attack and the legitimate traffic around it.
- A packet capture and a JSON event log from every scenario, generated from one
  model, so users can inspect exactly what a rule saw.
- Independent checks of that traffic with real Zeek/ICSNPP parsers.
- Honest boundaries: passing a synthetic scenario qualifies behavior on that
  fixture, not production recall or false-positive rates.

## 2. Goals and non-goals

### Goals

1. Detections for common Modbus, DNP3 and S7 attack and anomaly patterns, each
   mapped to verified ATT&CK-for-ICS techniques.
2. A simulator that emits PCAP and a documented JSONL event log for benign and
   anomalous scenarios, with no hardware and no network transmission.
3. A harness proving every detection fires on its anomalous scenarios and stays
   quiet on its benign ones.
4. A generated ATT&CK-for-ICS coverage map, including an ATT&CK Navigator layer.
5. A one-command first run and a documented contract for adding detections and
   protocols.

### Scope and evidence

Substation is an **offline regression and teaching toolkit**. All rules are
`experimental`. Registry status `validated` means the synthetic Tier-1 contract
passes; `tier2` means the rule needs a sensor engine and passes in Tier 2. Coverage
counts are content mappings, not a claim to detect a whole technique or tactic.
Independent evidence — parser comparisons, an attributed external Modbus corpus
and a SIEM-backend comparison — is recorded in [`validation.md`](validation.md).

### Non-goals and hard safety boundaries

- **No interaction with live OT.** The simulator only writes files; it never
  opens a sending socket or transmits on an interface (§6.4).
- **No exploit code, weaponization or payloads** aimed at real equipment. Rules
  model the *network signature* of malicious behavior.
- **The honeypot is passive and isolated** (§6.10).
- Not a SIEM, sensor or OT monitoring product.
- Protocols beyond Modbus, DNP3 and S7 (IEC 60870-5-104, EtherNet/IP, BACnet,
  OPC UA, PROFINET) are out of scope until the existing qualification gaps (§10)
  are closed.

## 3. Users and use cases

| User | Context | What Substation gives them |
|---|---|---|
| OT security engineer | Owns detection for an OT environment | Tested templates to adapt, plus a policy compiler for site allow-lists |
| ICS SOC analyst | Triages OT alerts | What each rule means, its mapping and its false-positive profile |
| IT detection engineer new to OT | Newly responsible for OT coverage | A safe sandbox for ICS protocols and a rule library with explicit assumptions |
| Detection contributor | Wants to extend coverage | A contract and harness for adding rules and protocols |

Primary use cases: validate a rule offline; learn a protocol from real PCAP and
JSON; assess ATT&CK coverage and gaps; contribute a rule with a passing test.

## 4. Success criteria

- `substation demo` succeeds on a clean install with Python 3.11+ on Linux or
  macOS, offline after installation, in seconds.
- Every shipped detection satisfies the Detection Contract (§6.6).
- Every ATT&CK mapping cites a technique verified against the live matrix.
- `make ci` is green before every push; `make verify VERIFY_ARGS=--require-complete`
  passes before every release.

## 5. Detection catalogue

Twelve detections. Mappings are verified against the live ATT&CK-for-ICS matrix
and recorded with sources in each detection's doc under `detections/docs/`.
The machine-readable index is `detections/registry.yaml`.

### 5.1 Modbus

| ID | Detection | Signal | Tactic (primary technique) | Engine |
|---|---|---|---|---|
| M1 | Unauthorized register/coil write | Write outside the permitted source, PLC, service, unit and complete register span | Impair Process Control (T1692.001) | Sigma |
| M2 | Illegal or abnormal function code | Undefined function codes; illegal-function or illegal-address exceptions | Discovery (T0888) | Sigma |
| M3 | Function-code / unit-ID sweep | Distinct function codes or unit IDs from one source, not request volume | Discovery (T0846) | Zeek |
| M4 | Bulk read / address-space sweep | Distinct address pages read from one table, not request volume | Collection (T0801) | Zeek |

### 5.2 DNP3

| ID | Detection | Signal | Tactic (primary technique) | Engine |
|---|---|---|---|---|
| D1 | Cold/warm restart | Restart request outside the approved master channel | Inhibit Response Function (T0816) | Sigma |
| D2 | Disable unsolicited responses | Reporting suppression outside the approved channel | Inhibit Response Function (T1691.002) | Sigma |
| D3 | Unauthorized control | SELECT/OPERATE/DIRECT_OPERATE outside the approved channel | Impair Process Control (T1692.001) | Sigma |
| D4 | Function-code enumeration | Distinct function codes from one source | Discovery (T0888) | Zeek |

### 5.3 Siemens S7

S7comm and S7comm-plus over TPKT/COTP. There is no open specification; protocol
behavior is grounded in the ICSNPP parser and the Wireshark dissector.

| ID | Detection | Signal | Tactic (primary technique) | Engine |
|---|---|---|---|---|
| S1 | CPU stop/start | PLC Stop, or PLC Control `P_PROGRAM`, outside the approved channel | Execution (T0858) | Sigma |
| S2 | Program / block download | Block download, or `_INSE` block activation, outside the approved channel | Lateral Movement (T0843) | Sigma |
| S3 | Module-information enumeration | Distinct SZL identifiers from one source | Discovery (T0888) | Zeek |

### 5.4 Cross-protocol

| ID | Detection | Signal | Tactic (primary technique) | Engine |
|---|---|---|---|---|
| X1 | Baseline deviation | New talker, new asset pair or new function for a pair, relative to a reviewed baseline | Discovery (T0846) | Zeek |

X1 is a novelty signal. It does not establish intent, authenticate sources or
persist its baseline across sensor restarts. M4's scenario demonstrates the
complementary gap: a trusted host collecting data is invisible to X1.

## 6. Architecture

### 6.1 System overview

```
            scenarios/<protocol>/*.yaml   (benign + anomalous, human-editable)
                              │
                              ▼
                    typed scenario model   (validated, immutable)
                    ┌─────────┴─────────┐
                    ▼                   ▼
             JSON emitter          PCAP emitter
             *.jsonl               *.pcap        (files only — no transmission)
                    │                   │
    Tier 1 (Python) ▼                   ▼ Tier 2 (Zeek/ICSNPP, Docker or native)
      Sigma subset over JSONL       field comparisons against real parsers
      hits + coverage map           stateful Zeek rules, fire/quiet
```

**LOCKED:** one scenario model drives both emitters, so scenario logic is not
duplicated. Two emitters can still disagree, which is why Tier 2 compares their
output with independent parsers. Generation is pure Python and needs no sensor.

### 6.2 Two-tier execution (LOCKED)

- **Tier 1 — Python only.** `substation demo` and `substation detect` generate
  events and evaluate the supported Sigma subset in-process. Runtime dependencies
  are Scapy, pySigma and PyYAML. No Zeek, Docker or hardware.
- **Tier 2 — real engines.** `make verify` runs Zeek with pinned ICSNPP parsers
  over the generated PCAPs, in Docker by default (the S7 plugin image is built
  locally from a pinned, patched source) or with native Zeek. It compares Modbus
  transaction fields, DNP3 per-message headers and object/control fields, and S7
  COTP and modeled request/response fields; reparses the external Modbus corpus;
  and runs every Zeek rule over its fire and quiet scenarios.
  `--require-complete` turns any skipped shipped check into a failure.

Sigma-over-JSON rules need no sensor; Zeek rules need their engine and are
therefore proven in Tier 2. Users who only want rules and traffic never install
Zeek.

### 6.3 Event schema (LOCKED approach; field names VERIFY)

Events are newline-delimited JSON, one event per line, with a common envelope and
a protocol-specific `detail` object:

- `ts`, `uid`, `conn` (`orig_h`, `orig_p`, `resp_h`, `resp_p`) — Zeek-style
  timestamp, connection id and 4-tuple.
- `proto` (`modbus` | `dnp3` | `s7comm`), `is_orig` and `direction`.
- `func_code`, `func_name` and `action_class`
  (`read` | `write` | `control` | `diagnostic` | `scan_indicator` | `other`).
- `is_exception` and `error`.
- `detail` — fields named after the ICSNPP/Zeek logs for that protocol.

This is Substation's synthetic contract, inspired by verified ICSNPP field names;
it is not the native sensor format. `substation import-modbus` projects matched
ICSNPP Modbus transactions into it; DNP3 and S7 import remain unqualified. The
normative definitions are [`schema.md`](schema.md) and the machine-readable
`substation/schema/event-log.schema.json`, which wins on disagreement.

### 6.4 Simulator (LOCKED)

- **Scenarios** are YAML under `scenarios/<protocol>/`: actors, ordered
  exchanges, timing, a `benign` | `anomalous` label and `exercises` — the
  detections that must fire or stay quiet. See [`scenario-format.md`](scenario-format.md).
- **Emitters:** Modbus PCAPs use Scapy's `contrib.modbus`; DNP3 and S7 frames are
  hand-assembled because Scapy has no usable layers (spikes 02, 05 and 07 in
  [`spikes/`](spikes/)). TCP streams are synthesized with handshakes and
  consistent sequence numbers.
- **Files-only invariant (enforced).** Emission runs inside a guard that refuses
  socket creation, connect/send on existing sockets and process creation. A
  static scan of the whole package rejects outbound connects, socket creation
  outside the honeypot, raw sockets, Scapy transmit functions and process
  spawning, however they are imported or aliased.
- **Realism requirement.** Scenarios model legitimate writers and continuous
  polling, not just the attacker; otherwise allow-list and sweep rules are
  untestable and not credible (§8).

### 6.5 Detection-engine policy (LOCKED)

Choose the simplest engine that expresses the behavior correctly, and record the
choice and reason in the detection's doc.

- **Sigma first** for single-event predicates over the JSON envelope: allow-list
  channels (M1, D1–D3, S1, S2) and illegal codes (M2).
- **Zeek** when the signal needs state across events: diversity and coverage
  sweeps (M3, M4, D4, S3) and learned baselines (X1).
- **Suricata** optionally, for packet signatures; none ship today.

Tier 1 evaluates Sigma by walking pySigma's parsed condition tree. It supports
field equality (case-insensitive by default), numeric comparison modifiers,
boolean logic and `1 of`/`all of` selections, and rejects anything else rather
than mis-evaluating it. Deployment compiles the same rules with a pySigma backend;
the SQLite comparison and its known limits are in [`validation.md`](validation.md).

### 6.6 Detection Contract

A detection is done only when it has all of:

1. The authored rule under `detections/<engine>/`.
2. At least one anomalous scenario it must fire on.
3. At least one benign scenario it must stay quiet on.
4. A passing fire-on-anomaly test (Tier 1, or the Tier-2 runner for Zeek).
5. A passing quiet-on-benign test.
6. A verified ATT&CK-for-ICS mapping (technique IDs and tactic, with source and
   date).
7. A doc with the engine choice and rationale, the data source and a
   false-positive profile.
8. A registry entry in `detections/registry.yaml`, from which the coverage map is
   generated.

The harness is metadata-driven: a new registry entry, rule and scenarios are
discovered without test-code changes. Tier-1 fire cases also pin the exact event
indices a rule must hit, so a rule that over-matches fails.

### 6.7 Coverage map

`make coverage-build` renders, from the registry only, a markdown table, a JSON
report, an ATT&CK Navigator layer and an SVG matrix into `docs/coverage/`.
`make ci` fails when the committed copies are stale; it never rewrites them.

### 6.8 One-command experience

`substation demo` (or `make demo`) runs a benign baseline and anomalous scenarios
across two protocols, prints per-scenario verdicts and the coverage map, and fails
if a scenario's Tier-1 `exercises` contract is violated.

### 6.9 Repository layout

```
substation/            Python package (CLI, scenario model, protocol encoders,
                       emitters, Sigma evaluator, schema, coverage, policy, honeypot)
detections/            rules (sigma/, zeek/), docs/, registry.yaml, policies/
scenarios/             YAML scenarios per protocol
tests/                 pytest suite, golden events, fidelity fixtures, Modbus corpus
scripts/               verify/ (Tier 2), release/, security/, corpus/, hooks/
docs/                  design, validation, schema, guides, spikes, coverage snapshot
```

`detections/` and `scenarios/` live at the repository root for contributors and
are copied into the wheel under `substation/content/` at build time.

### 6.10 Optional honeypot

A passive Modbus/TCP probe logger that answers with stub values and logs probes
in the Substation schema, so the Tier-1 rules can run on what it captures. It
binds loopback by default; an external bind needs both `--allow-external` and
`SUBSTATION_HONEYPOT_I_UNDERSTAND=1`, and must be network-isolated. It never
initiates connections and is outside the simulator and the demo. See
[`substation/honeypot/README.md`](../substation/honeypot/README.md).

## 7. Decisions

### Locked decisions

1. **Schema:** ICSNPP-aligned per-protocol detail plus a normalized envelope, as
   JSONL (§6.3).
2. **Simulator:** one scenario model, dual PCAP/JSON emission, pure Python,
   files-only (§6.4).
3. **Engine policy:** Sigma first, Zeek for state, Suricata optional, rationale
   recorded per detection (§6.5).
4. **Two tiers:** Python-only Tier 1 is the first-run path; Tier 2 proves the
   rest in real engines (§6.2).
5. **Local CI:** `make ci` is the gate, run by the pre-push hook installed with
   `make hooks`. There are no cloud CI workflows.

### VERIFY gates

- **ATT&CK-for-ICS technique IDs:** checked against the live matrix per
  detection, with the source and date in the detection doc. The matrix has been
  restructured before: T0855 and T0804 now redirect to T1692.001 and T1691.002
  (re-checked 2026-09-26).
- **ICSNPP and Zeek field names and event signatures:** checked against the
  pinned parser sources before a schema or rule depends on them.
- **Library capability** (Scapy layers, pySigma behavior): spiked and recorded in
  [`spikes/`](spikes/) before code depends on it.

## 8. Risks and OT-realism guardrails

| Risk | Why it matters | Mitigation |
|---|---|---|
| "Unauthorized write = any write" | Engineers legitimately write setpoints; such a rule is all false positives | Allow-list by source, asset, service, unit and span (M1, D3, S2); scenarios include legitimate writers |
| "Scanning = high volume" | SCADA masters poll constantly | Sweep rules count distinct codes, units, SZLs or address pages (M3, M4, D4, S3), never request rate |
| Synthetic traffic that real parsers would not recognize | Rules that only work on Substation's JSON are not credible | Tier 2 compares fields with Zeek/ICSNPP and reparses an external corpus |
| Over-claimed ATT&CK mappings | Loose technique IDs erode practitioner trust | VERIFY gate per detection; coverage presented as content mapping |
| S7 complexity (no open spec) | Highest encoding risk | Field-level comparison with the pinned ICSNPP plugin, including a reviewed bounds patch |
| IP-based permissions | A compromised approved host is invisible to a channel allow-list | Documented in every allow-list rule; X1 and M4 cover different behavior |
| Misuse as an attack tool | The project must never touch live OT | Files-only invariant enforced in code and tests; no exploit content; passive honeypot |

## 9. References

- MITRE ATT&CK for ICS: <https://attack.mitre.org/matrices/ics/>
- Zeek: <https://zeek.org/> · CISA ICSNPP: <https://github.com/cisagov/icsnpp>
- Sigma: <https://sigmahq.io/> · pySigma: <https://github.com/SigmaHQ/pySigma>
- ATT&CK Navigator: <https://github.com/mitre-attack/attack-navigator>
- Modbus Application Protocol Specification v1.1b3 and Modbus Messaging on
  TCP/IP Implementation Guide v1.0b (modbus.org)
- IEEE Std 1815 (DNP3)
- S7comm/S7comm-plus: the Wireshark dissectors and CISA ICSNPP S7comm parser

## 10. Roadmap

Open qualification work, in priority order:

1. Measure rule behavior on independent, representative benign traffic and
   boundary cases beyond the synthetic catalogue.
2. Qualify general DNP3 and S7 sensor-log normalization, and deployment on a
   real SIEM backend with its field mappings and missing-data semantics.
3. Qualify remaining Modbus function extensions, timing, and unmodeled session
   and payload semantics.
4. Optional Suricata companion rules, with a Tier-2 runner, for users without
   Zeek.

New protocols and honeypot features stay deferred until they serve a
demonstrated use case with matching evidence.
