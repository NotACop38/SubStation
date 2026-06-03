# Substation — Product Requirements Document

**Status:** Draft v0.1 (source of truth) · **Owner:** project lead · **Engineering partner:** Claude
**Last updated:** 2026-06-03

> This document and the companion `ENGINEERING_CHECKLIST.md` are the source of truth for Substation. Decisions marked **LOCKED** are committed but reversible — revisit by editing this doc and noting the change. Items marked **VERIFY** must be confirmed against an authoritative source before the relevant code/content is frozen.

-----

## 1. Overview

**Substation** is a defensive detection-content pack for industrial-protocol attacks and anomalies — **Modbus, DNP3, and Siemens S7** — mapped to **MITRE ATT&CK for ICS**, shipped together with a **protocol traffic simulator** that produces benign and anomalous telemetry so the detections can be developed and validated **without real OT hardware**.

### Problem

OT/ICS detection content is scarce and hard to validate. Most defenders don’t have a PLC lab, so they can’t generate the telemetry needed to test a rule before trusting it in production. The result is detections that are untested, naive, or copied without understanding their false-positive behavior. Defenders need two things together: **ready-to-use detections** and **a safe, repeatable way to generate the telemetry that exercises them.**

### Vision / one-line pitch

> Clone the repo, run one command, and watch synthetic ICS telemetry flow through real detections and light up an ATT&CK-for-ICS coverage map — no PLC, no lab, no live OT.

### What “good” looks like

- A first-time visitor goes from `git clone` to “I see detections firing on attacks and staying quiet on benign traffic, plus a coverage map” in **one command and under five minutes**, with **no external dependencies beyond Python** for the headline path.
- The content is **credible to OT practitioners**: detections account for real OT realities (engineers legitimately write setpoints; SCADA masters poll constantly), and every mapping is traceable to an authoritative source.
- The project is **easy to extend**: a contributor can add a protocol or a detection by following a documented contract.

-----

## 2. Goals and non-goals

### Goals

1. Provide tested detections for common Modbus/DNP3/S7 attack and anomaly patterns, each mapped to ATT&CK for ICS.
1. Provide a synthetic protocol simulator that emits both **PCAP** and a **documented JSON protocol-event log** for benign and anomalous scenarios, with no hardware.
1. Provide a test harness that proves **each detection fires on its anomalous telemetry and stays quiet on benign telemetry.**
1. Provide an ATT&CK-for-ICS **coverage map** (human-readable + ATT&CK Navigator layer).
1. Make the project **one-command runnable** and **easy to contribute to** (clear path to add protocols/detections).
1. Optimize for community visibility: credible, well-referenced content with a clean first-run experience.

### Non-goals (and hard safety boundaries)

- **No interaction with live OT systems.** Substation is strictly defensive.
- **The simulator only ever writes files** (PCAP/JSON). It does not transmit on a live network interface. This is an architectural invariant (see §6.4), stated plainly in the README, and enforced in code.
- **No exploit code, no weaponization, no payloads** intended to damage or manipulate real equipment. We model the *network signature* of malicious behavior for detection purposes; we do not build tooling to perform it against real devices.
- **Any honeypot is passive and isolated** (research-only, opt-in, last priority) — see §6.10.
- Not a SIEM, not a packet-capture appliance, not a substitute for a real OT monitoring product.
- v1 protocol set is Modbus/DNP3/S7 only. IEC 60870-5-104, EtherNet/IP-CIP, BACnet, OPC UA, PROFINET, etc. are explicitly out of scope for v1 and are candidate contributions later.

-----

## 3. Users and primary use cases

|User                           |Context                                |What they get from Substation                                                                                  |
|-------------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------|
|OT security engineer           |Owns detection in an OT/ICS environment|Vetted detections they can adapt; telemetry to validate before deploying                                       |
|ICS SOC analyst                |Triages alerts from OT monitoring      |Reference for what each detection means, its ATT&CK mapping, and its false-positive profile                    |
|IT detection engineer new to OT|Just got handed OT coverage            |A safe sandbox to learn ICS protocols and a starting detection library that won’t drown them in false positives|
|Detection-content contributor  |Wants to extend coverage               |A documented contract to add a protocol or detection with a passing test                                       |

**Primary use cases**

1. *Validate a detection offline.* Generate benign + anomalous telemetry, run the detection, confirm fire/quiet behavior.
1. *Learn an ICS protocol safely.* Inspect realistic PCAP/JSON for benign and attack scenarios.
1. *Assess coverage.* See which ATT&CK-for-ICS techniques are covered and where the gaps are.
1. *Contribute.* Add a new protocol/detection following the documented contract and the test harness.

-----

## 4. Success metrics

**Adoption / visibility (primary objective)**

- One-command demo succeeds on a clean clone on Linux/macOS with only Python 3.11+ installed.
- README “why this exists” + first-success path is unambiguous.
- At launch: Modbus fully end-to-end with ≥3 detections + ≥1 cross-protocol baseline detection scaffold; coverage map renders; CONTRIBUTING explains adding a protocol/detection.

**Quality / credibility**

- 100% of shipped detections have: a passing fire-on-anomaly test, a passing quiet-on-benign test, an ATT&CK mapping, and a documented false-positive profile (the **Detection Contract**, §6.6).
- Every ATT&CK mapping cites a verified technique ID from the live matrix (§7, **VERIFY**).
- CI is green on every merge and runs the full generate→detect→report loop.

**Extensibility**

- Adding a new protocol or detection is documented as a finite, ordered checklist; a contributor PR can be reviewed against the Detection Contract.

-----

## 5. Scope — protocols and target detections

Detections below are the v1 target set. **Engine choice** is per the policy in §6.5. **ATT&CK mapping is by technique name**; exact technique IDs are **VERIFY** items resolved during coverage-map work (§7) and recorded in the checklist, not trusted from memory.

> Naming caveat: ATT&CK-for-ICS *tactics* are stable and used confidently below; *technique IDs* are provisional/illustrative until verified against the live matrix.

### 5.1 Modbus (vertical slice — built first, end to end)

|# |Detection                            |Behavior                                                                                                                                                              |Likely ATT&CK-for-ICS tactic(s)                  |Engine (proposed)                                 |
|--|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|--------------------------------------------------|
|M1|Unauthorized register/coil write     |Write function (e.g. WriteSingle/MultipleRegisters/Coils) from a source **not** on the allow-list of permitted writers (HMI/EWS), or to a register/unit outside policy|Impair Process Control; Inhibit Response Function|Sigma (allow-list match)                          |
|M2|Illegal / abnormal function code     |Use of reserved/undefined function codes, or exception responses indicating illegal-function/illegal-address probing                                                  |Discovery                                        |Sigma                                             |
|M3|Function-code / unit-ID sweep        |One source touching many function codes and/or sweeping unit IDs in a short window (diversity/sweep, **not** raw request volume)                                       |Discovery                                        |Sigma correlation rule, or Zeek if state is needed|
|M4|Read of unusual/large register ranges|Bulk reads outside baseline (potential collection/recon)                                                                                                              |Collection; Discovery                            |Sigma correlation, or Zeek                        |

### 5.2 DNP3

|# |Detection                                    |Behavior                                                     |Likely ATT&CK-for-ICS tactic(s)|Engine (proposed)       |
|--|---------------------------------------------|-------------------------------------------------------------|-------------------------------|------------------------|
|D1|Cold/warm restart issued                     |DNP3 function for device restart from unexpected source      |Inhibit Response Function      |Sigma                   |
|D2|Disable unsolicited responses                |Suppressing outstation reporting (alarm/telemetry blinding)  |Inhibit Response Function      |Sigma                   |
|D3|Unauthorized control (operate/direct-operate)|CROB/analog output operate from non-allow-listed master      |Impair Process Control         |Sigma (allow-list)      |
|D4|Function-code scanning / enumeration         |Diversity of function codes / object scanning from one source|Discovery                      |Sigma correlation / Zeek|

### 5.3 Siemens S7 (S7comm / S7comm-plus over COTP/TPKT — hardest)

|# |Detection                             |Behavior                                       |Likely ATT&CK-for-ICS tactic(s)                        |Engine (proposed)                      |
|--|--------------------------------------|-----------------------------------------------|-------------------------------------------------------|---------------------------------------|
|S1|CPU Stop / Start                      |PLC run-state change from unexpected source    |Inhibit Response Function; Impair Process Control      |Sigma; Zeek if S7 state tracking needed|
|S2|Data-block / program write or download|Writing data blocks / downloading program logic|Impair Process Control (program/parameter modification)|Sigma; possibly Zeek                   |
|S3|Enumeration / module-info reads       |Reading PLC identity/module info (recon)       |Discovery                                              |Sigma                                  |

### 5.4 Cross-protocol

|# |Detection                                                                 |Behavior                                                                                                 |Likely ATT&CK-for-ICS tactic(s)|Engine (proposed)                                 |
|--|--------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------|--------------------------------------------------|
|X1|Baseline deviation (new talker / new asset pair / new function for a pair)|A source/destination/function combination not seen in the learned baseline, across any supported protocol|Discovery; Lateral Movement    |**Zeek** (requires learned state + set membership)|

X1 is the flagship reason for the normalized envelope (§6.3) and the primary justification for a stateful Zeek detection.

-----

## 6. Architecture

### 6.1 System overview

```
                    scenarios/*.yaml  (benign + anomalous, human-editable)
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Scenario model      │  single source of truth per run
                   │  (actors, exchanges, │
                   │   timing, labels)    │
                   └─────────┬───────────┘
              emit PCAP ◄────┤  (same model)  ├────► emit JSON event log
            (scapy / hand-   │                │      (Zeek/ICSNPP-aligned)
             built PDUs /    │                │
             template splice)│                │
                             ▼                ▼
                        artifacts/*.pcap   artifacts/*.jsonl
                             │                │
        ┌────────────────────┴───────┐        │
        │ (Tier 2, CI only)          │        │ (Tier 1, pure Python, default)
        │ real Zeek + ICSNPP / Suri- │        │
        │ cata over PCAP for         │        │  Sigma detections evaluated
        │ fidelity + signature tests │        │  over JSON event log
        └────────────────────────────┘        │
                                               ▼
                                  hits + ATT&CK-for-ICS coverage map
```

**Core design principle (LOCKED):** one scenario model drives **both** emitters, so PCAP and JSON can never drift. Generation is **pure Python** with **no Zeek and no hardware**, so the headline path runs anywhere.

### 6.2 Two-tier execution model (LOCKED)

This is the most important UX/credibility decision, so it is explicit:

- **Tier 1 — zero external dependencies (the headline path).** Generate telemetry (pure Python) → run **Sigma** detections over the **JSON** event log → print hits + coverage map. Requires only Python 3.11+. This is what `one command` runs and what the README promises.
- **Tier 2 — full-fidelity validation (CI / contributors).** Run PCAPs through **real Zeek + ICSNPP** and/or **Suricata** (containerized) to (a) prove our synthetic JSON matches real Zeek output and (b) execute Zeek-script and Suricata detections that genuinely require packet-level state.

Consequence we accept and document: **Sigma-over-JSON detections need no Zeek; Zeek/Suricata detections inherently require their engine** to execute and are therefore validated in Tier 2. Users who only want detections + telemetry never need to install Zeek/Suricata. This keeps the barrier to first success near zero while still proving the harder detections.

### 6.3 Event-log JSON schema (LOCKED approach; field names VERIFY)

**Decision:** model the JSON on **Zeek + ICSNPP** per-protocol fields (so our Sigma rules target the *same shape as real production Zeek logs*), wrapped in a thin **normalized envelope** that enables cross-protocol detection.

- **Why ICSNPP alignment over Zeek’s thinner built-ins:** detections authored here transfer to production Zeek deployments with minimal change — a major utility and credibility win — and “Zeek/ICSNPP-aligned” is a citable realism story.
- **Why add an envelope:** the three protocols’ Zeek logs are not uniformly shaped; a small common envelope lets the cross-protocol baseline detection (X1) and shared Sigma logic operate uniformly.

**Envelope (common, every event):**

- `ts` — event timestamp
- `uid` — connection id (Zeek-style)
- `conn` — `{ orig_h, orig_p, resp_h, resp_p }` (Zeek conn tuple)
- `proto` — `modbus | dnp3 | s7comm`
- `is_orig` / `direction` — request vs response
- `func_code` — raw function/command code
- `func_name` — decoded, normalized function name
- `action_class` — normalized verb: `read | write | control | diagnostic | scan_indicator | other` (drives X1 and shared logic)
- `is_exception` / `error` — error/exception indicator
- `detail` — nested protocol-specific object mirroring **ICSNPP** fields for that protocol (e.g. Modbus: transaction id, unit id, address, quantity, values; DNP3: function, objects, IIN; S7: rosctr/function, area, db number, etc.)

**Format:** newline-delimited JSON (`.jsonl`), one event per line — matches how Zeek logs stream and is trivial to process.

**VERIFY before freeze:** exact ICSNPP field names and per-protocol detail-log structure against the **current** ICSNPP parsers (the parsers evolve; we confirm names, we don’t guess). Documented in `docs/schema.md`.

### 6.4 Simulator design (LOCKED)

- **Scenario format:** human-editable **YAML** under `scenarios/<proto>/`. A scenario declares actors (master/HMI/EWS, outstation/PLC), an ordered list of protocol exchanges, timing, a `benign | anomalous` label, and `exercises:` (which detection IDs it is meant to fire/keep quiet).
- **Engine:** loads a scenario → builds an internal event model → hands it to two emitters.
- **Emitters:**
  - **PCAP** via scapy where the protocol layer is workable, **hand-assembled PDUs** or **template-PCAP splicing** where it is not (see §8 — scapy’s Modbus support is uneven and it lacks solid S7comm/DNP3 layers).
  - **JSON** event log (Zeek/ICSNPP-aligned, §6.3) from the same model.
- **Files-only invariant (LOCKED, enforced):** the simulator writes files and never opens a sending socket / never transmits on a live interface. Stated in the README and guarded in code.
- **Realism requirement:** scenarios must model a **legitimate writer/master** (HMI/EWS) and **continuous benign polling**, not only the attacker — otherwise the allow-list and scanning detections are untestable and not credible (see §8).
- **Optional fidelity check (Tier 2, CI):** run generated PCAPs through real Zeek+ICSNPP and diff against our JSON as a golden test, proving the synthetic JSON is faithful. Out of the core path.

### 6.5 Detection-engine policy (LOCKED)

Per behavior, choose the simplest engine that expresses it correctly; each detection’s doc states the engine and **why**.

- **Sigma-first** for field matches over the JSON event log: allow-list writer matches (M1, D3), illegal function codes (M2), run-state/control commands (D1, D2, S1). Use **Sigma correlation rules** for simple count/temporal thresholds (some scanning, M3/D4) where they suffice.
- **Zeek script** when real state is required: learned baselines, set membership, multi-log joins, cross-protocol deviation (X1), and any scanning detection that needs durable state beyond a correlation window.
- **Suricata** as an **optional** packet-level companion for users not running Zeek, where a behavior is cleanly expressible as a packet signature.
- The Modbus slice deliberately ships **at least one Sigma and one Zeek** example to prove both rails.

**Sigma execution in the harness (decision; mechanism VERIFY):** detections are authored as Sigma and validated with **pySigma**. For offline testing, Sigma rules are **evaluated directly against the JSON event stream** (Sigma-to-Python evaluation) so Tier 1 needs no SIEM. Production users compile the *same* rules to their SIEM via standard pySigma backends (Elastic, Splunk, etc.). The exact evaluation library/approach is a Phase 0 spike — we confirm a working mechanism rather than assume one.

### 6.6 Test harness and the Detection Contract

The harness (pytest) enforces a single reusable contract for **every** detection:

> **Detection Contract — a detection is “done” only when it has all of:**
>
> 1. The authored rule (Sigma/Zeek/Suricata).
> 1. At least one **anomalous** scenario it must fire on.
> 1. At least one **benign** scenario it must stay quiet on.
> 1. A passing **fire-on-anomaly** test and a passing **quiet-on-benign** test.
> 1. An **ATT&CK-for-ICS mapping** (verified technique ID + tactic).
> 1. A **doc**: engine choice + rationale, data source, and a **false-positive profile** (what benign behavior could trip it and why it doesn’t here).
> 1. A **coverage-map entry**.

Tier 1 tests run Sigma-over-JSON. Tier 2 tests (CI) run Zeek/Suricata over PCAP.

### 6.7 Coverage map

- **Human-readable** table (markdown + JSON) generated from detection metadata: technique, tactic, protocol, detection ID(s), engine, status.
- **ATT&CK Navigator layer** (JSON) so users can load Substation’s coverage directly into the Navigator — strong for credibility and visibility.
- Generated, not hand-maintained, so it can’t drift from the detections.

### 6.8 One-command UX (LOCKED)

A single entrypoint (CLI subcommand and/or `make demo`) runs the Tier 1 loop end to end: **generate telemetry → run detections → print hits + render coverage map.** Zero external dependencies beyond Python. Tier 2 validation is a separate target (`make verify` / CI job).

### 6.9 Repository layout (proposed)

```
substation/
  README.md                  # why it exists + one-command quick start
  pyproject.toml
  Makefile                   # demo, verify, test targets
  scenarios/                 # YAML scenario defs (benign + anomalous)
    modbus/  dnp3/  s7/
  substation/                # python package
    scenarios/               # loader + scenario model
    protocols/               # per-protocol encoders + field maps
    emit/                    # pcap emitter + json emitter (shared model)
    detect/                  # sigma evaluation, zeek runner, suricata runner
    coverage/                # coverage-map + Navigator-layer builder
    cli.py
  detections/
    sigma/  zeek/  suricata/
  tests/                     # pytest harness (Detection Contract)
  coverage/                  # generated coverage map + Navigator layer
  docs/
    schema.md                # event-log JSON schema (the contract everything binds to)
    adding-a-protocol.md
    adding-a-detection.md
  .github/workflows/         # CI: generate -> detect -> report (+ Tier 2)
```

### 6.10 Optional honeypot (research-only, last)

A minimal, **passive, isolated** Modbus responder that logs inbound probes for research. Constraints: opt-in, no real process emulation beyond banner/coil/register stubs, must be deployed network-isolated, with explicit safety/legal cautions in its README. Built **last**, only after the core product is solid. Clearly out of the headline path.

-----

## 7. Key decisions and open items

### Locked decisions (reversible)

1. **Schema:** ICSNPP-aligned per-protocol detail + normalized envelope; `.jsonl`. (§6.3)
1. **Simulator:** single scenario model → dual emit (PCAP + JSON); pure Python; **files-only**; optional Tier-2 Zeek fidelity check. (§6.4)
1. **Engine policy:** Sigma-first; Zeek for stateful; Suricata optional; per-detection rationale. (§6.5)
1. **Two-tier execution:** Tier 1 zero-dep (Sigma/JSON) is the headline; Tier 2 (Zeek/Suricata, containerized) validates the rest. (§6.2)
1. **Build order:** Modbus end-to-end first, then harden+CI, then DNP3, then S7, then coverage polish + contributor guides + optional honeypot. (See checklist.)

### Open items deferred to implementation (with verification gates)

- **VERIFY — ATT&CK-for-ICS technique IDs.** Confirm every mapping against the live matrix during coverage-map work; record IDs in the checklist. Tactics are treated as stable; IDs are not trusted from memory.
- **VERIFY — ICSNPP field names / detail-log shapes.** Confirm against current parsers before freezing `docs/schema.md`.
- **VERIFY — scapy protocol-layer capability.** Spike per protocol (Modbus/DNP3/S7) to decide scapy vs hand-built PDUs vs template PCAPs.
- **VERIFY — Sigma offline evaluation mechanism.** Confirm a working Sigma-to-Python evaluation path for the harness in Phase 0.

-----

## 8. Risks and OT-realism guardrails

|Risk                                                 |Why it matters                                                                                              |Mitigation                                                                                                          |
|-----------------------------------------------------|------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
|Naive “unauthorized write = any write”               |Engineers legitimately write setpoints; a write-only rule is pure false positives and discredits the project|M1/D3/S2 use **allow-list by source/asset/unit** or baseline deviation; simulator **must** model a legitimate writer|
|Naive “scanning = high volume”                       |SCADA masters poll constantly; volume thresholds fire on normal operation                                   |M3/D4 key on **function-code diversity, illegal codes, unit-ID sweeping**, not raw request rate                     |
|scapy protocol gaps                                  |scapy’s Modbus is uneven; no solid S7comm/DNP3 layers                                                       |Hand-assembled PDUs / template-PCAP splicing; per-protocol capability spike (§7)                                    |
|Synthetic telemetry doesn’t match real Zeek          |Detections that only work on our JSON aren’t credible                                                       |Tier-2 fidelity check diffs our JSON against real Zeek+ICSNPP output                                                |
|Over-claiming ATT&CK mappings                        |Wrong/loose technique IDs erode trust with practitioners                                                    |Per-detection verified IDs (§7), false-positive profile in every doc (§6.6)                                         |
|S7 complexity (S7comm/-plus, COTP/TPKT, no open spec)|Highest implementation risk; built last for a reason                                                        |Lean on community/Wireshark-dissector references; isolate S7 to its own phase                                       |
|Scope creep into other protocols                     |Dilutes a clean v1                                                                                          |IEC-104/CIP/BACnet/etc. are explicitly post-v1 contributions                                                        |
|Misuse perception (an “ICS attack tool”)             |The simulator must never be usable against live OT                                                          |Files-only invariant enforced in code + README; no exploit/weaponization content; passive/isolated honeypot only    |

-----

## 9. References (authoritative)

- **MITRE ATT&CK for ICS** — technique/tactic matrix: <https://attack.mitre.org/matrices/ics/>
- **Zeek** + **ICSNPP** (Industrial Control Systems Network Protocol Parsers), CISA: <https://github.com/cisagov/icsnpp>
- **Sigma** detection format: <https://github.com/SigmaHQ/sigma> · **pySigma**: <https://github.com/SigmaHQ/pySigma>
- **Suricata**: <https://suricata.io/>
- **Modbus Application Protocol Specification** (v1.1b3) — modbus.org
- **DNP3 / IEEE Std 1815** — IEEE
- **S7comm / S7comm-plus** — no official open specification; reference community documentation and the Wireshark S7comm dissector.
- **ATT&CK Navigator** — for the coverage layer: <https://github.com/mitre-attack/attack-navigator>

> All ATT&CK mappings cite verified technique IDs from the live matrix (§7). Protocol behavior is grounded in the specs above; S7 relies on community/dissector references given the absence of an open spec.

-----

## 10. Build order (summary)

Full task breakdown, exit criteria, and the per-detection contract are in **`ENGINEERING_CHECKLIST.md`**.

1. **Decisions + skeleton** — lock §7 decisions; repo layout; scenario format; one-command stub; Phase-0 verification spikes.
1. **Modbus vertical slice** — schema frozen for Modbus; simulator (benign + anomalous, PCAP + JSON); ≥3 Modbus detections incl. ≥1 Sigma and ≥1 Zeek; harness green; first coverage-map row.
1. **Harden + CI + demo + docs** — GitHub Actions full loop; one-command demo; `docs/schema.md`; README.
1. **DNP3** — on the proven pattern.
1. **S7** — hardest; isolated phase.
1. **Coverage polish + contributor guides + optional honeypot.**
