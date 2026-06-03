# Substation — Engineering Checklist

**Status:** Draft v0.1 (source of truth) · Companion to `PRD.md`
**Last updated:** 2026-06-03

> Phased, incremental plan. We build **one piece at a time** in this order; the lead approves each piece before we start it. `[ ]` = todo, `[~]` = in progress, `[x]` = done. **VERIFY** gates must be satisfied before the dependent item is frozen.

-----

## How to read this

- Each phase has an **Objective**, **Tasks**, **Deliverables**, and **Exit criteria** (what must be true to call it done).
- Every detection in every phase must satisfy the **Detection Definition of Done** (below) — it is the reusable contract from `PRD.md` §6.6.
- **Verification gates** (ATT&CK IDs, ICSNPP fields, scapy capability, Sigma evaluation) are called out where they bite.

### Detection Definition of Done (reusable)

A detection is **done** only when all are true:

- [ ] Authored rule (Sigma / Zeek / Suricata) committed under `detections/`.
- [ ] ≥1 **anomalous** scenario it must fire on.
- [ ] ≥1 **benign** scenario it must stay quiet on.
- [ ] Passing **fire-on-anomaly** test.
- [ ] Passing **quiet-on-benign** test.
- [ ] **ATT&CK-for-ICS mapping** with a **verified** technique ID + tactic.
- [ ] Doc: engine choice + rationale, data source, and **false-positive profile**.
- [ ] **Coverage-map entry** (auto-generated from metadata).

-----

## Phase 0 — Decisions and skeleton

**Objective:** lock decisions, stand up a thin runnable skeleton, and de-risk the unknowns before writing real content.

**Tasks**

- [ ] Confirm `PRD.md` §7 locked decisions with the lead.
- [x] Create repo layout per `PRD.md` §6.9 (empty packages + placeholders).
- [x] Define the **scenario YAML format** (actors, exchanges, timing, `benign|anomalous` label, `exercises:` detection IDs) and document it inline with a commented example. (`docs/scenario-format.md` + commented `scenarios/modbus/benign-poll.yaml`; typed model + strict loader in `substation/scenarios/`.)
- [x] Stand up the **one-command entrypoint** as a stub (`cli.py` + `make demo`) that runs an end-to-end no-op (loads a trivial scenario → writes empty artifacts → prints a placeholder coverage map). Prove the wiring before the logic. (`substation demo` exercises load→generate→detect→report; emit/detect/coverage stages are wired no-ops.)
- [x] `pyproject.toml` with pinned deps (scapy, pySigma, pytest, Jinja2) targeting Python 3.11+.
- [x] **VERIFY spike — Sigma offline evaluation:** confirm a working Sigma-to-Python evaluation path over `.jsonl` for the harness; record the chosen mechanism in `docs/schema.md` notes. (`docs/spikes/03-sigma-offline-evaluation.md` — verdict: walk the pySigma-parsed condition AST in pytest; passing prototype. Also bumped `PyYAML` pin 6.0.1→6.0.3 to satisfy pySigma.)
- [x] **VERIFY spike — scapy capability (Modbus first):** confirm whether scapy can assemble the Modbus PDUs we need, or whether we hand-build / splice template PCAPs. Record the verdict per protocol. (`docs/spikes/02-scapy-modbus-capability.md` — verdict: **use scapy `contrib.modbus`**; all 8 needed PDUs incl. exception responses build + round-trip; no hand-build/splice for Modbus.)
- [x] **VERIFY spike — ICSNPP fields (Modbus first):** pull the **current** ICSNPP Modbus parser field names / detail-log shapes; draft the Modbus `detail` object from real names, not memory. (`docs/spikes/01-icsnpp-modbus-fields.md` — `modbus_detailed.log` fields verified against cisagov/icsnpp-modbus `main.zeek`; not yet frozen — re-pull against a pinned commit at Phase-1 freeze.)

**Deliverables:** runnable (no-op) skeleton; scenario format doc; three spike notes.
**Exit criteria:** `make demo` runs end to end doing nothing useful but proving the pipeline; spikes answered; decisions confirmed.

> **Phase-0 spike notes:** `docs/spikes/01-icsnpp-modbus-fields.md`,
> `docs/spikes/02-scapy-modbus-capability.md`,
> `docs/spikes/03-sigma-offline-evaluation.md`. Findings only — nothing frozen; the
> schema freeze and ATT&CK-ID verification remain Phase-1 gates.

-----

## Phase 1 — Modbus vertical slice (the whole product in miniature)

**Objective:** prove the entire architecture on the simplest protocol: scenario → PCAP + JSON → detections → harness → coverage row.

**Tasks**

- [ ] **Freeze the event-log schema for Modbus** in `docs/schema.md`: envelope (`PRD.md` §6.3) + Modbus `detail` from the verified ICSNPP fields. (Gate: ICSNPP VERIFY done.)
- [ ] Implement the **scenario model** + YAML loader.
- [ ] Implement the **JSON emitter** (envelope + Modbus detail) from the scenario model.
- [ ] Implement the **PCAP emitter** for Modbus (scapy or hand-built/template per the spike).
- [ ] Author **benign Modbus scenarios**: continuous HMI/EWS polling **and** legitimate setpoint writes from allow-listed sources (required for credible allow-list/scan detections — `PRD.md` §8).
- [ ] Author **anomalous Modbus scenarios** for M1–M3 (≥M1, M2, M3 at minimum).
- [ ] Author **detections** (deliberately mix engines to prove both rails):
  - [ ] **M1** Unauthorized register/coil write — **Sigma** (allow-list by source/unit/register).
  - [ ] **M2** Illegal / abnormal function code — **Sigma**.
  - [ ] **M3** Function-code / unit-ID sweep — **Sigma correlation** or **Zeek** (must include ≥1 **Zeek** detection somewhere in this phase; if M3 stays Sigma, add a Zeek variant or pull X1’s Modbus path forward).
- [ ] Build the **test harness** (pytest) enforcing the Detection Definition of Done for M1–M3 (Tier 1: Sigma over JSON).
- [ ] Generate the **first coverage-map row(s)** from detection metadata.
- [ ] **VERIFY — ATT&CK IDs** for M1–M3 against the live matrix; record IDs.
- [ ] Write per-detection docs incl. **false-positive profiles**.

**Deliverables:** working Modbus generate→detect→report; ≥3 detections (≥1 Sigma, ≥1 Zeek); first coverage rows; `docs/schema.md` (Modbus).
**Exit criteria:** every Modbus detection fires on its anomalous scenario and stays quiet on benign; coverage map renders the Modbus rows; harness green locally.

-----

## Phase 2 — Harden, CI, one-command demo, docs

**Objective:** make it real for a first-time visitor and keep it green automatically.

**Tasks**

- [ ] **GitHub Actions (Tier 1):** run the full generate→detect→report loop on every push/PR; fail on any contract violation.
- [ ] **GitHub Actions (Tier 2):** containerized **Zeek + ICSNPP** (and **Suricata** if used) to (a) run the **fidelity check** (diff our Modbus JSON vs real Zeek output) and (b) execute Zeek/Suricata detections.
- [ ] Polish the **one-command demo** (`make demo` / `substation demo`): clean output showing hits + a readable coverage map; confirm zero external deps for Tier 1.
- [ ] **README:** “why this exists,” the one-command quick start (<5 min to first success), Tier 1 vs Tier 2 explanation, safety statement (files-only; defensive-only).
- [ ] Finalize `docs/schema.md` as the binding contract.
- [ ] Add the **ATT&CK Navigator layer** export to the coverage builder.
- [ ] Enforce the **files-only invariant** in code (guard against socket sends) + assert it in tests.

**Deliverables:** green CI (both tiers); polished demo; README; Navigator layer.
**Exit criteria:** clean clone → one command → hits + coverage map on Linux/macOS with only Python 3.11+ (Tier 1); CI green including Tier-2 fidelity check.

-----

## Phase 3 — DNP3

**Objective:** extend on the proven pattern; validate that “add a protocol” is mechanical.

**Tasks**

- [ ] Add DNP3 `detail` to the schema (VERIFY ICSNPP DNP3 fields).
- [ ] DNP3 encoders + PCAP/JSON emit (scapy capability spike for DNP3).
- [ ] Benign DNP3 scenarios (legitimate master polling + unsolicited responses).
- [ ] Anomalous scenarios + detections D1–D4 (allow-list for D3; diversity/sweep for D4).
- [ ] Harness + coverage rows; **VERIFY** ATT&CK IDs; docs + FP profiles.

**Deliverables:** DNP3 end-to-end; D1–D4 satisfying the contract.
**Exit criteria:** DNP3 detections fire/quiet correctly; coverage updated; CI green; the act of adding DNP3 surfaced concrete inputs for `docs/adding-a-protocol.md`.

-----

## Phase 4 — Siemens S7 (highest risk; isolated phase)

**Objective:** cover S7comm/S7comm-plus despite the absence of an open spec.

**Tasks**

- [ ] Schema `detail` for S7 over **COTP/TPKT** (VERIFY ICSNPP S7 fields).
- [ ] S7 PDU construction — expect **hand-built PDUs / template PCAPs** (scapy lacks solid S7comm); reference Wireshark S7comm dissector.
- [ ] Benign S7 scenarios (normal engineering/HMI interaction).
- [ ] Anomalous scenarios + detections S1–S3 (CPU stop/start; data-block/program write; enumeration).
- [ ] Harness + coverage rows; **VERIFY** ATT&CK IDs; docs + FP profiles.

**Deliverables:** S7 end-to-end; S1–S3 satisfying the contract.
**Exit criteria:** S7 detections fire/quiet correctly; coverage updated; CI green.

-----

## Phase 5 — Coverage polish, contributor guides, optional honeypot

**Objective:** maximize visibility and make external contribution easy; add the research honeypot last.

**Tasks**

- [ ] Implement/finish **cross-protocol baseline detection X1** (Zeek; learned state + set membership over the normalized envelope).
- [ ] Polish the coverage map: rendered table in README/docs + downloadable Navigator layer; show covered vs gap techniques.
- [ ] `docs/adding-a-protocol.md` and `docs/adding-a-detection.md` — finite ordered checklists derived from the DNP3/S7 experience; reference the Detection Definition of Done.
- [ ] `CONTRIBUTING.md` + PR template that checks the Detection Contract.
- [ ] **Optional honeypot** (`PRD.md` §6.10): minimal **passive, isolated** Modbus responder logging probes; opt-in; strong safety/legal README; built only after the above is solid.
- [ ] Launch polish: examples/screens of the demo output and coverage map for the README.

**Deliverables:** flagship coverage story; contributor path; optional honeypot.
**Exit criteria:** a contributor can add a protocol/detection by following the docs; coverage map is launch-quality; honeypot (if shipped) is clearly optional, passive, and isolated.

-----

## Cross-cutting / definition of “launch-ready”

- [ ] One command, clean clone, <5 min to first success (Tier 1, Python-only).
- [ ] All shipped detections satisfy the Detection Definition of Done.
- [ ] Every ATT&CK mapping cites a **verified** technique ID.
- [ ] CI green (Tier 1 always; Tier 2 fidelity + Zeek/Suricata).
- [ ] README answers “why this exists” and shows the payoff visually.
- [ ] Safety posture explicit and enforced: files-only simulator, defensive-only, passive/isolated honeypot.
- [ ] Clear, documented path to add protocols/detections.

## Verification gates (master list)

- **ATT&CK-for-ICS technique IDs** — verify against the live matrix at coverage-map time, per detection. Never trusted from memory.
- **ICSNPP field names / detail shapes** — verify against current parsers before freezing each protocol’s schema.
- **scapy capability** — spike per protocol; decide scapy vs hand-built vs template PCAP.
- **Sigma offline evaluation** — confirm the harness’s Sigma-to-Python evaluation mechanism (Phase 0).

## Where Claude Code fits

Bulk scaffolding (package skeleton, boilerplate, repetitive per-protocol stubs) can be offloaded to Claude Code once Phase 0 decisions and the schema are pinned. Design, schema, detection logic, ATT&CK mappings, and reviews stay here.
