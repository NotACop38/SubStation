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

- [x] **Freeze the event-log schema for Modbus** in `docs/schema.md`: envelope (`PRD.md` §6.3) + Modbus `detail` from the verified ICSNPP fields. (Gate: ICSNPP VERIFY done.) (`docs/schema.md` frozen for Modbus; machine-readable `substation/schema/event-log.schema.json` (draft 2020-12); dependency-free validator `substation/schema/` + `python -m substation.schema`; wired into `make ci` via the `schema` target over committed golden events `tests/data/events/`. `.jsonl`, one event per line. DNP3/S7 `detail` stay unconstrained until Phases 3/4.)
- [x] Implement the **scenario model** + YAML loader. (Built in Phase 0: `substation/scenarios/model.py` + `loader.py`; consumed here by `build_events`.)
- [x] Implement the **JSON emitter** (envelope + Modbus detail) from the scenario model. (`substation/emit/json_emitter.py`; every event is validated against the frozen schema before it is written.)
- [x] Implement the **PCAP emitter** for Modbus (scapy or hand-built/template per the spike). (`substation/emit/pcap_emitter.py` via `scapy.contrib.modbus` per spike 02. **One** shared event model — `substation/protocols/modbus.py` `build_events` → `ModbusEvent` — drives both emitters, so PCAP and JSON cannot drift (PRD §6.1). A benign scenario emits matching artifacts: one Modbus/TCP segment per JSON event; output is byte-deterministic.)
- [x] Author **benign Modbus scenarios**: continuous HMI/EWS polling **and** legitimate setpoint writes from allow-listed sources (required for credible allow-list/scan detections — `PRD.md` §8). (`scenarios/modbus/benign-baseline.yaml` — continuous HMI/EWS polling + legitimate EWS setpoint writes from allow-listed sources; the canonical quiet baseline for M1–M3. `benign-poll.yaml` remains the `make demo` wiring scenario.)
- [x] Author **anomalous Modbus scenarios** for M1–M3 (≥M1, M2, M3 at minimum). (`anomalous-m1-unauthorized-write.yaml` — write from a non-allow-listed source; `anomalous-m2-illegal-function.yaml` — reserved/undefined function code `0x09`; `anomalous-m3-sweep.yaml` — one source sweeping function codes across unit ids, diversity-not-volume. Each sets `exercises.fires`/`quiet` so it fires its target detection and stays quiet on the others.)
- [x] Author **detections** (deliberately mix engines to prove both rails): (M1/M2 **Sigma** + M3 **Zeek** committed under `detections/`; proves both rails per PRD §6.5.)
  - [x] **M1** Unauthorized register/coil write — **Sigma** (allow-list by source/unit/register). (`detections/sigma/modbus_m1_unauthorized_write.yml`; allow-list by **source + unit + register** — writable setpoints 40–49 enumerated as explicit values so the Tier-1 evaluator matches them today, no range-modifier dependency. Fire/quiet validated over real emitted telemetry: 0 hits on `benign-baseline`; fires on both rogue writes in `anomalous-m1`; fires on the allow-listed-but-off-policy writes in `anomalous-m1-out-of-policy-write` while staying quiet on its in-policy write. Closes the PR #7 review on the unit/register gap.)
  - [x] **M2** Illegal / abnormal function code — **Sigma**. (`detections/sigma/modbus_m2_illegal_function_code.yml`; reserved/undefined code via `action_class: other`, or an `ILLEGAL_FUNCTION`/`ILLEGAL_DATA_ADDRESS` exception. Parses under pinned pySigma; fire/quiet awaits the undefined-code emitter + harness, per the M2 scenario note.)
  - [x] **M3** Function-code / unit-ID sweep — **Sigma correlation** or **Zeek** (must include ≥1 **Zeek** detection somewhere in this phase; if M3 stays Sigma, add a Zeek variant or pull X1’s Modbus path forward). (Shipped as the **Zeek** rail: `detections/zeek/modbus_m3_unit_function_sweep.zeek` — per-source distinct function-code/unit-ID diversity over a window, **diversity not volume**. `modbus_message`/`ModbusHeaders` API verified against live base Zeek source. Tier-2 fire/quiet runs with the Phase-2 Zeek runner.)
- [x] Build the **test harness** (pytest) enforcing the Detection Definition of Done for M1–M3 (Tier 1: Sigma over JSON). (`tests/test_detection_contract.py` — fully metadata-driven: reads `detections/registry.yaml` + every `scenarios/` scenario and, per detection, asserts fire-on-anomaly AND quiet-on-benign from its own `exercises:`, auto-discovering new detections with no test-code change. Tier-1 Sigma is evaluated in-process via `substation/detect/sigma_eval.py` (the spike-03 parsed-AST walk); it also enforces contract linkage (rule+doc exist, ≥1 fire/≥1 quiet, exercises reference known IDs) and that each Sigma rule's logsource+ATT&CK tags agree with the registry. Tier-2 Zeek (M3) and the not-yet-emittable M2 fire fixture are skipped with explicit reasons, not silently passed. Runs under `make ci`'s `test` target.)
- [x] Generate the **first coverage-map row(s)** from detection metadata. (`substation/coverage/` — `python -m substation.coverage` renders, from `detections/registry.yaml` only, `coverage/coverage.md` + `coverage/coverage.json` (technique, tactic, protocol, detection ID, engine, tier, status) and `coverage/navigator-layer.json`. Deterministic and generated, never hand-edited (the `coverage/` outputs stay git-ignored per repo policy). `make coverage-build` is wired into `make ci`, which regenerates them from the registry every run so they cannot drift; `make coverage-check` additionally verifies a committed snapshot against the registry when one exists.)
- [x] **VERIFY — ATT&CK IDs** for M1–M3 against the live matrix; record IDs. (Verified 2026-06-04 against the live ATT&CK-for-ICS matrix: **M1** → T1692.001 *Unauthorized Message: Command Message* + related T0836 *Modify Parameter* (Impair Process Control, TA0106); **M2** → T0888 *Remote System Information Discovery* (Discovery, TA0102); **M3** → T0846 *Remote System Discovery* (Discovery, TA0102). NB the matrix was restructured — former *T0855 Unauthorized Command Message* is now **T1692.001**. Recorded per-detection in `detections/docs/`.)
- [x] Write per-detection docs incl. **false-positive profiles**. (`detections/docs/M1-unauthorized-write.md`, `M2-illegal-function-code.md`, `M3-unit-function-sweep.md` — each: engine choice + rationale, data source, false-positive profile, and the verified ATT&CK mapping with provenance.)

**Deliverables:** working Modbus generate→detect→report; ≥3 detections (≥1 Sigma, ≥1 Zeek); first coverage rows; `docs/schema.md` (Modbus).
**Exit criteria:** every Modbus detection fires on its anomalous scenario and stays quiet on benign; coverage map renders the Modbus rows; harness green locally.

-----

## Phase 2 — Harden, CI, one-command demo, docs

**Objective:** make it real for a first-time visitor and keep it green automatically.

**Tasks**

- [ ] **GitHub Actions (Tier 1):** run the full generate→detect→report loop on every push/PR; fail on any contract violation.
- [ ] **GitHub Actions (Tier 2):** containerized **Zeek + ICSNPP** (and **Suricata** if used) to (a) run the **fidelity check** (diff our Modbus JSON vs real Zeek output) and (b) execute Zeek/Suricata detections.
- [ ] Polish the **one-command demo** (`make demo` / `substation demo`): clean output showing hits + a readable coverage map; confirm zero external deps for Tier 1.
- [x] **README:** “why this exists,” the one-command quick start (<5 min to first success), Tier 1 vs Tier 2 explanation, safety statement (files-only; defensive-only). (`README.md` rebuilt as a storefront: hero + one-line pitch + STATIC shields.io badges (Python 3.11+, MIT, "CI: local via Claude Code", locally-generated ATT&CK-ICS coverage — no CI-service badges); "Why this exists"; copy-pasteable one-command quick start with a realistic terminal sample (quiet-on-benign + fire-on-anomaly); a Mermaid architecture diagram (scenario model → dual emit → Tier 1 detect/report, Tier 2 verify alongside); the generated ATT&CK-for-ICS coverage table + Navigator-layer load link; Tier 1 vs Tier 2 explained; explicit SAFETY section (files-only, defensive-only, passive/isolated honeypot). Plus a `make demo-cast` target + `scripts/record-demo.sh` (asciinema+agg) and a `docs/assets/demo.svg` placeholder to record the demo to an animated SVG/GIF.)
- [ ] Finalize `docs/schema.md` as the binding contract.
- [x] Add the **ATT&CK Navigator layer** export to the coverage builder. (Pulled forward to Phase 1 alongside the coverage generator: `substation/coverage/builder.py` `render_navigator_layer` emits an `ics-attack` Navigator layer (`coverage/navigator-layer.json`) from the registry — one technique object per (technique, tactic), scored by detection count. Regenerated by `make coverage-build` (wired into `make ci`).)
- [x] Enforce the **files-only invariant** in code (guard against socket sends) + assert it in tests. (Pulled forward to Phase 1: `substation/emit/guard.py` `files_only_guard` wraps all emission and makes every socket connect/transmit primitive raise `FilesOnlyViolation`; `tests/test_files_only.py` proves generation opens **no** socket and the guard blocks connect/send.)

**Deliverables:** green CI (both tiers); polished demo; README; Navigator layer.
**Exit criteria:** clean clone → one command → hits + coverage map on Linux/macOS with only Python 3.11+ (Tier 1); CI green including Tier-2 fidelity check.

-----

## Phase 3 — DNP3

**Objective:** extend on the proven pattern; validate that “add a protocol” is mechanical.

**Tasks**

- [x] Add DNP3 `detail` to the schema (VERIFY ICSNPP DNP3 fields). (Spiked first: `docs/spikes/04-icsnpp-dnp3-fields.md` verifies field names against Zeek base `dnp3.log` (`DNP3::Info` + `DNP3::function_codes`) and ICSNPP `dnp3_control.log`/`dnp3_objects.log` (`scripts/main.zeek`) — fetched live, not memory. DNP3 `detail` (`fc_request`/`fc_reply`/`iin` + `control`/`objects` sub-objects) FROZEN in `docs/schema.md` + `substation/schema/event-log.schema.json` (`proto==dnp3` branch + `dnp3_detail`/`dnp3_control`/`dnp3_objects` `$defs`, `additionalProperties:false`). Golden events `tests/data/events/dnp3/valid.jsonl` are validated by `make ci`'s `schema` target.)
- [x] DNP3 encoders + PCAP/JSON emit (scapy capability spike for DNP3). (`docs/spikes/05-scapy-dnp3-capability.md` — verdict: **scapy 2.7.0 ships no DNP3 layer**, so the PCAP is hand-built; the DNP3 CRC + frame layout are verified against ICSNPP's real `dnp3_example.pcap`. **One** shared event model — `substation/protocols/dnp3.py` `build_events` → `Dnp3Event` — drives both emitters (`event_to_dict` for JSON; `substation/emit/dnp3_pcap.py` for hand-built DNP3/TCP), so PCAP and JSON cannot drift (PRD §6.1). `emit/__init__.py` dispatches per protocol; JSON write/validate is shared. Byte-deterministic; one DNP3 link frame per JSON event with matching function codes + valid CRCs — `tests/test_emit_dnp3.py`.)
- [x] Benign DNP3 scenarios (legitimate master polling + unsolicited responses). (`scenarios/dnp3/benign-baseline.yaml` — allow-listed master enables unsolicited reporting, polls continuously (READ) and issues a legitimate OPERATE; the outstation returns solicited RESPONSEs and spontaneous UNSOLICITED_RESPONSEs. The canonical quiet baseline for D1–D4.)
- [x] Anomalous scenarios + detections D1–D4 (allow-list for D3; diversity/sweep for D4). (`anomalous-d1-restart.yaml` (COLD_RESTART from an unexpected source), `anomalous-d2-disable-unsolicited.yaml` (DISABLE_UNSOLICITED blinding), `anomalous-d3-unauthorized-operate.yaml` (OPERATE/DIRECT_OPERATE from a non-allow-listed master), `anomalous-d4-enumeration.yaml` (one source, nine distinct function codes). **D1/D2/D3 Sigma** (allow-list) + **D4 Zeek** (function-code diversity, mirroring M3) under `detections/`; proves both rails per PRD §6.5. Each scenario's `exercises.fires`/`quiet` make it fire its target and stay quiet on the others.)
- [x] Harness + coverage rows; **VERIFY** ATT&CK IDs; docs + FP profiles. (Metadata-driven harness auto-discovers D1–D4 from `detections/registry.yaml` — D1/D2/D3 fire-on-anomaly AND quiet-on-benign proven Tier-1 over real telemetry; D4 (Zeek tier2) fire/quiet runs in the Tier-2 runner, linkage enforced now. **ATT&CK IDs VERIFIED** against the live matrix 2026-06-04 — D1 → T0816 *Device Restart/Shutdown* + T0814 (Inhibit Response Function, TA0107); D2 → **T1691.002** *Block Operational Technology Message: Reporting Message* + T0878 (Inhibit Response Function); D3 → **T1692.001** *Unauthorized Message: Command Message* (Impair Process Control, TA0106); D4 → T0888 *Remote System Information Discovery* + T0846 (Discovery, TA0102). NB the matrix was restructured: former T0804 → T1691.002, former T0855 → T1692.001. Per-detection docs + FP profiles in `detections/docs/D1–D4`.)

**Deliverables:** DNP3 end-to-end; D1–D4 satisfying the contract.
**Exit criteria:** DNP3 detections fire/quiet correctly; coverage updated; CI green; the act of adding DNP3 surfaced concrete inputs for `docs/adding-a-protocol.md` (friction recorded in `docs/adding-a-protocol.md` → "DNP3 friction notes" and spike 05).

-----

## Phase 4 — Siemens S7 (highest risk; isolated phase)

**Objective:** cover S7comm/S7comm-plus despite the absence of an open spec.

**Tasks**

- [x] Schema `detail` for S7 over **COTP/TPKT** (VERIFY ICSNPP S7 fields). (Spiked first: `docs/spikes/06-icsnpp-s7comm-fields.md` verifies field names + value tables against `cisagov/icsnpp-s7comm` `scripts/icsnpp/s7comm/main.zeek` + `scripts/consts.zeek` — fetched live, not memory. S7 `detail` (`rosctr_*`/`pdu_reference`/`function_*`/`subfunction_*`/`error_*` + `cotp`/`read_szl`/`upload_download`/`plus` sub-objects, mirroring `cotp.log`/`s7comm.log`/`s7comm_read_szl.log`/`s7comm_upload_download.log`/`s7comm_plus.log`) FROZEN in `docs/schema.md` + `substation/schema/event-log.schema.json` (`proto==s7comm` branch + `s7comm_detail`/`s7comm_cotp`/`s7comm_read_szl`/`s7comm_upload_download`/`s7comm_plus` `$defs`, `additionalProperties:false`). Golden events `tests/data/events/s7/valid.jsonl` validated by `make ci`'s `schema` target.)
- [x] S7 PDU construction — expect **hand-built PDUs / template PCAPs** (scapy lacks solid S7comm); reference Wireshark S7comm dissector. (`docs/spikes/07-s7comm-pdu-capability.md` — verdict: **scapy 2.7.0 ships no S7/COTP/TPKT layer**, so the PCAP is hand-built; the TPKT/COTP framing + S7comm header layout are verified byte-for-byte against ICSNPP's `snap7.pcap` / `s7ident.pcap` (incl. the Read-SZL parameter and the 10- vs 12-byte ACK-Data header). **One** shared event model — `substation/protocols/s7comm.py` `build_events` → `S7Event` — drives both emitters (`event_to_dict` for JSON; `substation/emit/s7comm_pcap.py` for hand-built TPKT/COTP/S7comm/S7comm-plus over TCP/102), so PCAP and JSON cannot drift (PRD §6.1). Byte-deterministic; one TPKT/S7 PDU per JSON event, with a COTP CR/CC handshake per connection — `tests/test_emit_s7comm.py`. S7comm-plus example is integrity-protected, so its opcode/function offsets are dissector-derived (Tier-2 fidelity item, spike 07).)
- [x] Benign S7 scenarios (normal engineering/HMI interaction). (`scenarios/s7/benign-baseline.yaml` — an allow-listed EWS connects, reads module identity once, performs a sanctioned program download and a legitimate run-state change, while an operator HMI continuously reads/writes process tags. The canonical quiet baseline for S1–S3.)
- [x] Anomalous scenarios + detections S1–S3 (CPU stop/start; data-block/program write; enumeration). (`anomalous-s1-cpu-stop.yaml` (PLC Stop from a non-allow-listed source amid a legit EWS run-state change), `anomalous-s2-program-download.yaml` (Request/Download Block/Download Ended + S7comm-plus Create Object from a rogue source), `anomalous-s3-enumeration.yaml` (one source sweeping six distinct module-info SZLs + List Blocks + Explore). **S1/S2 Sigma** (allow-list) + **S3 Zeek** (SZL-ID diversity, mirroring M3/D4) under `detections/`; proves both rails per PRD §6.5. Each scenario's `exercises.fires`/`quiet` make it fire its target and stay quiet on the others.)
- [x] Harness + coverage rows; **VERIFY** ATT&CK IDs; docs + FP profiles. (Metadata-driven harness auto-discovers S1–S3 from `detections/registry.yaml` — S1/S2 fire-on-anomaly AND quiet-on-benign proven Tier-1 over real telemetry; S3 (Zeek tier2) fire/quiet runs in the Tier-2 runner, linkage enforced now. **ATT&CK IDs VERIFIED** against the live matrix 2026-06-04 — S1 → **T0858** *Change Operating Mode* (Execution, TA0104); S2 → **T0843** *Program Download* (Lateral Movement, TA0109); S3 → T0888 *Remote System Information Discovery* + T0846 *Remote System Discovery* (Discovery, TA0102). Per-detection docs + FP profiles in `detections/docs/S1–S3`.)

**Deliverables:** S7 end-to-end; S1–S3 satisfying the contract.
**Exit criteria:** S7 detections fire/quiet correctly; coverage updated; CI green.

-----

## Phase 5 — Coverage polish, contributor guides, optional honeypot

**Objective:** maximize visibility and make external contribution easy; add the research honeypot last.

**Tasks**

- [x] Implement/finish **cross-protocol baseline detection X1** (Zeek; learned state + set membership over the normalized envelope). (`detections/zeek/x1_cross_protocol_baseline.zeek` — normalizes Modbus `modbus_message`, DNP3 `dnp3_application_request_header` and S7comm `s7comm_read_szl` (the events verified for M3/D4/S3) into one `(orig_h, resp_h, func)` tuple and runs a single learned baseline over all three. Three deviation classes in precedence order — **new talker** > **new asset pair** > **new function for a pair** — with the learned state injected via `redef`-able `known_talkers`/`known_pairs`/`known_funcs` (the Tier-2 runner derives it from the benign baselines) plus an optional self-learn window. Registry id `X1`, protocol `cross` (new registry label), ATT&CK Discovery/**T0846** (verified, same as M3/D4/S3; PRD §5.4's Lateral Movement relation noted in the doc). Benign+anomalous scenarios span protocols: all three `benign-baseline.yaml` add `X1` to `exercises.quiet`; `scenarios/modbus/anomalous-x1-new-talker.yaml` (new talker/pair) + `scenarios/dnp3/anomalous-x1-new-function.yaml` (new function for a known pair) fire it. Doc + FP profile: `detections/docs/X1-cross-protocol-baseline.md`. Tier-2 like the other Zeek rails; harness enforces contract linkage now.)
- [x] Polish the coverage map: rendered table in README/docs + downloadable Navigator layer; show covered vs gap techniques. (`substation/coverage/builder.py` now renders a **covered-vs-gap** view over the full ICS tactic matrix (`_ICS_TACTICS`, stable tactic IDs) in both `coverage.md` and `coverage.json` (`tactic_coverage`), plus a Navigator-layer download link. A committed, published snapshot lives at `docs/coverage/` (`coverage.md` rendered table + `coverage.json` + `navigator-layer.json`); `make coverage-build` writes both the git-ignored working copy and the docs snapshot, and `make coverage-check` is the drift gate against `docs/coverage`. 5/12 tactics currently covered.)
- [x] `docs/adding-a-protocol.md` and `docs/adding-a-detection.md` — finite ordered checklists derived from the DNP3/S7 experience; reference the Detection Definition of Done. (Both rewritten as finite, ordered checklists keyed to the **Detection Contract** / Detection Definition of Done. `adding-a-detection.md` (10 steps) covers an existing protocol; `adding-a-protocol.md` (8 steps) covers a new protocol and preserves the DNP3 + S7 friction notes that seeded it.)
- [x] `CONTRIBUTING.md` + PR template that checks the Detection Contract. (`CONTRIBUTING.md` — ground rules (defensive-only, files-only, no cloud CI, VERIFY gates), setup, what to contribute, the 8-point Detection Contract, engine policy, commit/PR process. `.github/PULL_REQUEST_TEMPLATE.md` — itemizes every Detection Contract element as checkboxes plus the safety invariants and `make ci`/coverage gates; it is a PR template only, not a workflow.)
- [x] **Optional honeypot** (`PRD.md` §6.10): minimal **passive, isolated** Modbus responder logging probes; opt-in; strong safety/legal README; built only after the above is solid. (`substation/honeypot/` — a passive Modbus/TCP probe logger, deliberately **out of the headline path** (nothing in `cli`/`make demo` imports it). It **only listens/responds** and **never** initiates an outbound connection (no `connect()`), and never touches real OT. No process emulation beyond banner/coil/register **stubs** + standards-compliant exception replies. The protocol core (`process_frame`) is a **pure function** mapping request bytes → `(reply, [events])` with no I/O, wrapped by a thin `ModbusHoneypot` socket loop. Every probe is logged through the **same** `substation.protocols.modbus.event_to_dict` mapping the simulator uses and validated against the frozen event-log schema before write, so captured probes conform to `docs/schema.md` and the shipped Tier-1 detections run against them unchanged (tests prove M1/M2 fire on honeypot telemetry). **Isolated by default**: binds loopback only unless an explicit `--allow-external` opt-in. Its own `substation/honeypot/README.md` states opt-in, deploy-network-isolated-only, plus safety/legal cautions. `python -m substation.honeypot` CLI. Pure-core + config-safety tests in `tests/test_honeypot.py` open no socket.)
- [ ] Launch polish: examples/screens of the demo output and coverage map for the README.

**Deliverables:** flagship coverage story; contributor path; optional honeypot.
**Exit criteria:** a contributor can add a protocol/detection by following the docs; coverage map is launch-quality; honeypot (if shipped) is clearly optional, passive, and isolated.

-----

## Cross-cutting / definition of “launch-ready”

- [ ] One command, clean clone, <5 min to first success (Tier 1, Python-only).
- [ ] All shipped detections satisfy the Detection Definition of Done.
- [ ] Every ATT&CK mapping cites a **verified** technique ID.
- [ ] CI green (Tier 1 always; Tier 2 fidelity + Zeek/Suricata).
- [x] README answers “why this exists” and shows the payoff visually.
- [ ] Safety posture explicit and enforced: files-only simulator, defensive-only, passive/isolated honeypot.
- [ ] Clear, documented path to add protocols/detections.

## Verification gates (master list)

- **ATT&CK-for-ICS technique IDs** — verify against the live matrix at coverage-map time, per detection. Never trusted from memory.
- **ICSNPP field names / detail shapes** — verify against current parsers before freezing each protocol’s schema.
- **scapy capability** — spike per protocol; decide scapy vs hand-built vs template PCAP.
- **Sigma offline evaluation** — confirm the harness’s Sigma-to-Python evaluation mechanism (Phase 0).

## Where Claude Code fits

Bulk scaffolding (package skeleton, boilerplate, repetitive per-protocol stubs) can be offloaded to Claude Code once Phase 0 decisions and the schema are pinned. Design, schema, detection logic, ATT&CK mappings, and reviews stay here.
