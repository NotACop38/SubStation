> Historical review snapshot. See the [current closeout](2026-09-10-validation-closeout.md) for completed follow-up work, current checks and remaining qualification limits. The findings and counts below record the earlier review stage.

# Substation project and code review — 2026-09-09

## Assessment

Substation has a defensible purpose as an **offline detection regression and
teaching toolkit**. Readable scenarios, files-only execution, seven Sigma examples
and four stateful Zeek rules make useful material for learning and repeatable
content development. The original production-readiness story exceeded the
implementation and evidence. Synthetic fixtures authored alongside their rules
can agree with each other while both omit important behavior.

The review retained the core architecture and corrected the product contract:
experimental templates, explicit sample policies, independent parser checks and
honest validation boundaries. Adding more protocols would currently increase the
qualification burden faster than demonstrated utility. Representative independent
traffic and sensor normalization should precede catalogue expansion.

Scope included the PRD and checklist, runtime modules, all detection families,
scenario and schema contracts, tests, packaging, release/security scripts,
documentation and generated assets. Changes were made on
`codex/project-review-hardening` from baseline `ed9a573`. This is a bounded review
with regression evidence, not a guarantee that every defect has been found.

## Findings and corrections

Priority describes impact on the project's own promises, not a CVSS rating.

| Priority | Finding and practical effect | Correction and evidence |
|---|---|---|
| P1 | M1 authorized only a write's starting address. A permitted writer could start inside 40–49 and extend past the policy without an alert. Destination, service and coil/register distinctions were also absent. | Authorize the entire holding-register span, source, target, service and unit. The formerly accepted span-gap scenario now fires. `test_m1_policy.py` checks 132 intervals against an independent range oracle and tests alternate assets, ports and coils. |
| P1 | X1 added novel traffic to its trusted sets after alerting. An anomaly could permanently authorize later traffic during that Zeek process. | Freeze trust after the explicit learning window. Separate five-minute alert suppression from authorization. A real-Zeek regression confirms recurrence after suppression and unchanged known sets, including timestamp-zero traffic. |
| P1 | S7 JSON and hand-built PCAPs disagreed. Missing download fields stopped the independent parser mid-flow; S7-plus omitted a digest-length field and ignored the requested version. User-Data responses also had incorrect framing. | Correct wire headers and minimal synthetic bodies. Add S7 request identity/count comparisons through the compiled CISA parser. All six S7 scenarios pass this check; wire-version tests cover versions 1–3. |
| P1 | A source archive omitted the detection/scenario content required by its wheel build. The release used `--no-isolation` but the dev environment lacked setuptools/wheel. | Explicit source manifest, restricted wheel-content copying and pinned build dependencies. A regression builds the sdist, rebuilds its wheel and compares every rule/scenario byte with the source. |
| P1 | Retrying an old release version could build current, unrelated source under an existing tag. `--allow-dirty` could omit new source files from the tagged tree. | Existing-tag retries require the clean tagged HEAD and matching version. Dirty mode accepts only tracked changes within release paths; new files must be committed first. Isolated Git regression tests exercise refusal cases. |
| P2 | Secret-scan backends examined different content. Native gitleaks examined history, while release claimed to scan staged content but actually read the working tree. A staged secret could be hidden by cleaning its working copy. | All backends scan the same source snapshot. Release explicitly scans the complete index. Synthetic regression proves staged bytes are caught after the working copy is cleaned. Missing scanners fail the gate; the regex fallback is diagnostic only. This is still not a history audit. |
| P2 | `make ci` regenerated coverage before checking it, silently repairing the drift it was meant to reject. Parallel make could race generation and checking. | Remove regeneration from CI. Isolated orchestration tests exercise both serial and parallel make with a stale sentinel and prove it remains unchanged while CI fails. |
| P2 | Sigma string matching was case-sensitive by default; unsupported expressions could hide behind short-circuit branches or empty input. Duplicate YAML and cached path content could obscure rule changes. | Match the supported Sigma semantics, honor explicit cased strings, reject unsupported AST nodes before reading events, reject duplicate keys and cache by rule content. Regression tests cover all these boundaries. |
| P2 | Malformed JSON input could appear to produce a quiet result; duplicate keys and non-finite values were accepted. Validating an empty directory reported success. | Validate strict JSON and schema before detection; reject duplicate keys, nonobjects and non-finite numbers. Empty input directories fail. New `substation detect` exposes validated Tier-1 evaluation with machine-readable hits and no partial output on invalid files. |
| P2 | DNP3/S7 rules treated an approved source as authorized for every destination. S1 called all PLC Control services CPU start/stop activity. | Scope example source permissions to the destination/service. Match S1 PLC Control only for `P_PROGRAM`, alongside PLC Stop. Tests distinguish approved channels from other targets and CPU control from `_GARB`/`_INSE`. |
| P2 | Tier-2 plugin probes used shell pipelines that could hide a failed Zeek exit. An unrecognized rule or unwired Suricata path could be skipped. A cached parser at the right commit could contain modified files. | Check subprocess statuses directly; reject dirty parser caches; fail unmapped/unwired checks. Add native Zeek and `--require-complete`. Release requires complete Tier 2 unless the operator explicitly waives it. |
| P2 | Scenario parameters could be misspelled or supplied to a function that silently ignored them. | Reject unknown/unused parameters for Modbus, S7 and DNP3 unsolicited responses. Tests exercise real emission with mistyped input. |
| P2 | Dependency audit could use a lock inconsistent with declared requirements. Development installation did not consume the transitive lock. | Check direct-requirement/lock consistency before auditing and install the lock in `make dev`. Pins are not artifact hashes; the check does not prove arbitrary lock entries form a complete transitive closure. |
| P2 | README and demo graphics called unevaluated Zeek rules quiet, promised zero dependencies, and described synthetic tests as production proof. The GIF was a hand-maintained transcript. | Reframe the README/PRD, mark Sigma rules experimental, explain mapping-count semantics, and generate GIF/SVG directly from a successful CLI run. Default demo now fails its own broken contracts. |

## Architectural decisions

| Decision | Judgment and resulting boundary |
|---|---|
| Files-only simulator | Keep. It meets the development objective without adding live-OT interaction. Runtime socket guards plus static/dynamic tests provide defense in depth; they are not a general sandbox against arbitrary hostile Python. |
| One model, two emitters | Keep. Shared input reduces duplicate scenario logic. It cannot prove equivalent outputs: the S7 failures demonstrated that directly. Independent parsing remains necessary. |
| Normalized JSON envelope | Keep as the synthetic toolkit contract. Native Zeek logs have different record structure, direction and transaction semantics. No automatic sensor adapter is shipped. X1 normalizes native events separately and does not consume this JSON envelope. |
| Sigma-first policy | Keep for single-event predicates and portable authoring. The offline evaluator supports a deliberate subset, not all Sigma syntax or backend behavior. Unsupported constructs fail. A compiled backend still needs differential testing. |
| Hand-written JSON Schema subset validator | Retain while the contract remains fixed and small. It avoids another runtime dependency but adds maintenance burden. Schema syntax validation is not protocol-semantic consistency; extending the schema requires matching validator coverage or a standard validator. |
| Two execution tiers | Keep. Python-only installation is accessible, while stateful Zeek rules must run in their real engine. Native results are labeled separately from pinned-container results; partial runs cannot support a complete qualification claim. |
| IP-based allowlists | Appropriate as explicit sample policies, insufficient as authenticated authorization. A compromised approved master using an approved channel is invisible to that predicate. Time windows, operating state, DNP3 point policy and S7 block policy remain site-specific gaps. |
| Sweep rules M3/D4/S3 | Distinct function/unit/SZL counts are better than raw volume for these examples. Thresholds/windows remain illustrative; maintenance tools, scan rates, restarts, packet loss and distribution across hosts need independent testing. |
| X1 baseline novelty | Useful change signal, not proof of reconnaissance or lateral movement. Training data can be contaminated. Baseline sets persist only within the Zeek process and must be reinjected after restart. Synthetic quiet cases are members by construction. |
| ATT&CK coverage map | Keep for content navigation. Ten technique mappings and five tactic buckets do not quantify detection effectiveness. Related impacts such as blinding or process modification are not demonstrated physical outcomes. |
| Optional honeypot | Keep separate, loopback by default and opt-in. It adds network-service maintenance without being necessary for the simulator's purpose. This review inspected its protocol/configuration code and ran its socket-free tests; it did not deploy or externally exercise the listener. |
| Local CI and release | Respect the local-only policy. No cloud workflow was added. Scan/check the proposed source and index, preserve interpreter selection and verify rebuilt distributions. Locks lack hashes and build reproducibility across hosts is not established. |
| Further protocol expansion | Defer. M4 remains planned. Prefer independent fixtures, normalization adapters, field-level parity and backend comparison before adding more protocols or honeypot behavior. |

## Validation evidence

The initial Python suite had **340 passes and 21 Tier-2 skips**. It did not expose
the S7 parser failures, release archive omission or accepted M1 policy gap.

Final local results:

- Full `make ci`: **passed**: 396 tests passed, 21 explicitly delegated Tier-2 skips; formatting, lint, strict types, schema, coverage, security and packaging checks passed.
- Complete native Tier 2: **41 passed, 0 failed, 1 optional skip** (no Suricata rules).
- Native Tier 2 without the S7 plugin: the same strict mode **correctly failed** with four required S7 skips, despite 29 passing checks.
- Source archive → rebuilt wheel: passing regression, including every shipped rule/scenario.
- Clean installed-wheel CLI smoke test: **passed**: `list`, `demo --strict`, `validate`, `detect`, coverage write/check and `pip check`, with imports verified inside the new environment.
- Current demo GIF/SVG and transcript: regenerated from executable output and visually inspected.
- ATT&CK: all registry technique IDs/names and tactic memberships checked against the live MITRE ICS STIX dataset; ten unique technique IDs, seventeen mapping associations, no revoked/deprecated technique references.

The native engine was **Zeek 8.2.2** with **ICSNPP S7comm 1.3.0**, upstream commit
`7ebeb03a0f954541369361651d1c27d09a64b5a3`. Modbus/DNP3 used the runner's existing
upstream commit pins. Docker was unavailable on the review host, so the pinned
Docker image was not qualified. Native Zeek and CMake were installed locally;
the S7 plugin was built locally and loaded explicitly, without deploying a sensor.
Homebrew reported an `openssl@3` post-install warning; a retry also warned. Zeek
ran successfully, but that Homebrew certificate/post-install step is not verified.

One documented diskcache advisory remains ignored by the scoped dependency audit:
its deserialization cache path is not used by this toolkit, with a regression
checking that boundary. This acceptance must be reevaluated if that path changes.
The audit covers the declared locked dependency set, not every package on the host.
The generated CycloneDX inventory is explicitly labeled **direct dependencies
only**; transitive SBOM entries and dependency edges remain a supply-chain gap.

## Remaining evidence gaps

No field deployment, representative independent benign corpus, production recall
measurement, false-positive-rate measurement or SIEM-backend comparison was
performed. Zeek request parity currently checks source/destination/function
**counts**, not every address, value, response or timing relationship. The tested
S7 parser emitted different PDU-reference values from the correctly encoded wire
reference; full S7 detail equivalence remains unqualified. Plaintext S7-plus
fixtures are not validation of integrity-protected or encrypted sessions.

These are product boundaries and next priorities, not claims covered by a green
unit suite. No project release, tag, remote push, live-OT transmission or honeypot
activation was performed during the initial review above. The subsequent PR
review and integration are recorded separately below.

## PR review follow-up

The second pass reviewed the complete branch against current `main`, including
surrounding input, packaging, release and hook behavior. It found and corrected:

- **P2 — incomplete input failure handling.** Oversized and invalid UTF-8 logs
  raised uncaught exceptions, while named pipes could wait indefinitely. Both
  detection and schema validation now share a bounded reader that checks the
  opened descriptor, refuses special files without waiting, and limits reads even
  if a regular file grows. Regressions cover byte/line limits, invalid encoding,
  excessive nesting and no partial detection output when a later file fails.
- **P2 — push gate installed outside Git's active hook directory.** The installer
  ignored `core.hooksPath` and placed linked-worktree hooks in an unused location.
  It now asks Git for the active directory and preserves unrelated existing
  hooks. Real isolated Git repositories test default/custom paths, linked
  worktrees and repeat installation. The hook no longer recommends bypassing CI.
- **P2 — review changelog inserted into its introductory sentence.** The initial
  documentation change left the new review notes outside the actual Unreleased
  section, so release promotion would omit them. The notes now belong to the
  single Unreleased section, and superseded stable-status/span-gap statements
  match the final behavior.

This is an agent self-review with executable regression checks, not an independent
reviewer approval. Existing sample-policy and qualification limits still apply.

## Primary references checked

- [MITRE ATT&CK for ICS matrix](https://attack.mitre.org/matrices/ics/) and [MITRE ICS STIX dataset](https://github.com/mitre-attack/attack-stix-data/blob/master/ics-attack/ics-attack.json): identifiers, names, status and tactic membership.
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html): default case-insensitive strings and experimental/stable status meaning.
- [CISA ICSNPP Modbus parser](https://github.com/cisagov/icsnpp-modbus/blob/main/scripts/main.zeek): request/transaction field semantics and target/span fields.
- [CISA ICSNPP S7comm](https://github.com/cisagov/icsnpp-s7comm): event signatures, optional subfunction sentinel and PDU layouts, checked against the source revision used for the local build.
