# Validation record

What Substation's checks establish, how to reproduce them, and what they do not
establish. Recorded on 2026-09-26 on Python 3.11, with the suite also passing on 3.12 and
3.13; every number below comes from the commands in this document, which anyone
can rerun.

| Gate | Command | Result |
|---|---|---|
| Local CI | `make ci` | Pass: format, lint, strict mypy, schema, coverage drift, security, and 687 tests: 637 pass, 37 Zeek-rule contract cases defer to Tier 2, 13 need native Zeek |
| Tier 2 | `make verify VERIFY_ARGS=--require-complete` | 65 checks passed, 0 failed (Docker, Zeek 8.2); Suricata reported as "no rules shipped" |
| External corpus | `make corpus` | Pass: 3 labeled cases, 42 event evaluations, no false positives or negatives |
| SIEM backend | `make verify-sigma` | Authored and exported rules hit identically in the official SQLite backend over 342 events |

## Tier 1: the Detection Contract

The harness (`tests/test_detection_contract.py`) reads the registry and, for every
detection, requires the rule, the doc, at least one scenario that must fire and one
that must stay quiet, a verified ATT&CK mapping and a registry entry. For the seven
Sigma rules it generates each scenario, evaluates the rule, and requires firing or
silence as declared. Each fire case also pins the exact event indices the rule must
hit, so a rule that fires on extra events fails. The Zeek rules' contract linkage is
checked here and their behavior in Tier 2.

The Tier-1 evaluator parses each rule with pySigma and rejects any construct it
does not implement (wildcards, regular expressions, placeholders, field
references, correlation rules) instead of mis-evaluating it. Equality is typed:
a quoted value matches only strings, an unquoted number only numbers. Every
shipped rule, and every rule compiled from the bundled policy, passes pySigma's
offline validators, except four tag-namespace validators (ATT&CK Enterprise,
CAR, D3FEND, threat groups) that do not know ATT&CK for ICS; the ICS tags are
checked against the registry instead.

## ATT&CK mappings

On 2026-09-26 every technique in the registry (T0801, T0814, T0816, T0836,
T0843, T0846, T0858, T0861, T0878, T0888, T1691.002, T1692.001) was re-checked
against the live ATT&CK-for-ICS matrix: all are current, and each detection's
tactic is one the technique belongs to. Each detection doc records its own
sources.

## Tier 2: independent parsers and the real engine

`make verify` runs Zeek 8.2
(`zeek/zeek@sha256:32b90c30cb87d66748c3a6776ad2c0f5502aae7c12da9766cfdd426453c58838`)
with ICSNPP Modbus at `64559be1`, ICSNPP DNP3 at `6e997bfc`, and ICSNPP S7comm
1.3.0 at `7ebeb03a` plus a reviewed bounds patch, built locally
([Tier-2 guide](tier2.md)).

| Check | Scope | Result |
|---|---|---|
| Modbus fields | 11 scenarios: 10 compared by identity, spans, values and outcomes, the illegal-function scenario by request count | 11 pass |
| External Modbus corpus | 2 attributed captures reparsed and compared with committed logs | 2 pass |
| DNP3 messages | 7 scenarios and 2 boundary fixtures: direction, order, function, IIN, objects, controls | 9 pass |
| S7 fields | 5 scenarios and an all-operations fixture: COTP, direction, order, headers, modeled details | 6 pass |
| M3 function/unit sweep | 1 fire, 8 quiet scenarios | 9 pass |
| M4 read sweep | 1 fire, 10 quiet scenarios | 11 pass |
| D4 function enumeration | 1 fire, 2 quiet scenarios | 3 pass |
| S3 SZL enumeration | 1 fire, 4 quiet scenarios | 5 pass |
| X1 baseline deviation | 4 fire (Modbus, DNP3, S7), 5 quiet scenarios | 9 pass |

Any `weird.log` diagnostic fails a comparison. These comparisons have caught real
encoder defects, among them DNP3 object widths, operation labels and IIN
representation.

## External Modbus corpus

The [attributed corpus](../tests/data/corpus/modbus/README.md) preserves selected
payloads from an external analyzer's test trace, with provenance and hashes.
`make corpus` verifies the hashes and schema, then scores M1 and M2 per event:

| Case | Events | M1 | M2 |
|---|---|---|---|
| Authorized traffic | 20 | 20 TN | 20 TN |
| Same traffic under a deny-policy counterfactual | 20 | 2 TP, 18 TN | 20 TN |
| Exception indicator | 2 | 2 TN | 1 TP, 1 TN |

The three cases reuse 22 observations. This is regression evidence that the rules
behave on traffic Substation did not generate; it is far too small to estimate
production precision or recall, and it covers no DNP3, S7 or stateful rule.

## SIEM backend comparison

`make verify-sigma` compiles the authored rules, and the rules exported from the
bundled policy, with the official pySigma SQLite backend (backend 1.2.4, pySigma
1.3.3, SQLite 3.45.1) and runs them over 342 catalogue and corpus events. For
every rule, the backend matches exactly the events the Tier-1 evaluator matches
(M1 7, M2 3, D1 1, D2 1, D3 3, S1 1, S2 4 hits in both sets). The table contract and the reproduced NULL-handling and
expression-depth limits are in [spike 10](spikes/10-sigma-backend-qualification.md).
Other backends and field mappings are not qualified.

## Supply chain and safety

- **Dependencies:** `make dev` installs the 53 locked packages from wheels with
  pinned artifact hashes (`--require-hashes`, no source builds). Each wheel's
  metadata was verified when the lock was made, which gives an offline CycloneDX
  SBOM with the runtime and development dependency graph.
- **Audit:** pip-audit checks the locked closure with `--strict`. One advisory is
  accepted with a written rationale: CVE-2025-69872 in diskcache, a transitive
  pySigma dependency whose cache path Substation never uses (a test proves the
  demo never imports it).
- **Secrets:** detect-secrets (or gitleaks) scans the tree; inline allow comments
  are ignored, and the only exceptions are reviewed digest lines bound to exact
  paths.
- **Files-only:** emission runs under a guard that refuses socket creation, socket
  transmission and process creation, and a static scan of the package forbids
  outbound connections, raw sockets, scapy transmit functions and process
  spawning, however imported.

## What is not established

- Production false-positive rates and recall. Synthetic scenarios and a
  three-case corpus prove behavior on fixtures, not in a plant.
- Behavior on representative benign traffic from real sites.
- Packet timing, complete protocol sessions, point values, PLC or outstation
  behavior, valid programs, and S7comm-plus integrity or encryption.
- DNP3 and S7 sensor import, and deployment on any SIEM other than the SQLite
  comparison above.

These gaps are the roadmap in [`design.md`](design.md) §10.
