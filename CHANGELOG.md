# Changelog

All notable changes to **Substation** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut **locally** with `make release` (there is no cloud CI/CD); the
`## [Unreleased]` notes are promoted to the new version at release time.

## [Unreleased]

### Added

- **M4, Modbus bulk read / address-space sweep** (Zeek; Collection: T0801, T0861):
  counts distinct address pages one source reads from one table, with a
  read-sweep scenario and a bulk-poll boundary scenario.
- **Complete Tier 2 in Docker.** `make verify` builds a local Zeek image with the
  pinned ICSNPP S7comm plugin and a reviewed bounds patch (`make verify-image`),
  so S3, X1's S7 path and every S7 comparison run without extra setup
  ([`docs/tier2.md`](docs/tier2.md)).
- **Field-level comparisons with real parsers:** Modbus transactions, DNP3
  per-message headers, objects and controls, and S7 COTP, headers and modeled
  fields; any `weird.log` diagnostic fails.
- **Sensor import:** `substation import-modbus` projects ICSNPP
  `modbus_detailed` logs (Zeek JSON or TSV) into the event schema, skipping and
  counting unprojectable rows (`--strict` fails instead) and marking value
  vectors the sensor truncated.
- **Site policies:** `substation policy compile` and `detect --policy` compile a
  versioned site profile into the seven Tier-1 Sigma rules; `make verify-sigma`
  compares their hits with the official SQLite backend.
- **External evidence:** an attributed Modbus corpus with per-event labels and
  metrics (`make corpus`, `substation evaluate-corpus`).
- **DNP3 modeling:** class objects (Class 0–3 Data), `ASSIGN_CLASS`,
  `AUTHENTICATE_REQ`, undefined codes answered with IIN2.0, application-control
  sequence, confirm and unsolicited bits, automatic confirmation of unsolicited
  responses, select-before-operate status, and a master-startup boundary
  scenario for D4.
- **CLI:** `--version`, `list`, `detect`, `validate`, `coverage`, multiple
  `demo --scenario` files and `demo --strict`; a status legend on the coverage
  map; honeypot `--connection-timeout`.
- **Packaging:** detections and scenarios ship in the wheel; Python 3.12 and 3.13
  are supported; the package ships `py.typed`.
- **Supply chain:** hash-locked dependencies with verified wheel metadata and an
  offline CycloneDX SBOM.
- **Coverage:** a generated ATT&CK matrix SVG alongside the table, JSON and
  Navigator layer.
- **Docs:** [`docs/design.md`](docs/design.md), [`docs/validation.md`](docs/validation.md),
  [`docs/deployment.md`](docs/deployment.md), [`docs/tier2.md`](docs/tier2.md)
  and [`SECURITY.md`](SECURITY.md).

### Changed

- **S2** no longer matches S7comm-plus Create Object, Set Variable and Delete
  Object, which open, use and close every S7-1200/1500 HMI session; it matches
  the block download sequence and the `_INSE` block activation.
- **D4** ignores `CONFIRM` and fires at ten distinct function codes; a standard
  master startup uses nine.
- **Sigma evaluation** is strict and typed: unsupported constructs are rejected
  when the rule is parsed, a quoted value matches only strings and an unquoted
  number only numbers.
- **Modbus naming and classes follow Zeek:** the exception to an undefined code is
  `unknown-194`, not `unknown-66_EXCEPTION`; programming and firmware functions
  are `write`, and the comm-link reset is `control`.
- **Scenario names** all carry their protocol prefix (`modbus-benign-poll`), which
  renames the Modbus artifacts.
- **Event logs** are time-ordered with microsecond timestamps, and each PCAP/JSON
  pair is published atomically.
- **`make release`** requires `--version` or `--bump`, builds from the staged
  tree, and rolls back every file it touched on failure.
- **The pre-push hook** runs `make ci` with the interpreter `make hooks`
  recorded, and refuses pushes whose commit is not checked out cleanly; the
  Makefile uses `.venv` when present.
- **The dependency audit** reads the hash-locked `requirements.lock` with
  `--strict`.
- `AGENTS.md` is the single agent constitution; `CLAUDE.md` imports it.

### Removed

- The `substation verify` subcommand, which only printed instructions; run
  `make verify`.
- `make release --allow-dirty`.
- The recorded demo GIF and cast and their tooling.
- `PRD.md`, `ENGINEERING_CHECKLIST.md` and the historical reviews, plans and
  launch report; `docs/design.md` and `docs/validation.md` replace them.

### Fixed

- **S7 wire encoding:** Request Download carries its length field, downloads use
  session 0, `_INSE`/`_DELE` name the scenario's block, the function status and
  acknowledgements sit where PLCs put them, and the S7comm-plus trailer is
  correct.
- **DNP3 fidelity:** operation labels, IIN representation, per-actor link
  addresses, echoed control blocks and no fabricated responses.
- **Modbus import:** one unmatched or unsupported row no longer aborts an import,
  and value vectors Zeek cut at 100 elements are kept, marked, instead of
  rejected; Tier 2 raises Zeek's logging limits.
- **M1** enforces the complete write span, not just its start address.
- SYN segments no longer carry an acknowledgement number; out-of-range
  timestamps fail before any file is written.
- Deeply nested or unhashable YAML, Unicode whitespace in JSONL, IPv4-mapped IPv6
  policy addresses and commands run outside a checkout fail with clear errors
  instead of tracebacks or surprises.
- The corpus derivation requires the reviewed parser revision.

### Security

- The files-only guard refuses socket and process creation during emission; the
  static scan resolves aliases and `getattr`, and forbids raw sockets, scapy
  socket factories and process spawning.
- The secret scanner ignores inline allow comments and refuses in-tree gitleaks
  configuration; every reviewed exception must match a current line.
- Tier 2 refuses cached parser checkouts whose edits are hidden from
  `git status` (assume-unchanged, skip-worktree, fsmonitor, ignored files).
- The honeypot stops when its log cannot be written and closes connections at a
  wall-clock limit.
- SBOM serial numbers are distinct per release; components carry the standard
  CycloneDX `scope`.

## [0.1.0] - 2026-06-04

### Added

- **Modbus vertical slice** — scenario model + strict YAML loader, dual PCAP/JSON
  emit from one shared event model, and detections M1 (unauthorized write,
  Sigma), M2 (illegal/abnormal function code, Sigma), and M3 (unit/function
  sweep, Zeek). Frozen Modbus event-log schema (`docs/schema.md` +
  machine-readable JSON Schema).
- **DNP3 protocol** — hand-built DNP3 PCAP/JSON emit, frozen DNP3 schema detail,
  and detections D1 (restart), D2 (disable-unsolicited), D3 (unauthorized
  operate) as Sigma plus D4 (enumeration) as Zeek.
- **Siemens S7 protocol** — hand-built TPKT/COTP/S7comm(+plus) PCAP/JSON emit,
  frozen S7 schema detail, and detections S1 (change operating mode), S2 (program
  download) as Sigma plus S3 (module enumeration) as Zeek.
- **Cross-protocol baseline detection X1** (Zeek) — learned `(src, dst, func)`
  membership over the normalized envelope across Modbus/DNP3/S7.
- **Two-tier execution** — Tier 1 zero-dependency Sigma-over-JSON harness
  (metadata-driven Detection Contract enforcement) and Tier 2 containerized real
  Zeek/ICSNPP fidelity + Zeek-detection validation (`make verify`).
- **Coverage map + ATT&CK Navigator layer** — generated from the detection
  registry (`make coverage-build`), with a committed published snapshot under
  `docs/coverage/` and a covered-vs-gap tactic view.
- **Local CI/CD** — `make ci` (format, lint, strict mypy, tests, schema,
  coverage, security) as the gate, installed as a git pre-push hook; `make
  security` (bandit + scoped dependency audit + secret scan + CycloneDX SBOM +
  files-only static invariant); and `make release` (this pipeline).
- **One-command demo** (`make demo`) — quiet-on-benign plus fire-on-anomaly with
  the live ATT&CK-for-ICS coverage map, pure-Python Tier-1.
- **Optional passive, isolated Modbus research honeypot** (`substation.honeypot`)
  — opt-in, loopback-by-default, never initiates outbound connections.
- **Docs** — README storefront, `docs/schema.md`, scenario format, spike notes,
  `docs/adding-a-protocol.md` / `docs/adding-a-detection.md`, `CONTRIBUTING.md`,
  and the launch-readiness report.

### Safety

- Files-only simulator enforced at runtime (`files_only_guard`) and by a
  codebase-wide static no-raw-socket-send invariant test.
- Defensive-only: detections model the network signature of malicious behavior;
  no exploit code or payloads against real equipment.

### Packaging

- The sdist + wheel ship the **library + `substation` CLI** only. The bundled
  scenarios (`scenarios/`), detection content (`detections/`), and the published
  coverage snapshot (`docs/coverage/`) deliberately live **outside** the Python
  package (PRD §6.9), so the headline `make demo` / coverage / detection-harness
  paths run from a **repo checkout** (`make dev` + `make demo`), not from a
  bare `pip install` of the wheel. This is intentional, not an oversight: the
  detection pack and scenarios are versioned repo content, not importable package
  data. Install the wheel for the simulator/CLI as a library; clone the repo to
  run the demo and detections.
