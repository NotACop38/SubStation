# Changelog

All notable changes to **Substation** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut **locally** with `make release` (CLAUDE.md: no cloud CI/CD); the
`## [Unreleased]` section is promoted to the new version at release time.

## [Unreleased]

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
