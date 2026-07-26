# Changelog

All notable changes to **Substation** are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are cut **locally** with `make release` (CLAUDE.md: no cloud CI/CD); the
`## [Unreleased]` section is promoted to the new version at release time.

## [Unreleased]

### Added

- **Packaged content** — `detections/` and `scenarios/` ship in the wheel under
  `substation.content` (setuptools `build_py` hook); CLI/registry resolve via
  `importlib.resources`-compatible paths with checkout fallback.

### Changed

- Constitution docs (PRD / AGENTS / CLAUDE / checklist / CONTRIBUTING) synced to
  local-CI reality; orphan root `coverage/` artifacts removed.
- Sigma rule `status:` aligned to `stable` for validated Tier-1 rules (except M1,
  which lands with the range-modifier change).


### Added

- **CLI front door** — `substation --version`; `substation list` (registered
  detections + bundled scenarios); `substation validate` and `substation
  coverage` as first-class spellings of the `python -m` entrypoints;
  `demo --scenario` accepts multiple files; and `demo --strict` exits non-zero
  unless every scenario's `exercises` contract holds (a one-command smoke test
  for scenario edits).
- **Exact-hit Detection Contract net** — every validated Tier-1 fire case now
  pins the exact event indices its rule must hit
  (`tests/test_detection_contract.py::_EXPECTED_FIRE_HITS`), so a rule that
  over-matches but still passes fire/quiet is caught. Plus: Sigma rule `id:`
  UUIDs must be unique, and scenario names must be globally unique across
  protocol trees (they are artifact basenames).
- **Honeypot probe-log rotation** — the probe log rotates to `<log>.1` at
  `log_max_bytes` (default 50 MiB, `--log-max-bytes`, 0 disables), so a noisy
  scanner can no longer grow it unboundedly.

### Changed

- `make ci` invokes every tool as `$(PY) -m <tool>` so the gate always checks
  the interpreter the package is installed in (bare tool names could resolve
  to shims bound to a different Python and fail or vacuously pass);
  `make test` gained the same Python-version guard as the other stages;
  `types-PyYAML` is pinned in the dev extra so the strict YAML loaders
  type-check for real.
- Internal dedup, behavior-identical (artifacts verified byte-identical):
  one shared synthetic-TCP PCAP scaffold (`substation/emit/_tcp.py`), shared
  protocol helpers (`substation/protocols/_common.py`), one strict YAML loader
  (`substation/_yaml.py`).
- Sigma rules are parsed once per process and the demo loads the registry
  once per run instead of per scenario.
- `make coverage-build` writes a single output — the committed
  `docs/coverage/` snapshot — instead of also writing a scratch `coverage/`
  directory nothing consumed.
- The DNP3 X1 scenario is renamed `dnp3-anomalous-x1-new-function`, matching
  its tree's naming convention (file name unchanged).

### Fixed

- `scripts/render-demo-gif.py` probes per-platform font paths instead of
  hardcoding the Debian DejaVu location, and fails with an actionable hint.
- The scenario loader rejects a non-string `description` instead of silently
  stringifying it; piping CLI output into `head` exits quietly instead of
  dumping a traceback.

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

