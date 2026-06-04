# Substation — Launch-Readiness Report

**Date:** 2026-06-04 · **Scope:** full end-to-end validation (`make ci`, `make
security`, `make verify`, the VERIFY gates, and the headline `make demo` promise).

This is the single full-validation pass requested for launch. Every gate below was
run to green; the gaps found along the way are listed with how each was resolved,
and the genuinely-remaining (environment-bound) items are called out honestly
rather than papered over.

## Status at a glance

| Gate | Result |
|------|--------|
| `make ci` (format, lint, strict mypy, tests, schema, coverage, security) | **green** |
| `make security` (bandit, dep audit, secret scan, SBOM, files-only invariant) | **green** |
| `make verify` (Tier-2: real Zeek/ICSNPP fidelity + Zeek detections) | **green — 27 pass, 0 fail, 4 explicit skips** |
| `make demo` (clean clone, Python-only) | **green — quiet-on-benign + real hits + coverage map** |
| VERIFY gates (ATT&CK IDs, ICSNPP fields) | **closed** (live spot-checks + live-parser fidelity) |

The local gate is `make ci` (CLAUDE.md: no GitHub Actions, ever). Tier 2 is the
local Docker gate `make verify`.

## Gaps found and how each was resolved

1. **Strict type-check was broken in the canonical dev env.** `loader.py` carried a
   `# type: ignore[misc]` on `_StrictLoader(yaml.SafeLoader)` justified as "yaml is
   untyped". But `types-pyyaml` ships transitively via the pinned `pySigma`, so yaml
   *is* typed under mypy and the ignore always read as unused — failing `mypy`
   (`warn_unused_ignores`). **Resolved:** removed the stale ignore; `mypy` is clean.

2. **M2 (illegal/abnormal function code) never fired in Tier 1.** Its fire scenario
   used function code `0x09`, which the emitter could not encode, so the harness
   *skipped* the fire assertion. The VERIFY gate also bit: base Zeek names `0x09`
   the legacy **PROGRAM_484** — it is *defined*, not undefined. **Resolved:** the
   Modbus model now encodes genuinely-undefined request codes (Zeek renders them
   `unknown-N`, `action_class: other`) plus the `ILLEGAL_FUNCTION` exception a
   compliant outstation returns, in both JSON and PCAP. The scenario uses `0x42`
   (`unknown-66`). M2 now fires **and** stays quiet over real telemetry; registry
   status `partial → validated`.

3. **The security gate was a placeholder.** `make security` was `bandit + pip-audit`,
   and bare `pip-audit` scanned the ambient (dev-container) interpreter — noisy and
   non-deterministic. **Resolved:** `make security` now runs, and is wired into
   `make ci`:
   - **bandit** over the package;
   - **scoped dependency audit** (`scripts/security/audit_deps.py`) over the
     *declared, pinned* closure from `pyproject.toml`, with a small **documented**
     ignore-list (see below);
   - **secret scan** (`scripts/security/secret_scan.py`) — detect-secrets by
     default, gitleaks-via-Docker opt-in, builtin regex fallback;
   - **CycloneDX SBOM** (`scripts/security/sbom.py`, stdlib-only);
   - a codebase-wide **static no-raw-socket-send / files-only invariant** test
     (`tests/test_no_raw_socket_send.py`) that parses every `substation/**/*.py` and
     forbids outbound `connect`, raw/`AF_PACKET` sockets, and scapy transmit
     functions — the honeypot's passive accept/reply path is allowed.
   - Bumped `pytest 9.0.2 → 9.0.3` (CVE-2025-71176, in our declared set).

4. **`make verify` was a Phase-0 stub.** **Resolved:** `scripts/verify/run.py` is a
   real Dockerized Tier-2 gate:
   - **Fidelity golden test** — every Modbus/DNP3 PCAP is parsed by **real Zeek +
     the real, pinned ICSNPP script analyzers**, and the decoded per-request
     semantics are diffed against our emitted `.jsonl`. All Modbus + DNP3 scenarios
     match.
   - **Zeek detections in their real engine** — M3, D4 and X1 are executed by real
     Zeek over their fire/quiet scenarios and assert the same behavior as Tier 1.
     X1's learned baseline is derived from the benign scenarios and injected via
     `redef`, exactly as its doc describes.

5. **A real DNP3 fidelity bug, caught by the new golden test.** The "with-flag"
   object variations (g30v2/g30v1/g20v2) carry a leading flag octet, so their
   per-point widths are 3/5/3 bytes — but `OBJECT_TYPES` used 2/4/2. Real Zeek's
   binpac raised `out_of_bound: AnalogInput16wFlag`, **disabled the DNP3 analyzer
   mid-stream**, and dropped every later frame (e.g. the benign `OPERATE`).
   **Resolved:** corrected the widths; all frames now parse and fidelity passes.

6. **The demo did not deliver the headline.** `make demo` ran a single *benign* poll
   showing "0 hits" and a "Phase-0 placeholder" coverage box. **Resolved:** the demo
   now runs a benign baseline (stays quiet) **and** anomalous M1/M2 scenarios (fire
   real detections) in one command, then renders the **real, registry-driven**
   ATT&CK-for-ICS coverage map (every detection, verified technique + tactic,
   fired/quiet this run).

7. **The "Python-only" promise was overstated.** The README said the Tier-1 path
   needs "only Python 3.11+", but it requires a `pip install` of pure-Python wheels
   (scapy, pySigma, PyYAML). **Resolved:** corrected to "Python 3.11+ and a one-line
   `pip install` of pure-Python wheels — no Zeek, Suricata, Docker, or hardware",
   and **validated in a fresh venv**: `pip install -e .` then `make demo` →
   quiet-on-benign + real hits + coverage map, exit 0.

## VERIFY gates — closed

- **ICSNPP field names / detail shapes.** Closed *live*, not from memory: the Tier-2
  fidelity test parses our PCAPs with the **current, pinned** ICSNPP Modbus
  (`64559be1`) and DNP3 (`6e997bfc`) parsers and confirms the decoded
  `(src, dst, function, unit/tid, address/quantity)` semantics match our
  schema-aligned `.jsonl`. The DNP3 object-width fix (gap #5) was a direct product
  of this gate.
- **ATT&CK-for-ICS technique IDs.** The registry was verified 2026-06-04; the
  restructured/unusual claims were re-confirmed against the **live matrix**:
  `T0855 → T1692.001` *Unauthorized Message: Command Message* (Impair Process
  Control, TA0106); `T1691.002` *Block Operational Technology Message: Reporting
  Message* (Inhibit Response Function, TA0107); `T0888` *Remote System Information
  Discovery* (Discovery, TA0102) — all current with the mapped tactics. The
  remaining mappings (T0846, T0816, T0814, T0878, T0836, T0858, T0843) are standard
  current ICS technique IDs.

## Remaining gaps (honest)

- **Siemens S7 in Tier 2 (S3, X1's S7 path, S7 fidelity).** These require the ICSNPP
  **`icsnpp-s7comm`** analyzer, which is a *compiled C++ Zeek plugin*. The runtime
  `zeek/zeek` image ships no build toolchain (no cmake/g++), so `make verify`
  **skips these with an explicit, loud reason** — never a silent pass. Modbus/DNP3
  fidelity and the M3/D4/X1 Zeek detections are fully validated. To enable the S7
  path: run `make verify` against a Zeek image that has the build toolchain and the
  `icsnpp-s7comm` plugin built (or a `zeek/zeek-dev` base). The S3 contract linkage
  (rule + doc + fire/quiet scenarios + verified ATT&CK mapping) is enforced today by
  the Tier-1 harness; only its *real-engine execution* is gated on the plugin.
- **Suricata.** The repo ships **no Suricata rules** (`detections/suricata/` is
  empty; Suricata is optional per PRD §6.5). The Tier-2 runner reports "nothing to
  execute" rather than inventing a rule.
- **`Jinja2` is pinned but unused.** The coverage builder hand-rolls its
  markdown/JSON, so `Jinja2` is currently dead weight (left pinned to respect the
  locked Phase-0 dependency list; a candidate for removal to shrink the install).
- **Environment constraints (not product gaps).** Docker Hub enforces
  unauthenticated pull-rate limits, and the in-container TLS path to GitHub is
  proxy-intercepted (so `zkg` cannot clone inside the container). The verify runner
  works around the latter by fetching the pinned ICSNPP script packages on the host
  and mounting them; the S7 C++ build is the only thing it cannot complete here.

## Reproducing the validation

```sh
make dev        # editable install + pinned dev tooling (pure-Python)
make ci         # format, lint, strict mypy, tests, schema, coverage, security
make verify     # Tier-2: real Zeek/ICSNPP fidelity + Zeek detections (needs Docker)
make demo       # the headline: quiet-on-benign + real hits + coverage map
```
