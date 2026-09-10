<div align="center">
<img src="docs/assets/hero.svg" alt="Substation: offline ICS detection development for Modbus, DNP3 and S7" width="100%">

**Generate synthetic ICS traffic. Test detection behavior. Inspect the evidence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-3fb950)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB)](pyproject.toml)
[![CI: local](https://img.shields.io/badge/CI-local-8957e5)](AGENTS.md)
[![Simulator: files only](https://img.shields.io/badge/Simulator-files%20only-0aa2aa)](#safety)
</div>

## Why this exists

Substation is an **offline detection regression and teaching toolkit** for Modbus,
DNP3 and Siemens S7. It pairs experimental Sigma/Zeek rules with readable benign
and anomalous scenarios. Generate PCAP and normalized JSON, inspect why a rule
fired, and preserve that behavior in a repeatable test without PLC hardware.

The useful result is a reproducible example with an explicit policy and expected
outcome. Synthetic tests do **not** establish production recall, false-positive
rates, device realism or detection of an entire ATT&CK technique. All rules need
site-specific policy and independent validation before operational use. The
[project review](docs/reviews/2026-09-09-codebase-review.md) explains the evidence
and remaining limits.

## Quick start

Use Python 3.11+ in a virtual environment. Installation downloads Python packages;
the demo itself needs no Docker, sensor engine or network connection.

```sh
git clone https://github.com/notacop38/substation.git
cd substation
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
substation demo
```

The default demo runs a benign Modbus baseline and Modbus/DNP3 anomalies. It checks
their Tier-1 contracts and labels applicable Zeek detections **not-run**. Artifacts
are written to `./artifacts/`. The wheel also includes rules and scenarios, so the
installed CLI works outside a checkout.

<img src="docs/assets/demo.gif" alt="Current demo output with synthetic fire and quiet results and explicit Tier-2 not-run labels" width="900">

<details>
<summary>Demo output</summary>

```text
substation demo · Tier-1 loop: generate -> detect -> report (pure Python)

[benign   ] benign-baseline                    18 events -> quiet (no hits)
[anomalous] anomalous-m1-unauthorized-write    10 events -> FIRED 2 hit(s) -> M1
[anomalous] anomalous-m2-illegal-function       4 events -> FIRED 2 hit(s) -> M2
[anomalous] dnp3-anomalous-d1-restart           7 events -> FIRED 1 hit(s) -> D1

ATT&CK-for-ICS coverage map
============================================================
  ID   Technique   Tactic                     This run
  ----------------------------------------------------------
  M1   T1692.001   Impair Process Control     ● FIRED
  M2   T0888       Discovery                  ● FIRED
  M3   T0846       Discovery                  ◇ not-run
  D1   T0816       Inhibit Response Function  ● FIRED
  D2   T1691.002   Inhibit Response Function  ○ quiet
  D3   T1692.001   Impair Process Control     ○ quiet
  D4   T0888       Discovery                   ·
  S1   T0858       Execution                   ·
  S2   T0843       Lateral Movement            ·
  S3   T0888       Discovery                   ·
  X1   T0846       Discovery                  ◇ not-run
============================================================
11 detections · 10 ATT&CK techniques · 5 tactics · 3 fired this run

Result: quiet on the benign baseline; fired 3 detection(s) on the anomalies (D1, M1, M2).
```

</details>

```sh
substation list
substation demo --scenario mine-benign.yaml mine-anomaly.yaml --strict
substation validate artifacts/benign-baseline.jsonl
substation detect artifacts/anomalous-m1-unauthorized-write.jsonl --detection M1
substation coverage --out ./coverage
```

`detect` accepts **Substation-schema JSONL**, validates every record, and prints
one JSON object per hit with `event_file`, `detection_id` and a zero-based
`event_index`. Its summary goes to stderr. Invalid input fails before any hit
output is published. It runs only Tier-1 rules. `import-modbus` normalizes supported
ICSNPP Modbus transactions; `detect --policy site.yaml` selects reviewed site
permissions. An empty valid log reports zero hits. See the
[import, policy and corpus guide](docs/independent-validation.md).

## How it works

<img src="docs/assets/pipeline.svg" alt="One scenario model feeds PCAP and JSON emitters; Sigma uses JSON and Zeek uses PCAP" width="100%">

One scenario model feeds both emitters. That reduces duplicated scenario logic;
independent parser checks are still needed because wire encoding can disagree
with the JSON model.

| Path | What it checks | Requirements |
|---|---|---|
| Tier 1 | Seven Sigma rules over validated JSON; synthetic contracts and a small external Modbus corpus | Python, scapy, pySigma, PyYAML and their dependencies |
| Tier 2 | Core Modbus fields, responses and external captures; DNP3/S7 request counts; four stateful Zeek rules | Docker by default, or explicit native Zeek; S7 requires its compiled plugin |

Tier 2 does not compare every detail field, response, timing edge or device
interaction. No Suricata rules are shipped. The simulator produces bounded
protocol fixtures, not a process emulator or encrypted S7 session implementation.
See [Tier-2 setup and limits](docs/verify-s7.md).

## Detection content and ATT&CK mappings

Eleven examples map to ten ATT&CK-for-ICS techniques across five of twelve tactics.
The identifiers and tactic relationships were rechecked against MITRE's published
ICS dataset on 2026-09-09. Mapping counts describe the catalogue; they are not a
measure of protection or tactic-wide coverage.

| Detection | Title | Protocol | Technique(s) | Tactic | Engine | Tier | Status |
|---|---|---|---|---|---|---|---|
| M1 | Unauthorized register/coil write | modbus | T1692.001, T0836 | Impair Process Control (TA0106) | sigma | 1 | synthetic tests |
| M2 | Illegal / abnormal function code | modbus | T0888 | Discovery (TA0102) | sigma | 1 | synthetic tests |
| M3 | Function-code / unit-ID sweep | modbus | T0846, T0888 | Discovery (TA0102) | zeek | 2 | requires Zeek |
| D1 | Cold/warm restart from unexpected source | dnp3 | T0816, T0814 | Inhibit Response Function (TA0107) | sigma | 1 | synthetic tests |
| D2 | Disable unsolicited responses | dnp3 | T1691.002, T0878 | Inhibit Response Function (TA0107) | sigma | 1 | synthetic tests |
| D3 | Unauthorized control (operate/direct-operate) | dnp3 | T1692.001 | Impair Process Control (TA0106) | sigma | 1 | synthetic tests |
| D4 | Function-code enumeration / scanning | dnp3 | T0888, T0846 | Discovery (TA0102) | zeek | 2 | requires Zeek |
| S1 | CPU stop/start from unexpected source | s7comm | T0858 | Execution (TA0104) | sigma | 1 | synthetic tests |
| S2 | Program / data-block write or download | s7comm | T0843 | Lateral Movement (TA0109) | sigma | 1 | synthetic tests |
| S3 | Enumeration / module-info reads | s7comm | T0888, T0846 | Discovery (TA0102) | zeek | 2 | requires Zeek |
| X1 | Cross-protocol baseline deviation (new talker / asset pair / function) | cross | T0846 | Discovery (TA0102) | zeek | 2 | requires Zeek |

The Sigma files are `experimental`. Registry `validated` denotes the synthetic
Tier-1 contract; `tier2` denotes the engine needed to execute a rule. The
[generated table](docs/coverage/coverage.md), [JSON](docs/coverage/coverage.json)
and [Navigator layer](docs/coverage/navigator-layer.json) share one registry.
`make coverage-build` updates them; `make ci` fails on drift without rewriting them.

Example allowlists are scoped to a source, destination and service. M1 additionally
checks the unit, register address space and complete write span. These IP-based
policies cannot identify a compromised approved host. X1 detects novelty relative
to reviewed baseline sets; novelty alone does not establish hostile intent, and
traffic after training never silently expands trust.

## Development and verification

With the virtual environment active:

```sh
make dev                 # install hash-locked dependencies and the package
make hooks               # install the local pre-push gate
make ci                  # formatting, lint, types, tests, schema, coverage and security
make corpus              # attributed Modbus regression metrics
make verify VERIFY_ARGS=--require-complete
```

`make verify` defaults to a pinned Docker image. To use an installed Zeek and S7
plugin, pass `VERIFY_ARGS='--native --require-complete'`. Missing required checks
then fail. The [review](docs/reviews/2026-09-09-codebase-review.md) records the tested
engine versions; native results do not qualify the pinned Docker image.

CI/CD is **local and Codex-driven**. There is no GitHub Actions or cloud CI.
`make release` builds and tags locally after its gates; it never pushes. An existing
tag can be rebuilt only from its clean matching checkout. The secret gate scans
current source, including new non-ignored files; release additionally scans the
exact Git index. Neither is a Git-history audit. Installation requires locked
artifact hashes; the offline SBOM includes transitive runtime/dev relationships
for its recorded environment. `make lock` explicitly refreshes dependency evidence.
The documented unused diskcache advisory remains accepted.

`make demo-gif` captures the current CLI and renders the GIF and SVG with Pillow.
It fails if the demo fails; it does not maintain a separate set of example results.
Rendering varies with the installed font. The editable sources remain in
`detections/` and `scenarios/`; packaging copies supported content into the wheel.

## Safety

- **Files-only simulator:** writes PCAP/JSON and never transmits on a live interface.
  Runtime socket guards and static/dynamic tests enforce that boundary.
- **Defensive fixtures:** model observable protocol signatures; no exploit payloads
  or operational PLC programs. Use captures for offline analysis; do not replay
  them toward real OT equipment.
- **Optional honeypot:** a separate passive Modbus listener, outside the demo and
  simulator. It binds loopback by default. External binding requires explicit
  opt-ins and must be network-isolated. See its [README](substation/honeypot/README.md).

## Project documents

- [PRD](PRD.md) and [engineering checklist](ENGINEERING_CHECKLIST.md): scope and decisions.
- [AGENTS.md](AGENTS.md): local execution rules and safety invariants.
- [Current project review](docs/reviews/2026-09-09-codebase-review.md): defects, decisions and verification.
- [Event schema](docs/schema.md) and [scenario format](docs/scenario-format.md): data contracts.
- [Contributing](CONTRIBUTING.md): adding or improving content.

[MIT license](LICENSE). Built with [Sigma](https://sigmahq.io/),
[Zeek/ICSNPP](https://github.com/cisagov/icsnpp), [scapy](https://scapy.net/) and
[MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/).
