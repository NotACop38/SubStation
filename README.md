# ![Substation](docs/assets/hero.svg)

**Test ICS detection rules without a PLC lab.**

Substation pairs experimental Sigma and Zeek rules with benign and anomalous
scenarios for **Modbus, DNP3 and Siemens S7**. Each scenario produces a packet
capture and a JSON event log, so you can inspect the traffic, see why a rule
fired, and test what happens when you change the scenario or policy.

The simulator only writes files. The default demo runs offline after installation,
using Python packages; it needs no hardware, Docker or sensor engine.

[Quick start](#quick-start) · [Detections](#detection-examples) ·
[Validation](#validation-and-limits) · [Contributing](CONTRIBUTING.md)

## Quick start

Use **Python 3.11+** on Linux or macOS. The first installation downloads packages.

```sh
git clone https://github.com/NotACop38/SubStation.git substation
cd substation
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
substation demo
```

Expect a quiet Modbus baseline and alerts from M1, M2 and D1. Excerpt from the
default run:

```text
[benign   ] benign-baseline                    18 events -> quiet (no hits)
[anomalous] anomalous-m1-unauthorized-write    10 events -> FIRED 2 hit(s) -> M1
[anomalous] anomalous-m2-illegal-function       4 events -> FIRED 2 hit(s) -> M2
[anomalous] dnp3-anomalous-d1-restart           7 events -> FIRED 1 hit(s) -> D1
```

The demo writes `.pcap` and `.jsonl` files to `./artifacts/` and prints an
ATT&CK-for-ICS mapping table. Applicable Zeek rules are marked **not-run** because
they need the separate Tier-2 checks. The default demo exercises Modbus and DNP3;
S7 scenarios are also [included](scenarios/s7).

Inspect the unauthorized-write example:

```sh
substation validate artifacts/anomalous-m1-unauthorized-write.jsonl
substation detect artifacts/anomalous-m1-unauthorized-write.jsonl --detection M1
```

Open the matching PCAP in a packet analyzer to compare the bytes with the events.
`detect` accepts [Substation-schema JSONL](docs/schema.md) and prints one JSON
object per hit, including a zero-based `event_index` into the input log.

## How it works

One scenario model feeds two emitters. The default path evaluates Sigma rules
over JSON. A separate Zeek run checks the packet encoding and the rules that
need state, such as function sweeps and baseline changes.

<picture>
  <source media="(max-width: 600px)" srcset="docs/assets/pipeline-mobile.svg">
  <img src="docs/assets/pipeline.svg" alt="One YAML scenario model emits JSONL for Tier 1 Sigma tests and PCAP for Tier 2 Zeek/ICSNPP field checks and stateful rules." width="800">
</picture>

**Tier 1 — Python.** The local evaluator runs seven Sigma rules over validated
JSON and checks the scenarios' expected fire/quiet results. This is what
`substation demo` runs. Rules and scenarios are included in the wheel, so the
installed CLI also works outside a checkout.

**Tier 2 — Zeek/ICSNPP.** `make verify` checks modeled protocol fields against
independent parsers and runs four stateful Zeek rules. It uses Docker by default
or an explicitly selected native Zeek installation. S7 needs a compiled,
patched plugin; follow the [setup guide](docs/verify-s7.md).

## Detection examples

The eleven examples below include a rule, benign and anomalous scenarios, engine
rationale, and a description of likely false positives. Follow a rule ID for its
assumptions and examples.

| Rule | Matches | Engine |
|---|---|---|
| [M1](detections/docs/M1-unauthorized-write.md) | Modbus writes outside permitted channels or spans | Sigma |
| [M2](detections/docs/M2-illegal-function-code.md) | Undefined Modbus functions or illegal-function/address errors | Sigma |
| [M3](detections/docs/M3-unit-function-sweep.md) | Modbus function-code or unit-ID sweeps | Zeek |
| [D1](detections/docs/D1-unauthorized-restart.md) | DNP3 restart outside approved channels | Sigma |
| [D2](detections/docs/D2-disable-unsolicited.md) | Disabling DNP3 unsolicited reporting outside policy | Sigma |
| [D3](detections/docs/D3-unauthorized-operate.md) | DNP3 control outside approved channels | Sigma |
| [D4](detections/docs/D4-function-enumeration.md) | DNP3 function enumeration | Zeek |
| [S1](detections/docs/S1-cpu-stop-start.md) | S7 CPU stop/start outside approved channels | Sigma |
| [S2](detections/docs/S2-program-write-download.md) | S7 program downloads or object writes outside policy | Sigma |
| [S3](detections/docs/S3-enumeration.md) | S7 module-information enumeration | Zeek |
| [X1](detections/docs/X1-cross-protocol-baseline.md) | New talker, asset pair or function across protocols | Zeek |

The [generated catalog](docs/coverage/coverage.md) contains the ATT&CK-for-ICS
mappings and tactic gaps. It shares a registry with the
[Navigator layer](docs/coverage/navigator-layer.json) and
[JSON report](docs/coverage/coverage.json). These mappings describe the content;
they do not measure protection against an entire technique.

## Use your own policy or telemetry

The bundled permissions are examples. Adapt the source, destination and service
allowlists to your environment; Modbus write permissions also cover the unit,
address space and complete write span. IP-based permissions cannot distinguish
a legitimate operator from a compromised approved host. X1 reports novelty
relative to a reviewed baseline; a new asset or function can be legitimate.

- **Site permissions:** write a versioned policy, use it with `detect --policy`,
  or export the resulting Sigma rules with `substation policy compile`.
- **Modbus sensor logs:** `substation import-modbus` accepts supported, matched
  ICSNPP transactions in JSON or TSV and records their origin in the output.
- **Scenario edits:** pass edited YAML files to `substation demo --scenario` and
  add `--strict` to fail on a violated Tier-1 fire/quiet expectation.

Start with the [policy and import guide](docs/independent-validation.md) or the
[scenario format](docs/scenario-format.md). General DNP3/S7 sensor import remains
unqualified.

## Validation and limits

Substation is an **offline regression and teaching toolkit**. Passing a scenario
establishes how a rule behaves on that fixture. Production recall, false-positive
rates and alert volume still need representative, independently labeled traffic.
The rules remain experimental.

Independent checks cover core Modbus transactions, DNP3 message/object fields,
and modeled S7 request/response details. The repository also includes a small,
attributed [external Modbus corpus](tests/data/corpus/modbus). The simulator does
not model a PLC process, complete device sessions or encrypted S7 traffic.

SIEM deployment needs its own validation. The
[SQLite backend comparison](docs/spikes/10-sigma-backend-qualification.md) agrees
on the scoped fixtures but exposes missing-field and large-policy limits.
The [current validation record](docs/reviews/2026-09-10-validation-closeout.md)
lists the tested versions, results and remaining gaps, including Docker S7
qualification.

## Development

With the virtual environment active:

```sh
make dev       # install hash-locked development dependencies
make hooks     # install the pre-push gate
make ci        # formatting, lint, types, tests, schema, coverage and security
```

CI runs locally. The pre-push hook runs `make ci`; there are no GitHub Actions or
cloud CI jobs. `make corpus` checks the external Modbus fixtures;
`make verify-sigma` runs the SQLite comparison.

For Tier 2, complete the [Zeek/S7 setup](docs/verify-s7.md), then run:

```sh
make verify VERIFY_ARGS=--require-complete
```

This fails if a required check cannot run. The stock Docker image lacks the S7
plugin. Native Zeek is supported with `VERIFY_ARGS='--native --require-complete'`.

See [Contributing](CONTRIBUTING.md) for the detection contract and
[Makefile](Makefile) for all commands, including local release builds.

## Safety

The simulator writes PCAP and JSON files and never transmits on a live interface.
Socket guards and tests enforce that boundary. Fixtures model observable protocol
signatures; they contain no exploit payloads or operational PLC programs. Keep
captures for offline analysis and do not replay them toward real OT equipment.

The optional [Modbus honeypot](substation/honeypot/README.md) is a separate passive
listener, outside the simulator and demo. It binds loopback by default; external
binding requires explicit opt-ins and network isolation.

## Reference

- [Event schema](docs/schema.md) · [Scenario format](docs/scenario-format.md)
- [Add a detection](docs/adding-a-detection.md) · [Add a protocol](docs/adding-a-protocol.md)
- [PRD](PRD.md) · [Engineering checklist](ENGINEERING_CHECKLIST.md) · [Agent instructions](AGENTS.md)

[MIT license](LICENSE). Built with [Sigma](https://sigmahq.io/),
[Zeek/ICSNPP](https://github.com/cisagov/icsnpp), [Scapy](https://scapy.net/) and
[MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/).
