# Substation

Substation is a **defensive** detection-content pack for industrial-protocol
attacks and anomalies — **Modbus, DNP3, and Siemens S7** — mapped to **MITRE
ATT&CK for ICS**, shipped with a **files-only protocol traffic simulator** that
produces benign and anomalous telemetry (PCAP + JSON) so detections can be
developed and validated **without real OT hardware**. The simulator only ever
writes files; it never transmits on a live network interface. This project is
defensive-only and is currently in early scaffolding (Phase 0) — see `PRD.md` and
`ENGINEERING_CHECKLIST.md` for the plan, and `CLAUDE.md` for the locked decisions
and safety invariants.

## Quick start (Phase 0 stub)

```sh
make dev     # install with pinned dev tooling
make ci      # the local gate: format-check, lint, type-check, tests
make demo    # Tier-1 loop end to end (Phase 0 no-op): load -> generate -> detect -> report
make hooks   # install the pre-push hook that runs `make ci`
```

`make demo` loads a scenario, writes (currently empty) PCAP/JSON artifacts under
`artifacts/`, runs (currently no) detections, and prints a placeholder coverage
map — proving the generate→detect→report pipeline is wired before any real logic
lands. Scenarios are human-editable YAML; the format is documented in
[`docs/scenario-format.md`](docs/scenario-format.md) with a fully commented
example at [`scenarios/modbus/benign-poll.yaml`](scenarios/modbus/benign-poll.yaml).
