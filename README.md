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
make demo    # Tier-1 demo (stub for now)
make hooks   # install the pre-push hook that runs `make ci`
```
