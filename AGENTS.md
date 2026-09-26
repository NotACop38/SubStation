# AGENTS.md — Substation constitution

**One-liner:** A defensive detection-content pack for ICS protocols (Modbus,
DNP3, Siemens S7) mapped to MITRE ATT&CK for ICS, shipped with a files-only
protocol traffic simulator so detections can be validated without real OT
hardware.

[`docs/design.md`](docs/design.md) is the source of truth for scope, architecture
and decisions. Read it before non-trivial work; cite it as `docs/design.md §N`.

## The 5 LOCKED decisions (design §7 — reversible by editing the design)

1. **Schema:** ICSNPP-aligned per-protocol detail + a normalized envelope; events
   are newline-delimited JSON (`.jsonl`).
2. **Simulator:** one scenario model → dual emit (PCAP + JSON); pure Python;
   **files-only**.
3. **Engine policy:** Sigma first; Zeek when real state is needed; Suricata
   optional; every detection documents its engine choice and rationale.
4. **Two-tier execution:** Tier 1 (Python-only Sigma over JSON) is the first-run
   path; Tier 2 (Zeek/ICSNPP, Docker or native) validates the rest.
5. **Local CI:** `make ci` is the gate, run by the pre-push hook.

## Safety invariants (non-negotiable)

- **Files-only simulator:** it writes PCAP/JSON and **never** opens a sending
  socket, transmits on a live interface or starts a process that could. Guard this
  in code and tests (`substation/emit/guard.py`, `tests/test_files_only.py`,
  `tests/test_no_raw_socket_send.py`).
- **Defensive-only:** model the *network signature* of malicious behavior for
  detection; no exploit code, weaponization, or payloads against real equipment.
- **The honeypot is passive and isolated:** opt-in, loopback by default,
  research-only, outside the simulator and the demo.

## VERIFY gates — never invent from memory

- ATT&CK-for-ICS **technique IDs**: verify against the live matrix per detection
  and record the source and date in the detection doc.
- **ICSNPP/Zeek field names and event signatures**: verify against the pinned
  parser sources before a schema or rule depends on them.
- **Library capability** (Scapy layers, pySigma behavior): spike and record in
  `docs/spikes/`.

## CI/CD is LOCAL — NO cloud CI

There is **no GitHub Actions and no `.github/workflows/`**, ever. `make ci` is the
gate; the pre-push hook installed by `make hooks` runs it on the pushed commit.

## Canonical commands

- `make dev` — hash-locked install of the package and its dev tooling.
- `make ci` — format check, lint, strict type check, tests (including the
  Detection Contract harness), schema, coverage drift check, `make security`.
- `make demo` — Tier-1 one-command demo (generate → detect → coverage map).
- `make verify VERIFY_ARGS=--require-complete` — Tier 2: parser comparisons and
  Zeek rules in real Zeek (Docker; builds the S7 plugin image once).
- `make security` — bandit, locked-dependency audit, secret scan, SBOM.
- `make release RELEASE_ARGS="--version X.Y.Z"` — cut a local release.
- `make hooks` — install the pre-push gate with the current interpreter.

## Validation cadence

Build and commit **per step**. Run focused checks during edits, then `make ci`
and the applicable `make verify` checks at the end of the work batch. An explicit
request to run a gate runs it immediately, and the pre-push `make ci` gate is
always required. Still **no GitHub Actions, ever.**
