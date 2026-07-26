# AGENTS.md — Substation constitution

**One-liner:** A defensive detection-content pack for ICS protocols (Modbus,
DNP3, Siemens S7) mapped to MITRE ATT&CK for ICS, shipped with a files-only
protocol traffic simulator so detections can be validated without real OT
hardware.

`PRD.md` and `ENGINEERING_CHECKLIST.md` are the source of truth. Read them before
non-trivial work.

## The 5 LOCKED decisions (PRD §7 — reversible by editing the PRD)

1. **Schema:** ICSNPP-aligned per-protocol detail + a normalized envelope; events
   are newline-delimited JSON (`.jsonl`).
2. **Simulator:** one scenario model → dual emit (PCAP + JSON); pure Python;
   **files-only**; optional Tier-2 Zeek fidelity check.
3. **Engine policy:** Sigma-first; Zeek when real state is needed; Suricata
   optional; every detection documents its engine choice + rationale.
4. **Two-tier execution:** Tier 1 (zero-dep Sigma-over-JSON) is the headline path;
   Tier 2 (containerized Zeek/Suricata) validates the rest.
5. **Build order:** Modbus end-to-end → harden + CI → DNP3 → S7 → coverage polish
   + contributor guides + optional honeypot.

## Safety invariants (non-negotiable)

- **Files-only simulator:** it writes PCAP/JSON and **never** opens a sending
  socket or transmits on a live interface. Guard this in code and tests.
- **Defensive-only:** model the *network signature* of malicious behavior for
  detection; no exploit code, weaponization, or payloads against real equipment.
- **Honeypot (if ever built) is passive and isolated:** opt-in, network-isolated,
  research-only, last priority.

## VERIFY gates — never invent from memory

- ATT&CK-for-ICS **technique IDs**: verify against the live matrix per detection.
- **ICSNPP field names / detail shapes**: verify against current parsers before
  freezing a protocol's schema.
- scapy capability and the Sigma offline-eval mechanism: spike and record.

## CI/CD is LOCAL and Codex-driven — NO cloud CI

There is **no GitHub Actions and no `.github/workflows/`**, ever. `make ci` is the
gate; the git pre-push hook (`make hooks`) runs it before every push. (This
overrides the GitHub-Actions references in PRD §6.9 / checklist Phase 2.)

## Canonical commands

- `make ci` — format-check, lint, type-check, unit tests, detection harness,
  schema, coverage-build/check, and `make security`. The gate.
- `make demo` — Tier-1 one-command demo (generate → detect → coverage map).
- `make verify` — Tier-2 fidelity + Zeek/Suricata validation (Docker).
- `make release` — cut a local release (gate → build → artifacts → tag).
- `make hooks` — install the pre-push gate.
- `make security` — bandit, scoped dep audit, secret scan, SBOM, files-only.

## Validation cadence

Build and commit **per step**. Do **not** run `make ci` / `make verify` after every
change — they remain defined but are invoked as **one large validation at the end**
of a work batch, not continuously. There is no automated per-edit or per-stop CI
(see `.Codex/settings.json`: the heavy PostToolUse and Stop hooks are disabled).
Still **no GitHub Actions, ever.**
