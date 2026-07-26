# Contributing to Substation

Thanks for helping extend Substation — a defensive, **files-only** ICS detection
pack (Modbus / DNP3 / S7) mapped to ATT&CK for ICS, shipped with a simulator so
detections are validated without real OT hardware. Read `CLAUDE.md` (the project
constitution), `PRD.md` and `ENGINEERING_CHECKLIST.md` (the source of truth)
before non-trivial work.

## Ground rules (non-negotiable — `CLAUDE.md`)

- **Defensive-only.** We model the *network signature* of malicious behaviour for
  detection. **No** exploit code, weaponization, or payloads against real
  equipment. PRs that add offensive tooling will be declined.
- **Files-only simulator.** The simulator writes PCAP/JSON and **never** opens a
  sending socket or transmits on a live interface. This is guarded in code
  (`substation/emit/guard.py`) and asserted in tests (`tests/test_files_only.py`).
  Don't weaken it.
- **No cloud CI, ever.** There is **no GitHub Actions / `.github/workflows/`**.
  CI is local: `make ci` is the gate, run by the git pre-push hook (`make hooks`).
- **VERIFY gates — never invent from memory.** ATT&CK-for-ICS **technique IDs**
  and **ICSNPP field names** must be verified against the live matrix / current
  parsers, with the source + date recorded. Tactics are treated as stable.

## Getting set up

```bash
make dev        # editable install with pinned dev tooling (Python 3.11+)
make hooks      # install the pre-push hook that runs `make ci`
make ci         # the full local gate: format-check, lint, type, tests, schema, coverage
make demo       # Tier-1 one-command demo (generate -> detect -> report)
```

Canonical targets: `make ci` (the gate), `make coverage-build` (regenerate the
coverage map + Navigator layer from the registry), `make security` (bandit over
the package + scripts, scoped dependency audit, secret scan, CycloneDX SBOM, and
the files-only / no-raw-socket-send invariant), `make verify` (Tier-2 fidelity
and Zeek/Suricata validation; Docker).

## What you can contribute

- **A new detection** for an existing protocol → follow the ordered checklist in
  [`docs/adding-a-detection.md`](docs/adding-a-detection.md).
- **A new protocol** (post-v1) → follow [`docs/adding-a-protocol.md`](docs/adding-a-protocol.md).
  Confirm scope with the maintainers first (`PRD.md` §2).
- **Scenarios, docs, coverage polish, bug fixes** → welcome; keep the gate green.

Both checklists are the operational form of the **Detection Contract** below.

## The Detection Contract (every detection must satisfy all of)

A detection is **done** only when it has all of (`PRD.md` §6.6 /
`ENGINEERING_CHECKLIST.md`):

1. The authored rule (Sigma / Zeek / Suricata) under `detections/`.
2. ≥1 **anomalous** scenario it must fire on.
3. ≥1 **benign** scenario it must stay quiet on.
4. A passing **fire-on-anomaly** test.
5. A passing **quiet-on-benign** test.
6. A **verified** ATT&CK-for-ICS mapping (technique ID + tactic).
7. A **doc**: engine choice + rationale, data source, and a **false-positive
   profile**.
8. A **coverage-map entry** (the `detections/registry.yaml` row everything is
   generated from).

The harness (`tests/test_detection_contract.py`) is fully metadata-driven: add a
registry entry + rule + scenarios and your detection is auto-discovered with no
test-code changes. Tier-2 (Zeek/Suricata) fire/quiet runs in the Tier-2 runner;
contract linkage is still enforced.

## Engine policy (pick the simplest that's correct — `PRD.md` §6.5)

- **Sigma (Tier 1)** for stateless field matches over the JSON envelope (default).
- **Zeek (Tier 2)** only when real state is required (learned baselines, set
  membership, cross-protocol logic — e.g. X1).
- **Suricata** only for an optional packet-level signature.

State the engine **and why** in the detection's doc.

## Commits & PRs

- Keep commits focused with descriptive messages; build per step (don't run
  `make ci`/`make verify` after every edit — they are the end-of-batch gate).
- Run `make ci` before pushing (the pre-push hook does this for you).
- Open the PR **ready for review** and fill in the PR template — it itemizes every
  Detection Contract element. PRs are reviewed against that contract.
- Don't commit generated telemetry (`artifacts/`, `*.pcap`, `*.jsonl` — except the
  golden fixtures under `tests/data/`). The coverage snapshot under `docs/coverage/`
  **is** committed; regenerate it with `make coverage-build`.
