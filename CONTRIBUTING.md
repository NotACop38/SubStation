# Contributing to Substation

Thanks for helping extend Substation — a defensive, **files-only** ICS detection
pack (Modbus / DNP3 / S7) mapped to ATT&CK for ICS, shipped with a simulator so
detections are validated without real OT hardware. Read [`AGENTS.md`](AGENTS.md)
(the ground rules) and [`docs/design.md`](docs/design.md) (scope, architecture and
decisions) before non-trivial work. Report vulnerabilities privately as described
in [`SECURITY.md`](SECURITY.md), not in a public issue.

## Ground rules (non-negotiable)

- **Defensive-only.** We model the *network signature* of malicious behaviour for
  detection. **No** exploit code, weaponization, or payloads against real
  equipment. PRs that add offensive tooling will be declined.
- **Files-only simulator.** The simulator writes PCAP/JSON and **never** opens a
  socket, transmits on an interface or starts a process that could. This is
  guarded at runtime (`substation/emit/guard.py`) and statically
  (`tests/test_no_raw_socket_send.py`). Don't weaken either.
- **No cloud CI, ever.** There is **no GitHub Actions / `.github/workflows/`**.
  CI is local: `make ci` is the gate, run by the pre-push hook (`make hooks`).
- **VERIFY gates — never invent from memory.** ATT&CK-for-ICS **technique IDs**
  and **ICSNPP/Zeek field names** are verified against the live matrix or the
  pinned parser source, with the source and date recorded.

## Getting set up

```bash
python3 -m venv .venv   # Python 3.11+; the Makefile uses .venv automatically
make dev                # hash-locked install of the package and dev tooling
make hooks              # pre-push hook: runs `make ci` on the commit you push
make demo               # Tier-1 one-command demo (generate -> detect -> report)
make ci                 # the full local gate
```

| Target | What it does |
|---|---|
| `make ci` | Format check, lint, strict type check, tests (including the Detection Contract harness), schema, coverage drift check and `make security`. |
| `make verify VERIFY_ARGS=--require-complete` | Tier 2: compares every PCAP with real Zeek/ICSNPP parsers and runs the Zeek rules over their scenarios. Needs Docker, or `--native` with local Zeek. See [`docs/tier2.md`](docs/tier2.md). |
| `make coverage-build` | Regenerates `docs/coverage/` (table, JSON, Navigator layer, SVG) from the registry. |
| `make security` | Bandit, audit of the locked dependency closure, secret scan, SBOM. |

The pre-push hook refuses to push a ref that is not the checked-out commit, or
from a working tree with uncommitted or untracked changes, because `make ci`
tests the working tree.

## What you can contribute

- **A new detection** for an existing protocol → follow the ordered checklist in
  [`docs/adding-a-detection.md`](docs/adding-a-detection.md).
- **A new protocol** → follow [`docs/adding-a-protocol.md`](docs/adding-a-protocol.md),
  after agreeing scope in an issue (`docs/design.md` §2, §10).
- **Scenarios, docs, coverage polish, bug fixes** → welcome; keep the gates green.

The highest-value work is the open qualification in `docs/design.md` §10:
independent benign captures, boundary cases and sensor normalization. Passing
synthetic scenarios is not a production false-positive or recall estimate; see
[`docs/validation.md`](docs/validation.md) for what is and is not established.

## The Detection Contract

A detection is **done** only when it has all of (`docs/design.md` §6.6):

1. The authored rule (Sigma / Zeek / Suricata) under `detections/`.
2. ≥1 **anomalous** scenario it must fire on.
3. ≥1 **benign** scenario it must stay quiet on.
4. A passing **fire-on-anomaly** test.
5. A passing **quiet-on-benign** test.
6. A **verified** ATT&CK-for-ICS mapping (technique ID + tactic).
7. A **doc**: engine choice + rationale, data source, and a **false-positive
   profile**.
8. A **registry entry** in `detections/registry.yaml`, from which the coverage map
   is generated.

The harness (`tests/test_detection_contract.py`) is metadata-driven: a registry
entry, rule and scenarios are discovered with no test-code changes, apart from
pinning a Tier-1 rule's exact hit indices. Tier-2 (Zeek) fire/quiet runs in real
Zeek under `make verify`; the contract linkage is still enforced in Tier 1.

## Engine policy (`docs/design.md` §6.5)

- **Sigma (Tier 1)** for single-event field matches over the JSON envelope (default).
- **Zeek (Tier 2)** only when real state is required (diversity sweeps, learned
  baselines, cross-protocol logic).
- **Suricata** only for an optional packet-level signature.

State the engine **and why** in the detection's doc.

## Commits & PRs

- Keep commits focused, with messages that say what changed and why. Run focused
  checks while editing and the full gates at the end of a batch.
- Open the PR **ready for review** and fill in the PR template; it itemizes every
  Detection Contract element, and PRs are reviewed against it.
- Don't commit generated telemetry (`artifacts/`, `*.pcap`, `*.jsonl`, except the
  fixtures under `tests/data/`). The coverage snapshot under `docs/coverage/`
  **is** committed; regenerate it with `make coverage-build`.
