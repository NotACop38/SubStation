# Substation full codebase review — 2026-06-09

> **Implementation status:** every finding below was fixed on this branch in
> the commits following this document — the P1 tooling fixes, the
> `emit/_tcp.py` / `protocols/_common.py` / `_yaml.py` deduplication, Sigma
> rule caching, the CLI growth (`--version`, multi-scenario + `--strict` demo,
> `list`/`validate`/`coverage`), protocol-prefixed scenario names, pinned
> contract hit counts, the Zeek syntax gate, honeypot log rotation, and the
> misc polish (including a latent secret-scan pragma bug found while fixing).
> The two "fine at current scale" notes (streaming JSONL I/O, in-memory PCAP
> assembly) were deliberately left as-is and documented.

Scope: every Python module in `substation/`, `scripts/`, and `tests/`; the
Makefile, `pyproject.toml`, `.claude/` tooling; all detection content
(`detections/`), scenarios, schema, and docs. Findings were verified empirically
in a fresh container: `python3 -m pytest` → **292 passed, 20 skipped in 3.2s**;
`make demo` → 0.54s, fires M1+M2, quiet on benign; schema, coverage drift check,
bandit, pip-audit, and secret scan all pass.

Overall verdict: the codebase is in excellent shape — strict validating loaders,
immutable scenario models, deterministic dual emitters gated by a frozen JSON
Schema, and the files-only safety invariant enforced at three independent layers
(runtime socket guard, static AST scan, runtime socket-construction test). The
findings below are ordered by priority.

---

## P1 — Bugs worth fixing before showcasing

### 1. `make ci` fails on a fresh environment (tool/interpreter mismatch)

The Makefile defines `PY ?= python3` but invokes `mypy`, `ruff`, `pytest`, and
`bandit` as **bare binaries** (`Makefile:37-66`). If those names resolve to
shims bound to a different interpreter (uv tools, pipx, a system package), the
gate checks the wrong environment. Reproduced in a clean container:

- `make ci` fails at the `type` stage with
  `Class cannot subclass "SafeLoader" (has type "Any")` in
  `substation/scenarios/loader.py:60` and `substation/detect/registry.py:71`,
  because the uv-tool mypy cannot see the project's packages;
- `python3 -m mypy` on the same tree passes cleanly.

**Fix:** invoke every tool through the configured interpreter — `$(PY) -m mypy`,
`$(PY) -m pytest`, `$(PY) -m ruff ...`, `$(PY) -m bandit ...` — so `make ci`
always tests the environment the package is installed in.

**Related hardening:** add `types-PyYAML` to the `dev` extra. Today `yaml` is
typed `Any` via the `ignore_missing_imports` override (`pyproject.toml:84`), so
the two `_StrictLoader` subclasses survive strict mode only by accident of which
mypy sees the stubs. With real stubs installed the override entry for `yaml`
can be dropped and the loaders become genuinely type-checked.

### 2. `scripts/security/audit_deps.py` leaks a temp file and exit codes

- `tempfile.NamedTemporaryFile(..., delete=False)` (`audit_deps.py:108`) is
  never unlinked on any path, so every `make security` run leaks a file in
  `$TMPDIR`. Wrap the audit in `try/finally: os.unlink(req_file)`.
- `return result.returncode` / `return fallback.returncode`
  (`audit_deps.py:158-161`) pass pip-audit's raw exit code through; an internal
  pip-audit error (exit ≥ 2) leaks out instead of being normalized to the
  script's documented 0/1 contract.

### 3. `scripts/render-demo-gif.py` hardcodes Linux font paths

`FONT_REG`/`FONT_BLD` point at `/usr/share/fonts/truetype/dejavu/...`
(`render-demo-gif.py:126-127`). `make demo-gif` therefore fails on macOS with an
opaque `OSError`. Probe a small list of candidate paths per platform (or use
`matplotlib`-style font discovery via `PIL.ImageFont.truetype` fallbacks) and
fail with an actionable message naming the missing font.

### 4. `make test` skips the `check-python` guard

`test:` (`Makefile:48`) is the only gate stage without the `check-python`
prerequisite, so `make test` on Python 3.9/3.10 produces confusing syntax
errors (`StrEnum`, `X | Y`) instead of the clear version message every other
target gives.

---

## P2 — Architecture and efficiency improvements

### 5. `_TcpFlow` is triplicated across the three PCAP emitters

`pcap_emitter.py:198-270`, `dnp3_pcap.py:169-235`, and `s7comm_pcap.py:187-253`
carry byte-for-byte identical `_TcpFlow`, `_mac`, `_isn`, and `write_pcap`
scaffolding (~100 lines × 3). The dnp3/s7 module docstrings already name the
fix ("a shared `emit/_tcp.py` is the eventual home"). Extract a generic
`TcpFlowWriter` parameterized by a `payload_for(event) -> bytes` callable; each
protocol module keeps only its PDU builders. This removes ~200 duplicated lines
and makes the fourth protocol's emitter trivially small — a strong story for
`docs/adding-a-protocol.md`.

### 6. Shared protocol helpers are quadruplicated

- `_zeek_uid` appears four times (`protocols/modbus.py:475`,
  `protocols/dnp3.py:429`, `protocols/s7comm.py:321`,
  `honeypot/modbus.py:168`), with `_B62` constants alongside.
- `_ipv4`, `_check_int`/`_opt_int`/`_opt_str` style param validators, the
  `_EPHEMERAL_BASE` connection bookkeeping, and the `_normalize_function`
  tokenizer are near-identical across the three protocol modules.
- The duplicate-key-rejecting `_StrictLoader` + constructor is defined twice
  (`scenarios/loader.py:60-91`, `detect/registry.py:71-96`).

A small `substation/protocols/_common.py` (uid, ipv4 check, param validators,
connection/port allocation) and a `substation/_yaml.py` (strict loader) would
cut several hundred lines and guarantee the protocols can't drift apart.

### 7. Registry and Sigma rules are re-parsed per scenario

In the demo loop, `run_detections` (`detect/__init__.py:53-69`) calls
`load_registry()` and re-reads + re-parses **every** Sigma rule file for each
scenario; `render_coverage_map` (`coverage/__init__.py:43`) loads the registry
a fourth time. At today's scale this is invisible (demo: 0.54s total), but the
fix is one-line-cheap: memoize `load_rule` (e.g. `functools.lru_cache` keyed on
resolved path) and/or load the registry once in `_cmd_demo` and pass it through.
This also makes the Tier-1 path scale to large event logs and many rules.

### 8. Minor code-quality nits

- `emit/json_emitter.py:37` does a deferred
  `from substation.schema import SchemaValidationError` inside `write_jsonl`
  even though the module already imports from `substation.schema` at top level
  — move it up.
- `scripts/security/secret_scan.py:115,154` import `json` and `os` inside
  functions; move to module top.
- `scenarios/loader.py:312`: `str(data.get("description", ""))` silently
  stringifies a non-string `description` (e.g. a mapping) — inconsistent with
  the loader's otherwise-strict posture; validate it like every other field.
- `write_jsonl` and `load_events` are fully in-memory (join-then-write, full
  `read_text().splitlines()`). Fine at current scale; if honeypot logs or
  long-running captures grow, switch to streaming (`fh.write` per line /
  iterate the file handle).

---

## P3 — Functionality and UX suggestions

### 9. Grow the CLI into the single front door

`substation` currently exposes `demo` and a help-text-only `verify`. Cheap,
high-visibility wins:

- `--version` flag (`substation.__version__` already exists).
- `demo --scenario` accepting multiple paths (`nargs="+"`), so users can run
  their own benign+anomalous pairs the way the bundled set does.
- `substation list` — enumerate bundled scenarios and registered detections
  (the registry has everything needed).
- Promote `python -m substation.schema` and `python -m substation.coverage` to
  `substation validate` / `substation coverage` subcommands so one entrypoint
  tells the whole story (the `-m` forms can stay).
- A `demo --strict` mode that checks each scenario's `exercises` contract
  (fires/quiet) and exits non-zero on violation — turning the demo into a
  one-command smoke test for users' own scenario edits.

### 10. Scenario naming is inconsistent and can collide in `artifacts/`

`scenario.name` becomes the artifact basename (`artifacts/<name>.pcap`), and the
three protocol trees use three conventions: Modbus unprefixed
(`benign-baseline`), S7 prefixed (`s7-benign-baseline`), DNP3 mixed
(`dnp3-benign-baseline` but `anomalous-x1-new-function` unprefixed). Two
scenarios from different protocols with the same unprefixed name would silently
overwrite each other's artifacts. Standardize on `<proto>-...` everywhere (or
emit into `artifacts/<proto>/`).

### 11. Tier-2 Zeek rules have no cheap syntax gate

4 of 11 detections (M3, D4, S3, X1 — all Zeek) execute only under `make verify`
(Docker), so a syntax error in a `.zeek` file can sit unnoticed between Tier-2
runs. The contract-linkage tests catch metadata drift but never parse the Zeek.
Consider a best-effort CI step: if `zeek` (or the Tier-2 container) is
available, run `zeek --parse-only detections/zeek/*.zeek`; skip cleanly when it
isn't. Also note the test-suite skip messages already make this honest — good.

### 12. Tighten the Detection Contract assertions

`test_detection_contract.py` asserts *≥1 hit* on fire scenarios and *0 hits* on
quiet ones. It never asserts the hits land on the **expected events** — e.g.
that M1 fires on exactly the two out-of-policy write requests and not on
responses. Asserting expected hit counts (or event indices) per scenario would
catch a rule that over-matches yet still passes both gates.

### 13. Honeypot hardening (opt-in path, low priority)

- `_ProbeLog` (`honeypot/modbus.py:562-578`) is append-only with no size cap or
  rotation; a noisy scanner can grow the log unboundedly. A simple max-size
  with rotation (or a documented `logrotate` recommendation in the README)
  fits the "research, isolated" posture.
- Request and response events share one `time.time()` timestamp
  (`_handle_connection`), while the simulator models a 50ms turnaround —
  harmless, but worth a comment since detections may key on ordering.
- The server is single-connection-at-a-time (documented and reasonable); the
  recv timeout already prevents wedging.

### 14. Misc polish

- Add a one-line Sigma-rule **UUID uniqueness** test (the registry tests check
  detection IDs but not the rule `id:` UUIDs).
- `detections/zeek/s7comm_s3_enumeration.zeek` and
  `x1_cross_protocol_baseline.zeek` handle `s7comm_*` events without an
  `@load` (Modbus/DNP3 analyzers are explicitly loaded); add a comment that
  ICSNPP provides these in the Tier-2 container, or load it explicitly.
- `coverage-build` writes both `coverage/` and `docs/coverage/` but
  `coverage-check` only verifies `docs/coverage/`; the in-repo `coverage/`
  output (gitkeep only) is redundant — consider emitting a single committed
  snapshot.
- `files_only_guard` monkeypatches `socket.socket` process-globally and is not
  thread-safe (fine for the single-threaded emitters — worth one docstring
  sentence). `os.sendfile` on a raw socket fd would bypass it, but the static
  AST scan covers the repo, so this is a documentation note, not a hole.
- The demo's coverage table uses a fixed width of 60
  (`coverage/__init__.py:65`); current data fits, but the width should derive
  from the longest row if tactic names grow.

---

## What is already excellent (keep it)

- **Safety invariant depth**: runtime guard + AST scan + socket-construction
  test is genuinely defense-in-depth; the honeypot is loopback-only by default
  with an explicit opt-in and never initiates connections.
- **Determinism everywhere**: blake2b-derived uids/ISNs/MACs, synthesized
  response values as a function of address — byte-identical artifacts make the
  golden tests and drift checks trustworthy.
- **Strictness**: duplicate-key-rejecting YAML loaders, deep-frozen scenario
  params with cycle detection, bool-vs-int guards on every numeric check, the
  schema validator rejecting NaN/Infinity barewords.
- **Generated, drift-checked coverage artifacts** (markdown + JSON + Navigator
  layer) from a single registry — exactly the right shape.
- **Speed**: full unit suite in ~3s; demo in ~0.5s. The Tier-1 "zero-dep"
  promise holds up.
