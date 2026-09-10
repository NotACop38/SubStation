"""Substation command-line entrypoint — the single front door.

The Tier-1 loop is **generate telemetry -> run detections -> render coverage
map** (`PRD.md` §6.8). The `demo` command runs the full path end to end: it
emits live PCAP + JSON from the scenario model, runs the Sigma detections
over the JSON event log, and prints the hits plus the real ATT&CK-for-ICS
coverage map (registry-driven). The bundled demo runs a benign baseline (which
stays quiet) and anomalous scenarios (which fire), so one command shows both the
expected behavior on the bundled synthetic fixtures.

The other subcommands surface the rest of the toolkit from one entrypoint:
``list`` (bundled scenarios + registered detections), ``validate`` (event-log
schema validation; also ``python -m substation.schema``), ``coverage`` (the
generated ATT&CK coverage artifacts; also ``python -m substation.coverage``),
``detect`` (evaluate normalized JSONL), and ``verify`` (how to run Tier-2).

Safety invariant (PRD.md §6.4): nothing here ever opens a sending socket or
transmits on a live interface. The simulator is files-only, always.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from substation import __version__
from substation.content import ContentError, content_path
from substation.coverage import render_coverage_map
from substation.detect import Hit, run_detections
from substation.detect.registry import Detection, RegistryError, load_registry
from substation.detect.sigma_eval import SigmaEvalError
from substation.emit import EmitError, write_artifacts
from substation.protocols.dnp3 import Dnp3Error
from substation.protocols.modbus import ModbusError
from substation.protocols.s7comm import S7Error
from substation.scenarios import Scenario, ScenarioError, load_scenario, load_scenarios
from substation.schema import SchemaValidationError

__all__ = ["main"]

_ARTIFACTS_DIR = Path("artifacts")


def _demo_scenarios() -> list[Path]:
    """Bundled demo set: Modbus quiet+fire plus one DNP3 fire (≥2 protocols)."""
    return [
        content_path("scenarios", "modbus", "benign-baseline.yaml"),
        content_path("scenarios", "modbus", "anomalous-m1-unauthorized-write.yaml"),
        content_path("scenarios", "modbus", "anomalous-m2-illegal-function.yaml"),
        content_path("scenarios", "dnp3", "anomalous-d1-restart.yaml"),
    ]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="substation",
        description="Defensive ICS detection-content pack and files-only protocol simulator.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="Run the Tier-1 demo loop end to end.")
    demo.add_argument(
        "--scenario",
        type=Path,
        nargs="+",
        default=None,
        help="Scenario YAML file(s) to run, e.g. a benign + anomalous pair "
        "(default: the bundled benign + anomalous demo set).",
    )
    demo.add_argument(
        "--artifacts",
        type=Path,
        default=_ARTIFACTS_DIR,
        help="Directory for generated artifacts (default: ./artifacts).",
    )
    demo.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero unless every scenario's exercises contract holds "
        "(Tier-1 detections listed under 'fires' fired and 'quiet' stayed quiet) — "
        "a one-command smoke test for scenario edits.",
    )
    demo.set_defaults(func=_cmd_demo)

    list_cmd = sub.add_parser("list", help="List registered detections and bundled scenarios.")
    list_cmd.set_defaults(func=_cmd_list)

    detect = sub.add_parser("detect", help="Run Tier-1 rules on normalized .jsonl event logs.")
    detect.add_argument("paths", nargs="+", type=Path, help="Substation-schema JSONL files.")
    detect.add_argument("--detection", nargs="+", help="Tier-1 detection IDs (default: all).")
    detect.add_argument("--policy", type=Path, help="Explicit site authorization profile.")
    detect.set_defaults(func=_cmd_detect)

    importer = sub.add_parser("import-modbus", help="Normalize ICSNPP Modbus JSON/TSV logs.")
    importer.add_argument("paths", nargs="+", type=Path)
    importer.add_argument("--out", type=Path, help="Atomic JSONL output (default: stdout).")
    importer.set_defaults(func=_cmd_import_modbus)

    policy = sub.add_parser("policy", help="Compile a site profile into portable Sigma.")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    compile_cmd = policy_sub.add_parser("compile")
    compile_cmd.add_argument("path", type=Path)
    compile_cmd.add_argument("--out", type=Path, required=True, help="New export directory.")
    compile_cmd.set_defaults(func=_cmd_policy)

    corpus = sub.add_parser("evaluate-corpus", help="Verify a labeled corpus and report metrics.")
    corpus.add_argument("path", type=Path)
    corpus.set_defaults(func=_cmd_corpus)

    validate = sub.add_parser(
        "validate",
        help="Validate .jsonl event logs against the frozen event-log schema.",
    )
    validate.add_argument(
        "paths",
        type=Path,
        nargs="*",
        help="Files or directories to validate (default: the committed golden events).",
    )
    validate.set_defaults(func=_cmd_validate)

    coverage = sub.add_parser(
        "coverage",
        help="Generate (or drift-check) the ATT&CK-for-ICS coverage map + Navigator layer.",
    )
    coverage.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed coverage files are up to date; do not write.",
    )
    coverage.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory (default: docs/coverage, the committed snapshot).",
    )
    coverage.set_defaults(func=_cmd_coverage)

    verify = sub.add_parser("verify", help="How to run Tier-2 (Docker) validation.")
    verify.set_defaults(func=_cmd_verify)

    return parser


def _cmd_demo(args: argparse.Namespace) -> int:
    artifacts_dir: Path = args.artifacts
    # An explicit --scenario runs just those files; otherwise run the bundled
    # benign+anomalous set so one command shows quiet-on-benign AND fire-on-anomaly.
    try:
        scenario_paths: list[Path] = (
            list(args.scenario) if args.scenario is not None else _demo_scenarios()
        )
    except ContentError as exc:
        print(
            f"error: {exc}\n"
            "Detection content should be available from a wheel install "
            "(packaged under substation.content) or a repo checkout.",
            file=sys.stderr,
        )
        return 1

    print("substation demo · Tier-1 loop: generate -> detect -> report (pure Python)\n")

    # Load the registry once: every scenario evaluates the same detections, and
    # the coverage map renders from the same metadata.
    registry = _load_registry_or_explain()
    if registry is None:
        return 1

    all_scenarios: list[Scenario] = []
    all_hits: list[Hit] = []
    per_scenario_hits: list[tuple[Scenario, list[Hit]]] = []
    seen_names: dict[str, Path] = {}
    for scenario_path in scenario_paths:
        # Content resolves from the checkout or from the installed wheel.
        if not scenario_path.exists():
            print(
                f"error: scenario not found at {scenario_path}.\n"
                "Pass --scenario PATH, or reinstall so packaged scenarios are present.",
                file=sys.stderr,
            )
            return 1
        try:
            scenario: Scenario = load_scenario(scenario_path)
        except ScenarioError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        # Artifact filenames derive from scenario names, so two scenarios in one
        # run sharing a name would silently overwrite each other's PCAP/JSON.
        if scenario.name in seen_names:
            print(
                f"error: {scenario_path} reuses scenario name {scenario.name!r} "
                f"(already used by {seen_names[scenario.name]}); each scenario in a "
                "run needs a distinct name because artifacts are written to "
                f"<artifacts>/{scenario.name}.pcap/.jsonl",
                file=sys.stderr,
            )
            return 1
        seen_names[scenario.name] = scenario_path
        try:
            emitted = write_artifacts(scenario, artifacts_dir)
        except (EmitError, Dnp3Error, ModbusError, S7Error) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        hits: list[Hit] = run_detections(emitted.jsonl, registry)
        if hits:
            ids = ", ".join(sorted({h.detection_id for h in hits}))
            verdict = f"FIRED {len(hits)} hit(s) -> {ids}"
        else:
            verdict = "quiet (no hits)"
        print(
            f"[{scenario.label.value:9}] {scenario.name:<34} "
            f"{emitted.event_count:>2} events -> {verdict}"
        )
        all_scenarios.append(scenario)
        all_hits.extend(hits)
        per_scenario_hits.append((scenario, hits))

    print()
    print(render_coverage_map(all_scenarios, all_hits, registry))
    fired = sorted({h.detection_id for h in all_hits})
    is_default_set = args.scenario is None
    benign_is_quiet = all(
        not hits for scenario, hits in per_scenario_hits if scenario.label.value == "benign"
    )
    if is_default_set and fired and benign_is_quiet:
        # The bundled set always pairs the benign baseline with the anomalies.
        print(
            f"\nResult: quiet on the benign baseline; fired {len(fired)} detection(s) on "
            f"the anomalies ({', '.join(fired)})."
        )
    else:
        # An explicit --scenario run: summarize only what was actually measured.
        labels = ", ".join(f"{s.name} ({s.label.value})" for s in all_scenarios)
        if fired:
            print(f"\nResult: ran {labels}; fired {len(fired)} detection(s) ({', '.join(fired)}).")
        else:
            print(f"\nResult: ran {labels}; no detections fired (quiet).")

    if args.strict or is_default_set:
        failures = _contract_failures(per_scenario_hits, registry)
        if failures:
            print("\nStrict contract check FAILED:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        if args.strict:
            print("\nStrict contract check: OK — every Tier-1 exercises entry held.")
    return 0


def _contract_failures(
    per_scenario_hits: list[tuple[Scenario, list[Hit]]], registry: list[Detection]
) -> list[str]:
    """Check each scenario's ``exercises`` contract against this run's hits.

    Only Tier-1 Sigma detections are checkable here (Tier-2 Zeek/Suricata rules
    run over PCAP in the Tier-2 runner), mirroring the Detection Contract
    harness's tier scoping — but an ``exercises`` id that names no registered
    detection at all is a failure, not a skip: silently ignoring a typo'd id
    would let strict mode report OK without having checked anything.
    """
    registry_ids = {d.id for d in registry}
    tier1_ids = {d.id for d in registry if d.engine == "sigma" and d.tier == 1}
    failures: list[str] = []
    for scenario, hits in per_scenario_hits:
        fired_ids = {h.detection_id for h in hits}
        for det_id in (*scenario.exercises.fires, *scenario.exercises.quiet):
            if det_id not in registry_ids:
                failures.append(
                    f"{scenario.name}: exercises names unknown detection {det_id!r} "
                    f"(known: {', '.join(sorted(registry_ids))})"
                )
        for det_id in scenario.exercises.fires:
            if det_id in tier1_ids and det_id not in fired_ids:
                failures.append(f"{scenario.name}: expected {det_id} to fire but it stayed quiet")
        for det_id in scenario.exercises.quiet:
            if det_id in tier1_ids and det_id in fired_ids:
                failures.append(f"{scenario.name}: expected {det_id} to stay quiet but it fired")
    return failures


def _load_registry_or_explain() -> list[Detection] | None:
    """Load the detection registry, printing an actionable error when it can't be."""
    try:
        return load_registry()
    except (RegistryError, ContentError) as exc:
        print(
            f"error: {exc}\n"
            "Detection content should be available from a wheel install "
            "(packaged under substation.content) or a repo checkout.",
            file=sys.stderr,
        )
        return None


def _cmd_list(_args: argparse.Namespace) -> int:
    registry = _load_registry_or_explain()
    if registry is None:
        return 1

    print("Detections (detections/registry.yaml):")
    for det in registry:
        techniques = ", ".join(t.id for t in det.attack.techniques)
        print(
            f"  {det.id:<4} {det.protocol:<7} {det.engine:<5} tier {det.tier}  "
            f"{det.title} [{techniques}]"
        )

    try:
        scenario_dir = content_path("scenarios")
    except ContentError as exc:
        print(f"\nScenarios: none found ({exc})")
        return 0
    try:
        scenarios = load_scenarios(scenario_dir)
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("\nScenarios (scenarios/):")
    for scenario in scenarios:
        exercised = ", ".join(
            [*scenario.exercises.fires, *(f"{d} quiet" for d in scenario.exercises.quiet)]
        )
        print(
            f"  {scenario.name:<40} {scenario.protocol.value:<7} {scenario.label.value:<9} "
            f"exercises: {exercised or '-'}"
        )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    from substation.schema.__main__ import main as schema_main

    return schema_main([str(p) for p in args.paths])


def _cmd_detect(args: argparse.Namespace) -> int:
    registry = _load_registry_or_explain()
    if registry is None:
        return 1
    eligible = {d.id: d for d in registry if d.engine == "sigma" and d.tier == 1}
    requested = list(eligible) if args.detection is None else args.detection
    invalid = set(requested) - eligible.keys()
    if invalid:
        print(
            f"error: unknown or non-Tier-1 detection(s): {', '.join(sorted(invalid))}; "
            f"available: {', '.join(eligible)}",
            file=sys.stderr,
        )
        return 1
    detections = [eligible[det_id] for det_id in dict.fromkeys(requested)]
    # Validate and evaluate every input before publishing results. A malformed
    # later file must not leave apparently successful, partial machine output.
    from substation.policy import load_policy

    policy = load_policy(args.policy) if args.policy is not None else None
    results = [(path, run_detections(path, detections, policy=policy)) for path in args.paths]
    for path, hits in results:
        for hit in hits:
            print(
                json.dumps(
                    {
                        "event_file": str(path),
                        "detection_id": hit.detection_id,
                        "event_index": hit.event_index,
                    }
                )
            )
    count = sum(len(hits) for _, hits in results)
    print(
        f"detect: {len(results)} file(s), {len(detections)} Tier-1 rule(s), {count} hit(s); "
        "Tier-2 rules not run",
        file=sys.stderr,
    )
    return 0


def _cmd_import_modbus(args: argparse.Namespace) -> int:
    from substation.ingest.modbus import load_modbus_log
    from substation.io import atomic_write
    from substation.schema import MAX_JSONL_BYTES, MAX_JSONL_LINES

    if args.out and any(args.out.resolve() == path.resolve() for path in args.paths):
        raise SchemaValidationError("output must differ from every input")
    events = []
    for path in args.paths:
        events.extend(load_modbus_log(path))
        if len(events) > MAX_JSONL_LINES:
            raise SchemaValidationError("combined projections exceed event load cap")
    output = "".join(json.dumps(event, allow_nan=False) + "\n" for event in events)
    if len(output.encode("utf-8")) > MAX_JSONL_BYTES:
        raise SchemaValidationError("projected JSONL exceeds event byte cap")
    if args.out:
        atomic_write(args.out, output)
    else:
        sys.stdout.write(output)
    print(
        f"import-modbus: {len(events)} observations; transaction timestamps retained",
        file=sys.stderr,
    )
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    from substation.policy import export_policy, load_policy

    export_policy(load_policy(args.path), args.out)
    print(f"policy: exported seven Tier-1 rules and provenance to {args.out}")
    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    from substation.corpus import evaluate_corpus

    report = evaluate_corpus(args.path)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


def _cmd_coverage(args: argparse.Namespace) -> int:
    # Resolve the registry from the checkout or packaged content.
    if _load_registry_or_explain() is None:
        return 1
    from substation.coverage.__main__ import main as coverage_main

    argv: list[str] = ["--check"] if args.check else []
    if args.out is not None:
        argv += ["--out", str(args.out)]
    return coverage_main(argv)


def _cmd_verify(_args: argparse.Namespace) -> int:
    # Tier 2 is a local, Docker-orchestrated gate (real Zeek/ICSNPP + Suricata),
    # deliberately kept out of the pure-Python installed path so the Tier-1
    # headline promise ("only Python 3.11+") holds. It is driven by the Makefile.
    print(
        "Tier-2 validation runs Zeek/ICSNPP over the emitted PCAPs for request\n"
        "identity/count parity and stateful detection checks. It is\n"
        "driven from a repo checkout:\n\n"
        "    make verify VERIFY_ARGS=--require-complete\n\n"
        "Use VERIFY_ARGS='--native --require-complete' with local Zeek and the S7 plugin.\n"
        "Tier 1 (this CLI's `demo`) stays pure-Python and needs no Docker."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        result: int = args.func(args)
        # Flush INSIDE the try: with a block-buffered pipe (the common non-TTY
        # case), an early-closed reader surfaces EPIPE only at flush time — if
        # that happens at interpreter shutdown instead of here, the handler
        # below never runs and Python prints "Exception ignored" and exits 120.
        sys.stdout.flush()
    except BrokenPipeError:
        # Piping into e.g. `head` closes stdout early; exit quietly (the Unix
        # convention, 128 + SIGPIPE) instead of dumping a traceback. Redirect
        # stdout to devnull first so interpreter shutdown doesn't re-raise;
        # tolerate streams without a real fd (e.g. captured stdout in tests).
        import contextlib
        import os

        with contextlib.suppress(OSError, ValueError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 141
    except (OSError, SchemaValidationError, SigmaEvalError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
