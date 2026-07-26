"""Substation command-line entrypoint — the single front door.

The Tier-1 loop is **generate telemetry -> run detections -> render coverage
map** (`PRD.md` §6.8). The `demo` command runs the full path end to end: it
emits live PCAP + JSON from the scenario model, runs the Sigma detections
over the JSON event log, and prints the hits plus the real ATT&CK-for-ICS
coverage map (registry-driven). The bundled demo runs a benign baseline (which
stays quiet) and anomalous scenarios (which fire), so one command shows both the
low-false-positive baseline and real detections.

The other subcommands surface the rest of the toolkit from one entrypoint:
``list`` (bundled scenarios + registered detections), ``validate`` (event-log
schema validation; also ``python -m substation.schema``), ``coverage`` (the
generated ATT&CK coverage artifacts; also ``python -m substation.coverage``),
and ``verify`` (how to run Tier-2).

Safety invariant (PRD.md §6.4): nothing here ever opens a sending socket or
transmits on a live interface. The simulator is files-only, always.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from substation import __version__
from substation.content import ContentError, content_path
from substation.coverage import render_coverage_map
from substation.detect import Hit, run_detections
from substation.detect.registry import Detection, RegistryError, load_registry
from substation.emit import EmitError, write_artifacts
from substation.protocols.dnp3 import Dnp3Error
from substation.protocols.modbus import ModbusError
from substation.protocols.s7comm import S7Error
from substation.scenarios import Scenario, ScenarioError, load_scenario, load_scenarios

__all__ = ["main"]

_ARTIFACTS_DIR = Path("artifacts")


def _demo_scenarios() -> list[Path]:
    """Bundled demo set: Modbus quiet baseline plus M1/M2 fire scenarios."""
    return [
        content_path("scenarios", "modbus", "benign-baseline.yaml"),
        content_path("scenarios", "modbus", "anomalous-m1-unauthorized-write.yaml"),
        content_path("scenarios", "modbus", "anomalous-m2-illegal-function.yaml"),
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
        # Scenarios live in the repo tree (PRD.md §6.9 keeps scenarios/ outside the
        # package), so they are only present for an in-tree checkout. Fail with an
        # actionable hint rather than a cryptic load error.
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
    if is_default_set and fired:
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

    if args.strict:
        failures = _contract_failures(per_scenario_hits, registry)
        if failures:
            print("\nStrict contract check FAILED:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
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


def _cmd_coverage(args: argparse.Namespace) -> int:
    # Same checkout requirement as list/demo: the coverage map renders from the
    # registry, which ships in the repo tree, not the installed package.
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
        "Tier-2 validation runs real Zeek/ICSNPP + Suricata over the emitted PCAPs\n"
        "(fidelity golden test + Zeek/Suricata detections). It needs Docker and is\n"
        "driven from a repo checkout:\n\n"
        "    make verify\n\n"
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
    return result


if __name__ == "__main__":
    sys.exit(main())
