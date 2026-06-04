"""Substation command-line entrypoint.

The Tier-1 loop is **generate telemetry -> run detections -> render coverage
map** (`PRD.md` §6.8). The `demo` command runs the full path end to end: it
emits live Modbus PCAP + JSON from the scenario model, runs the Sigma detections
over the JSON event log, and prints the hits plus the real ATT&CK-for-ICS
coverage map (registry-driven). The bundled demo runs a benign baseline (which
stays quiet) and anomalous scenarios (which fire), so one command shows both the
low-false-positive baseline and real detections.

Safety invariant (PRD.md §6.4): nothing here ever opens a sending socket or
transmits on a live interface. The simulator is files-only, always.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from substation.coverage import render_coverage_map
from substation.detect import Hit, run_detections
from substation.emit import EmitError, write_artifacts
from substation.protocols.modbus import ModbusError
from substation.scenarios import Scenario, ScenarioError, load_scenario

__all__ = ["main"]

# Repo-root-relative defaults for the demo.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_ARTIFACTS_DIR = _REPO_ROOT / "artifacts"
# The bundled demo tells the whole story in one command: a benign baseline that
# stays QUIET (low false positives), then anomalies that FIRE real detections.
_DEMO_SCENARIOS = [
    _REPO_ROOT / "scenarios" / "modbus" / "benign-baseline.yaml",
    _REPO_ROOT / "scenarios" / "modbus" / "anomalous-m1-unauthorized-write.yaml",
    _REPO_ROOT / "scenarios" / "modbus" / "anomalous-m2-illegal-function.yaml",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="substation",
        description="Defensive ICS detection-content pack and files-only protocol simulator.",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="Run the Tier-1 demo loop end to end.")
    demo.add_argument(
        "--scenario",
        type=Path,
        default=None,
        help="Scenario YAML to run (default: the bundled benign + anomalous demo set).",
    )
    demo.add_argument(
        "--artifacts",
        type=Path,
        default=_ARTIFACTS_DIR,
        help="Directory for generated artifacts (default: ./artifacts).",
    )
    demo.set_defaults(func=_cmd_demo)

    verify = sub.add_parser("verify", help="How to run Tier-2 (Docker) validation.")
    verify.set_defaults(func=_cmd_verify)

    return parser


def _cmd_demo(args: argparse.Namespace) -> int:
    artifacts_dir: Path = args.artifacts
    # An explicit --scenario runs just that file; otherwise run the bundled
    # benign+anomalous set so one command shows quiet-on-benign AND fire-on-anomaly.
    scenario_paths: list[Path] = [args.scenario] if args.scenario is not None else _DEMO_SCENARIOS

    print("substation demo — Tier-1 loop: generate -> detect -> report (pure Python)\n")

    all_scenarios: list[Scenario] = []
    all_hits: list[Hit] = []
    for scenario_path in scenario_paths:
        # Scenarios live in the repo tree (PRD.md §6.9 keeps scenarios/ outside the
        # package), so they are only present for an in-tree checkout. Fail with an
        # actionable hint rather than a cryptic load error.
        if not scenario_path.exists():
            print(
                f"error: scenario not found at {scenario_path}.\n"
                "Run `make demo` from a repo checkout, or pass --scenario PATH.",
                file=sys.stderr,
            )
            return 1
        try:
            scenario: Scenario = load_scenario(scenario_path)
        except ScenarioError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        try:
            emitted = write_artifacts(scenario, artifacts_dir)
        except (EmitError, ModbusError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        hits: list[Hit] = run_detections(emitted.jsonl)
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

    print()
    print(render_coverage_map(all_scenarios, all_hits))
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
    return 0


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
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
