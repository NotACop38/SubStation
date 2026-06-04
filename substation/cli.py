"""Substation command-line entrypoint.

The Tier-1 loop is **generate telemetry -> run detections -> render coverage
map** (`PRD.md` §6.8). The `demo` command runs the full path end to end: the
generate stage now emits live Modbus PCAP + JSON from the scenario model (Phase
1), while detect and report remain placeholders until their Phase-1 content lands.

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

# Repo-root-relative defaults for the Phase-0 demo.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO_SCENARIO = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"
_ARTIFACTS_DIR = _REPO_ROOT / "artifacts"


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
        default=_DEMO_SCENARIO,
        help="Scenario YAML to run (default: the bundled benign Modbus poll).",
    )
    demo.add_argument(
        "--artifacts",
        type=Path,
        default=_ARTIFACTS_DIR,
        help="Directory for generated artifacts (default: ./artifacts).",
    )
    demo.set_defaults(func=_cmd_demo)

    verify = sub.add_parser("verify", help="Run Tier-2 fidelity validation (stub).")
    verify.set_defaults(func=_cmd_verify)

    return parser


def _cmd_demo(args: argparse.Namespace) -> int:
    scenario_path: Path = args.scenario
    artifacts_dir: Path = args.artifacts

    print(
        "substation demo — generate emits live Modbus PCAP + JSON; "
        "detect/report remain Phase-1 placeholders\n"
    )

    # The bundled demo scenario lives in the repo tree (PRD.md §6.9 keeps
    # scenarios/ outside the package), so it is only present for an in-tree
    # checkout. If it is missing — e.g. running the installed console script
    # without the repo — fail with an actionable hint rather than a cryptic load
    # error.
    if scenario_path == _DEMO_SCENARIO and not scenario_path.exists():
        print(
            f"error: bundled demo scenario not found at {scenario_path}.\n"
            "Run `make demo` from a repo checkout, or pass --scenario PATH.",
            file=sys.stderr,
        )
        return 1

    # --- load ---------------------------------------------------------------
    try:
        scenario: Scenario = load_scenario(scenario_path)
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"[load]     {scenario.name} "
        f"({scenario.protocol.value}, {scenario.label.value}): "
        f"{len(scenario.actors)} actors, {len(scenario.exchanges)} exchanges"
    )

    # --- generate -----------------------------------------------------------
    try:
        emitted = write_artifacts(scenario, artifacts_dir)
    except (EmitError, ModbusError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"[generate] wrote {emitted.event_count} events -> "
        f"{emitted.pcap.name}, {emitted.jsonl.name}"
    )

    # --- detect -------------------------------------------------------------
    hits: list[Hit] = run_detections(emitted.jsonl)
    print(f"[detect]   {len(hits)} hit(s) from the JSON event log")

    # --- report -------------------------------------------------------------
    print("[report]   rendering coverage map\n")
    print(render_coverage_map([scenario], hits))
    return 0


def _cmd_verify(_args: argparse.Namespace) -> int:
    print("substation verify: Tier-2 validation not yet implemented (Phase 0 stub).")
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
