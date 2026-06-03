"""Substation command-line entrypoint (Phase 0 stub).

The real Tier-1 loop (generate telemetry -> run detections -> render coverage
map) lands in later phases. For now this only proves the wiring exists.

Safety invariant (PRD.md §6.4): nothing here ever opens a sending socket or
transmits on a live interface. The simulator is files-only, always.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="substation",
        description="Defensive ICS detection-content pack and files-only protocol simulator.",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="Run the Tier-1 demo loop (stub).")
    demo.set_defaults(func=_cmd_demo)

    verify = sub.add_parser("verify", help="Run Tier-2 fidelity validation (stub).")
    verify.set_defaults(func=_cmd_verify)

    return parser


def _cmd_demo(_args: argparse.Namespace) -> int:
    print("substation demo: pipeline wiring OK (Phase 0 stub — no telemetry yet).")
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
