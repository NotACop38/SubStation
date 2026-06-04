"""CLI for the optional research honeypot: ``python -m substation.honeypot``.

Opt-in and **out of the headline path** (``make demo`` never runs this). Binds
**loopback only** by default; capturing remote probes on an isolated research
segment requires the explicit ``--allow-external`` opt-in. Read
``substation/honeypot/README.md`` before running it.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from substation.honeypot.modbus import (
    HoneypotConfig,
    HoneypotConfigError,
    ModbusHoneypot,
)
from substation.protocols.modbus import DEFAULT_MODBUS_PORT

__all__ = ["main"]

_BANNER = (
    "WARNING: this is a passive research honeypot. Deploy it on a "
    "NETWORK-ISOLATED segment only, never on a production/OT network. "
    "See substation/honeypot/README.md for safety and legal cautions."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m substation.honeypot",
        description="Passive, isolated Modbus/TCP honeypot that logs inbound probes (PRD §6.10).",
        epilog=_BANNER,
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Address to bind (default: 127.0.0.1, loopback-only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_MODBUS_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_MODBUS_PORT}; <1024 needs root).",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("honeypot-probes.jsonl"),
        help="Path to the .jsonl probe log (default: ./honeypot-probes.jsonl).",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="Opt in to binding a NON-loopback address. Only on an isolated research segment.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    print(_BANNER, file=sys.stderr)
    config = HoneypotConfig(
        log_path=args.log,
        bind_host=args.bind,
        port=args.port,
        allow_external=args.allow_external,
    )
    try:
        honeypot = ModbusHoneypot(config)
    except HoneypotConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    honeypot.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
