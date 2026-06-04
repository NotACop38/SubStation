"""Optional research honeypot — a **passive, isolated** Modbus probe logger.

This subpackage is the optional honeypot of ``PRD.md`` §6.10 / Phase 5: a minimal
Modbus/TCP responder that **only ever listens and answers** inbound probes and
records them as schema-conforming event-log lines, so the same Substation
detections (M1/M2/M3, …) can be run against captured probe traffic.

It is deliberately **out of the headline path**: nothing in ``substation.cli`` or
``make demo`` imports it, and it ships disabled-by-default safety behaviour
(loopback-only bind unless explicitly overridden — see :mod:`.modbus` and
``substation/honeypot/README.md``).

Boundary vs. the simulator (important): the *simulator* is **files-only** and
never opens a socket (``substation.emit.guard``). The honeypot is the one
component that intentionally binds a **listening** socket — but it is strictly
**passive**: it ``accept()``s inbound connections and replies on them, and it
**never initiates an outbound connection** (no ``connect()``) and never touches
real OT. Deploy it network-isolated only; read the README before running it.
"""

from __future__ import annotations

from substation.honeypot.modbus import (
    HoneypotConfig,
    HoneypotConfigError,
    ModbusHoneypot,
    StubDevice,
    process_frame,
)

__all__ = [
    "HoneypotConfig",
    "HoneypotConfigError",
    "ModbusHoneypot",
    "StubDevice",
    "process_frame",
]
