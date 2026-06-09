"""Best-effort syntax gate for the Tier-2 Zeek detections.

M3/D4/S3/X1 execute only in the Tier-2 (Docker) runner, so a syntax error in a
``.zeek`` file could otherwise sit unnoticed between ``make verify`` runs. When
a ``zeek`` binary is available (e.g. the Tier-2 container, or a dev box with
Zeek installed) this parses every shipped detection script; without one the
tests skip with a reason rather than silently passing.

The S7comm events (``s7comm_header`` & co.) are defined by the ICSNPP plugin,
not base Zeek, so scripts handling them cannot fully resolve against a bare
Zeek. Failures whose every error concerns an s7comm identifier are therefore
skipped (plugin absent), while any other parse failure — an actual syntax
error — fails the gate.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ZEEK_SCRIPTS = sorted((_REPO_ROOT / "detections" / "zeek").glob("*.zeek"))
_ZEEK = shutil.which("zeek")


def _only_missing_icsnpp_identifiers(stderr: str) -> bool:
    """True when every reported error line is about an ICSNPP-provided s7comm name."""
    error_lines = [line for line in stderr.splitlines() if "error" in line.lower()]
    return bool(error_lines) and all("s7comm" in line.lower() for line in error_lines)


@pytest.mark.skipif(_ZEEK is None, reason="zeek not on PATH — Tier-2 container runs this gate")
@pytest.mark.parametrize("script", _ZEEK_SCRIPTS, ids=[p.name for p in _ZEEK_SCRIPTS])
def test_zeek_detection_parses(script: Path) -> None:
    assert _ZEEK is not None  # narrowed by skipif
    # S603: argv is fully constructed from shutil.which("zeek") + repo paths —
    # no untrusted input reaches the call.
    proc = subprocess.run(  # noqa: S603
        [_ZEEK, "--parse-only", str(script)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0 and _only_missing_icsnpp_identifiers(proc.stderr):
        pytest.skip(f"{script.name} needs the ICSNPP s7comm plugin (not installed here)")
    assert proc.returncode == 0, f"zeek --parse-only failed for {script.name}:\n{proc.stderr}"


def test_zeek_detection_scripts_exist() -> None:
    """The glob above must actually cover the shipped Zeek detections."""
    names = {p.name for p in _ZEEK_SCRIPTS}
    assert {
        "modbus_m3_unit_function_sweep.zeek",
        "dnp3_d4_function_enumeration.zeek",
        "s7comm_s3_enumeration.zeek",
        "x1_cross_protocol_baseline.zeek",
    } <= names
