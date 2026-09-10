"""Real-engine regression tests for state lifetime (optional local Zeek)."""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from scripts.verify import run as verify
from substation.emit import write_artifacts
from substation.scenarios import load_scenario

pytestmark = pytest.mark.skipif(shutil.which("zeek") is None, reason="local Zeek is unavailable")


def test_x1_unapproved_traffic_realerts_without_becoming_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    scenario = load_scenario(repo / "scenarios/modbus/benign-poll.yaml")
    exchange = scenario.exchanges[0]
    scenario = replace(
        scenario, exchanges=tuple(replace(exchange, offset=t) for t in (0.0, 1.0, 301.0))
    )
    pcap = write_artifacts(scenario, tmp_path).pcap
    assertions = tmp_path / "assert-state.zeek"
    assertions.write_text(
        "redef tcp_inactivity_timeout = 1hr;\n"
        "event zeek_done() {\n"
        " if ( |CrossProtoBaseline::known_talkers| != 0 || "
        "|CrossProtoBaseline::known_pairs| != 0 || "
        "|CrossProtoBaseline::known_funcs| != 0 ) "
        'Reporter::fatal("unapproved traffic became trusted");\n'
        "}\n"
    )
    monkeypatch.setattr(verify, "_NATIVE_ZEEK", shutil.which("zeek"))
    logs = verify.run_zeek(
        pcap, [str(repo / "detections/zeek/x1_cross_protocol_baseline.zeek"), str(assertions)], []
    )
    try:
        notices = verify.read_zeek_log(logs, "notice.log")
        assert len(notices) == 2, (
            "must suppress the immediate repeat but alert again after five minutes"
        )
        assert all("new talker" in notice["msg"] for notice in notices)
    finally:
        shutil.rmtree(logs)
