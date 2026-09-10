"""Externally authored capture regression, explicit labels and evidence integrity."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from substation.schema import SchemaValidationError

ROOT = Path(__file__).resolve().parents[1] / "tests/data/corpus/modbus"


def test_external_corpus_expected_confusion_counts() -> None:
    from substation.corpus import evaluate_corpus

    report = evaluate_corpus(ROOT)
    assert report["case_count"] == 3
    assert report["event_evaluations"] == 42
    assert report["detections"]["M1"] == {
        "tp": 2,
        "fp": 0,
        "fn": 0,
        "tn": 40,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
    }
    assert report["detections"]["M2"]["tp"] == 1
    assert report["passed"]


def test_capture_tampering_is_rejected(tmp_path: Path) -> None:
    from substation.corpus import evaluate_corpus

    folder = tmp_path / "corpus"
    shutil.copytree(ROOT, folder)
    with (folder / "core.pcap").open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(SchemaValidationError, match="hash"):
        evaluate_corpus(folder)


@pytest.mark.parametrize("mutation", ["path", "label", "empty"])
def test_invalid_or_vacuous_manifest_fails(tmp_path: Path, mutation: str) -> None:
    from substation.corpus import evaluate_corpus

    folder = tmp_path / "corpus"
    shutil.copytree(ROOT, folder)
    path = folder / "manifest.json"
    manifest = json.loads(path.read_text())
    if mutation == "path":
        manifest["cases"][0]["events"] = "../outside.jsonl"
    elif mutation == "label":
        manifest["cases"][0]["positive"]["M1"] = [True]
    else:
        manifest["cases"] = []
    path.write_text(json.dumps(manifest))
    with pytest.raises(SchemaValidationError):
        evaluate_corpus(folder)


def test_committed_captures_preserve_payloads_and_only_synthetic_headers() -> None:
    import hashlib

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import rdpcap

    for name in ("core", "exception"):
        provenance = json.loads((ROOT / f"{name}.provenance.json").read_text())
        packets = rdpcap(str(ROOT / f"{name}.pcap"))
        assert len(packets) == provenance["packet_count"]
        for packet, digest in zip(packets, provenance["payload_sha256"], strict=True):
            assert hashlib.sha256(bytes(packet[TCP].payload)).hexdigest() == digest
            assert {packet[IP].src, packet[IP].dst} <= {"192.0.2.10", "192.0.2.50", "192.0.2.51"}
            assert {packet[Ether].src, packet[Ether].dst} <= {
                "02:00:00:00:00:10",
                "02:00:00:00:00:50",
            }
            assert {packet[TCP].sport, packet[TCP].dport} == {43000, 502}
            assert not packet[TCP].options
            assert 1 <= packet.time < 2
