#!/usr/bin/env python3
"""Rebuild the attributed Modbus corpus from a hash-pinned local upstream checkout.

Requires native Zeek. Reads PCAPs and writes files only; never replays traffic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, Raw, TCP, rdpcap, wrpcap

from scripts.verify import run
from substation.ingest.modbus import load_modbus_log

SOURCE_SHA256 = "a84656f9af62b2c948200ec288d51b81f03037c277a31a40efee0cfb244f1e30"
SOURCE_REVISION = "27f22b41fd9839c0bad1b98df9c6289e578fd02a"  # pragma: allowlist secret


def derive(source: Path, destination: Path) -> None:
    trace = source / "testing/traces/modbus_example.pcap"
    if hashlib.sha256(trace.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("upstream capture hash differs from reviewed source")
    if shutil.which("zeek") is None:
        raise ValueError("native Zeek is required to regenerate sensor observations")
    run._NATIVE_ZEEK = shutil.which("zeek")
    destination.mkdir(parents=True, exist_ok=True)
    packets = rdpcap(str(trace))
    for name, indices, target in [
        ("core", list(range(43)), "192.0.2.50"),
        ("exception", [98, 99], "192.0.2.51"),
    ]:
        chosen = [packets[i] for i in indices]
        starts = {
            orig: next(p[TCP].seq for p in chosen if (p[TCP].dport == 502) == orig)
            for orig in (True, False)
        }
        output = []
        for i, packet in enumerate(chosen):
            tcp = packet[TCP]
            orig = tcp.dport == 502
            payload = bytes(tcp.payload)
            # Rebuild transport/network metadata; retain every Modbus payload byte.
            result = (
                Ether(
                    src="02:00:00:00:00:10" if orig else "02:00:00:00:00:50",
                    dst="02:00:00:00:00:50" if orig else "02:00:00:00:00:10",
                )
                / IP(
                    src="192.0.2.10" if orig else target,
                    dst=target if orig else "192.0.2.10",
                    id=i,
                    ttl=64,
                )
                / TCP(
                    sport=43000 if orig else 502,
                    dport=502 if orig else 43000,
                    flags=tcp.flags,
                    seq=(tcp.seq - starts[orig]) % 2**32,
                    ack=(tcp.ack - starts[not orig]) % 2**32 if "A" in tcp.flags else 0,
                    window=8192,
                )
            )
            if payload:
                result = result / Raw(payload)
            result.time = packet.time - chosen[0].time + 1
            output.append(result)
        pcap = destination / f"{name}.pcap"
        wrpcap(str(pcap), output)
        logs = run.run_zeek(pcap, [str((source / "scripts").resolve()), "LogAscii::use_json=T"], [])
        try:
            events = load_modbus_log(logs / "modbus_detailed.log")
        finally:
            shutil.rmtree(logs)
        events.sort(key=lambda event: (event["detail"]["tid"], not event["is_orig"]))
        for event in events:
            event["uid"] = f"Ccorpus-{name}"
            event["detail"].pop("modbus_detailed_link_id", None)
        (destination / f"{name}.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8"
        )
        (destination / f"{name}.provenance.json").write_text(
            json.dumps(
                {
                    "source_packet_indices_zero_based": indices,
                    "payload_sha256": [
                        hashlib.sha256(bytes(p[TCP].payload)).hexdigest() for p in chosen
                    ],
                    "packet_count": len(output),
                    "event_count": len(events),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    for filename in ("LICENSE.txt", "NOTICE.txt"):
        shutil.copyfile(source / filename, destination / filename)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    derive(args.source, args.out)
    print(
        "Rebuilt captures/logs/provenance. Review differences and refresh manifest artifact hashes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
