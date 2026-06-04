# Spike 5 — scapy DNP3 PDU capability

**Status:** RESOLVED. **Verdict: hand-build DNP3 frames** — scapy 2.7.0 ships **no**
DNP3 layer, so the DNP3 PCAP emitter assembles the data-link / transport /
application bytes itself (over scapy's generic `IP`/`TCP`), with the DNP3 CRC
**verified against a real capture**.
**VERIFY gate:** `PRD.md` §6.4 / §7 — "scapy protocol-layer capability" (per-protocol);
`PRD.md` §8 risk "scapy lacks solid S7comm/DNP3 layers."
**Date:** 2026-06-04 · **scapy:** 2.7.0 (pinned in `pyproject.toml`).

## Goal

Decide whether scapy can assemble the DNP3/TCP PDUs the simulator needs, or whether
we hand-build PDUs / splice template PCAPs (the route `PRD.md` §6.4 reserves for
protocols scapy does not cover).

## Method

1. Enumerated scapy's contrib layers for a DNP3 module.
2. Since none exists, validated a **hand-built DNP3 encoder** against real wire
   bytes: downloaded ICSNPP-DNP3's own test capture
   (`testing/traces/dnp3_example.pcap`, via `codeload` tarball — raw single-file
   path 404s; the file lives under `testing/traces/`, **not** `tests/traces/` as the
   README's run-command implies), extracted the TCP payloads, and checked our CRC +
   frame layout reproduce the real frames exactly.

## Result 1 — scapy has no DNP3 layer

`scapy 2.7.0` `contrib/` ships `scada/iec104`, `scada/pcom`, and `opc_da` — **no
DNP3**. `from scapy.contrib import dnp3` → `ImportError`. Confirms the `PRD.md` §8
risk. (Modbus, by contrast, has `scapy.contrib.modbus` — spike 02.) So DNP3 PCAP =
**hand-assembled bytes** framed in scapy's generic `IP`/`TCP` (which we already use
for the Modbus TCP stream).

## Result 2 — DNP3 data-link frame layout (verified against real frames)

DNP3 link frame: `05 64 | LEN | CTRL | DEST(2, little-endian) | SRC(2, LE) |
CRC(2, LE)` then the user data split into ≤16-byte blocks, **each** followed by its
own 2-byte CRC. `LEN` counts `CTRL + DEST + SRC + user_data` (i.e. `5 + len(user)`),
excluding the `05 64`, `LEN` itself, and all CRCs. Verified `LEN`, `CTRL`
(`0xC4` master→outstation, `0x44` outstation→master), addresses, transport byte and
application header (`app_control`, `function_code`, and the 2-byte `iin` on
responses) against frames decoded from the example capture.

## Result 3 — DNP3 CRC (verified against 4 real frames)

DNP3 uses CRC-16 with the reflected polynomial `0xA6BC` (i.e. `0x3D65`), init
`0x0000`, **final XOR `0xFFFF`**, transmitted low-byte-first. Our implementation
reproduced the real header CRCs exactly:

| Header (hex)         | Expected CRC (LE) | Computed |
| -------------------- | ----------------- | -------- |
| `05640bc405006400`   | `6f36`            | OK       |
| `0564ff4464000500`   | `3518`            | OK       |
| `0564374464000500`   | `173d`            | OK       |
| `056411c405006400`   | `c5f2`            | OK       |

The algorithm and these vectors are recorded in
`substation/protocols/dnp3.py::dnp3_crc` so the encoder is never re-derived from
memory.

## Decision / impact

- **DNP3 PCAP emitter = hand-built** (`substation/emit/dnp3_pcap.py`): link header +
  per-block CRCs + transport + application bytes, framed with scapy `Ether/IP/TCP`.
  Reuses the same synthetic-TCP-stream approach as the Modbus emitter (handshake →
  PSH/ACK data → FIN), so captures parse cleanly for the Tier-2 Zeek fidelity check.
- The **same scenario event model** drives the JSON and PCAP emitters (`PRD.md`
  §6.1), so the two cannot drift — identical guarantee to Modbus, different wire
  encoder.
- **Friction noted** for `docs/adding-a-protocol.md`: the per-protocol PCAP path is
  not uniform (scapy contrib for Modbus, hand-built for DNP3, hand-built/template
  expected for S7), and the synthetic-TCP-stream framing is currently duplicated per
  emitter — a candidate for a shared `emit/_tcp.py` helper.

## Nothing blocked

scapy + network available; CRC/layout verified against an authoritative capture.
No escalation needed.
