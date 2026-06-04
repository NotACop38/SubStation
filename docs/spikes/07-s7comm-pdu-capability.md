# Spike 7 — S7comm / S7comm-plus PDU construction capability

**Status:** RESOLVED. **Verdict: hand-build S7 PDUs** — scapy 2.7.0 ships **no**
S7comm/S7comm-plus/COTP application layer, so the S7 PCAP emitter assembles the
TPKT / COTP / S7comm bytes itself, with the **header layout verified byte-for-byte
against ICSNPP's own example captures**.
**VERIFY gate:** `PRD.md` §6.4 / §7 — "scapy protocol-layer capability" (per-protocol);
`PRD.md` §8 risk "scapy lacks solid S7comm/DNP3 layers" + "S7 complexity (no open spec)".
**Date:** 2026-06-04 · **scapy:** 2.7.0 (pinned in `pyproject.toml`).

## Goal

Decide whether scapy can assemble the S7comm/S7comm-plus PDUs the simulator needs,
or whether we hand-build them / splice template PCAPs (the route `PRD.md` §6.4
reserves for protocols scapy does not cover — explicitly anticipated for S7).

## Method

1. Enumerated scapy's contrib layers for an S7comm/COTP/TPKT module.
2. Since none exists, validated a **hand-built encoder** against real wire bytes:
   extracted the TCP payloads from ICSNPP-S7comm's own test captures
   (`testing/traces/snap7.pcap`, `s7ident.pcap`, `s7comm_plus.pcap`, via the
   `codeload` tarball) and confirmed our TPKT/COTP/S7comm **framing and header
   layout reproduce the real frames exactly**.

## Result 1 — scapy has no S7 layer

`scapy 2.7.0` `contrib/` ships `scada/iec104`, `scada/pcom`, `opc_da` — **no
s7comm, no COTP, no TPKT**. Confirms the `PRD.md` §8 risk. So S7 PCAP =
**hand-assembled bytes** framed in scapy's generic `Ether`/`IP`/`TCP` (the same
synthetic-TCP-stream approach as Modbus/DNP3).

## Result 2 — TPKT + COTP + S7comm framing (verified against `snap7.pcap`)

Every S7 message is `TPKT | COTP | S7comm`:

- **TPKT** (RFC 1006): `03 00 | LEN(2, big-endian)` — `LEN` is the **whole** TPKT
  unit incl. the 4-byte header. Verified: a 25-byte Setup-Communication packet is
  `03 00 00 19 …` (`0x0019 = 25`).
- **COTP data**: `02 f0 80` — length `0x02`, PDU type `0xf0` (DT Data), TPDU-NR
  `0x80` (EOT). Verified on every S7comm data packet.
- **COTP CR/CC** (connection handshake, verified against `s7ident.pcap`):
  `LI | PDU | DST_REF(2) | SRC_REF(2) | CLASS(1) | params…`, PDU `0xe0` = Connection
  Request, `0xd0` = Connection Confirm; params `c0 01 0a` (TPDU size), `c1 02 …`
  (calling TSAP), `c2 02 …` (called TSAP). The ICSNPP `cotp` event keys the PDU name
  on the **high nibble** (`0xe → CR Connection Request`, `0xd → CC Connection
  Confirm`).
- **S7comm header**: `32 | ROSCTR(1) | REDUNDANCY(2)=0000 | PDU_REF(2) | PARAM_LEN(2)
  | DATA_LEN(2)` then `PARAM || DATA`. **Verified** the header is **10 bytes** for
  Job-Request (`0x01`) and User-Data (`0x07`), and **12 bytes** for ACK / ACK-Data
  (`0x02`/`0x03`) — the latter inserts a 2-byte `ERROR_CLASS || ERROR_CODE` after
  `DATA_LEN`. Example (Setup-Comm ACK-Data response): `32 03 0000 0000 0008 0000
  0000 f0 …` — the `00 00` before the `f0` parameter is the error class/code.
- **S7comm parameter** begins with the **function code byte** (Job: `0x05` Write
  Variable, `0x29` PLC Stop, `0x28` PLC Control, `0x04` Read Variable, `0x1a`
  Request Download, `0xf0` Setup Communication). For **User-Data** the parameter is
  `00 01 12 | LEN | METHOD | FUNC | SUBFUNC | SEQ`, where `FUNC` carries the
  request/response nibble (`0x44` = Request CPU Functions, `0x84` = Response) and
  `SUBFUNC` (`0x01` = Read SZL). **Verified** against `snap7.pcap`'s Read-SZL
  exchange: request param `00 01 12 04 11 44 01 00`, data `ff 09 00 04 | SZL_ID(2) |
  SZL_INDEX(2)`.

## Result 3 — S7comm-plus framing (verified header; protected payload)

`s7comm_plus.pcap` frames are `TPKT | COTP DT | 72 | VERSION(1) | DATA_LEN(2) |
payload`. **Verified** the protocol id `0x72`, version byte and 2-byte data length
(e.g. `03 00 00 71 02 f0 80 72 03 00 62 …`, `0x0062 = 98` payload bytes). The
example capture is the **integrity-protected** S7-1500 variant, so its opcode /
function bytes are not in cleartext; we therefore build the **documented plaintext
header** (`72 | version | data_len | OPCODE(1) | … | FUNCTION(2)`) per the Wireshark
S7comm-plus dissector, with the `opcode` (`0x31/0x32/0x33`) and `function`
(`0x04bb` Explore, `0x04ca` Create Object, `0x04f2` Set Variable) **values** taken
from the verified ICSNPP `consts.zeek` tables (spike 06). This is the one place the
exact byte offsets are dissector-derived rather than capture-verified, and is flagged
below as the Tier-2 fidelity item.

## Decision / impact

- **S7 PCAP emitter = hand-built** (`substation/emit/s7comm_pcap.py`): TPKT + COTP
  (CR/CC handshake and DT data) + S7comm/S7comm-plus bytes, framed with scapy
  `Ether`/`IP`/`TCP` on a synthetic but well-formed TCP stream (SYN → PSH/ACK → FIN),
  so captures reassemble cleanly. Output is byte-deterministic.
- The **same scenario event model** drives the JSON and PCAP emitters (`PRD.md`
  §6.1: `substation/protocols/s7comm.py` `build_events` → `S7Event`), so the two
  cannot drift — identical guarantee to Modbus/DNP3, different wire encoder.
- **Tier-1 authority / Tier-2 fidelity boundary (documented honestly).** The Tier-1
  detections evaluate our **JSON** (whose `detail` carries the verified ICSNPP field
  *values* directly), so they do not depend on a real Zeek parse. The PCAP framing
  and S7comm header layout are capture-verified; the *inner parameter/data bodies*
  for functions absent from the example captures (Write Variable, PLC Stop, PLC
  Control, the download functions) and the s7comm-plus opcode/function offsets are
  built per the Wireshark dissector and are the subject of the **Tier-2 Zeek+ICSNPP
  fidelity diff** (Phase 2 target), exactly as DNP3's were (spike 05). Each emitted
  parameter still **begins with the verified function-code byte**, the field ICSNPP's
  `s7comm.log` keys `function_name` on.
- **Friction noted** for `docs/adding-a-protocol.md`: the synthetic-TCP-stream
  framing is now duplicated across three emitters (Modbus/DNP3/S7) — the candidate
  shared `emit/_tcp.py` helper is overdue.

## Nothing blocked

scapy + network available; framing/headers verified against authoritative captures.
No escalation needed.
