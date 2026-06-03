# Spike 2 — scapy Modbus PDU capability

**Status:** RESOLVED. **Verdict: use scapy** for Modbus PCAP emission — no
hand-built PDUs or template-PCAP splicing required for v1 Modbus.
**VERIFY gate:** `PRD.md` §6.4 / §7 — "scapy protocol-layer capability (Modbus first)."
**Date:** 2026-06-03 · **scapy:** 2.7.0 (pinned in `pyproject.toml`).

## Goal

Decide whether scapy can assemble the Modbus/TCP PDUs the simulator needs
(read/write coils & registers, exception responses), or whether we must hand-build
PDUs / splice template PCAPs (`PRD.md` §8 risk: "scapy's Modbus is uneven").

## Method

Throwaway probe (`/tmp`, not committed): imported `scapy.contrib.modbus`, checked
class availability for every PDU we need, then **built each PDU, serialized it with
`raw()`, and re-dissected the bytes** to confirm a clean round-trip. Also wrote a
full `IP/TCP/MBAP/PDU` packet to a `.pcap` with `wrpcap` and read it back.

## Results

`scapy.contrib.modbus` is **present** and ships every class we need. All 8 target
PDUs build + round-trip cleanly (MBAP length/`protoId` auto-computed):

| PDU                                   | Func | Result | Example bytes (hex)              |
| ------------------------------------- | ---- | ------ | ------------------------------- |
| Read Coils — request                  | 0x01 | OK     | `000100000006010100000010`      |
| Read Holding Registers — request      | 0x03 | OK     | `00020000000601030000000a`      |
| Read Holding Registers — response     | 0x03 | OK     | `000200000009010306000100020003`|
| Write Single Coil — request           | 0x05 | OK     | `00030000000601050007ff00`      |
| Write Single Register — request        | 0x06 | OK     | `0004000000060106000100ff`      |
| Write Multiple Coils — request         | 0x0F | OK     | `000500000008010f0000000801ff`  |
| Write Multiple Registers — request     | 0x10 | OK     | `00060000000b0110001000020411112222` |
| Read Holding Registers — **exception** | 0x83 | OK     | `000200000003018302` (exceptCode=2) |

`wrpcap` + `rdpcap` round-trip preserved the Modbus layer (files-only — no socket).

## scapy field names (exact — they are NOT the obvious guesses)

Recorded so the encoder doesn't waste time rediscovering them:

| Class                                       | Field names                                              |
| ------------------------------------------- | -------------------------------------------------------- |
| `ModbusADURequest` / `ModbusADUResponse`    | `transId, protoId, len, unitId`                          |
| `ModbusPDU01ReadCoilsRequest`               | `funcCode, startAddr, quantity`                          |
| `ModbusPDU03ReadHoldingRegistersRequest`    | `funcCode, startAddr, quantity`                          |
| `ModbusPDU05WriteSingleCoilRequest`         | `funcCode, outputAddr, outputValue`                      |
| `ModbusPDU06WriteSingleRegisterRequest`     | `funcCode, registerAddr, registerValue`                  |
| `ModbusPDU0FWriteMultipleCoilsRequest`      | `funcCode, startAddr, quantityOutput, byteCount, outputsValue` |
| `ModbusPDU10WriteMultipleRegistersRequest`  | `funcCode, startAddr, quantityRegisters, byteCount, outputsValue` |
| `ModbusPDU03ReadHoldingRegistersError`      | `funcCode, exceptCode`                                   |

Exception classes follow the pattern `ModbusPDU<NN><Name>Error` with `exceptCode`;
the response ADU sets the high bit of the function code automatically (0x03 → 0x83).

## Gotchas / notes

- **Reserved/undefined function codes (M2):** the named PDU classes don't cover
  truly *undefined* codes. For "illegal/abnormal function code" scenarios, build a
  raw PDU with `ModbusADURequest()/Raw(load=bytes([func, ...]))` (scapy `Raw` layer)
  rather than a named class. Confirmed feasible; flagged for the encoder.
- **Environment quirk (not a scapy limitation):** importing `scapy.contrib.modbus`
  initially failed because scapy probes optional `cryptography`, whose Rust binding
  needed `_cffi_backend`. Fixed by installing `cffi`. Does **not** affect Modbus
  assembly; noted so the next person isn't surprised. We do not depend on
  `cryptography` for Modbus.

## Decision / impact

- **Modbus PCAP emitter = scapy `contrib.modbus`.** Hand-built/template-splice paths
  are **not** needed for Modbus and stay reserved for DNP3/S7 (their own spikes).
- The PCAP emitter and the JSON emitter are driven from the same scenario model
  (`PRD.md` §6.4); the field-name table above feeds the Modbus encoder.

## Nothing blocked

scapy installed and exercised successfully. No escalation needed.
