# Event-log JSON schema (placeholder)

This document will be the binding contract for Substation's `.jsonl` event log:
the normalized envelope (`PRD.md` §6.3) plus per-protocol `detail` objects modeled
on **ICSNPP** fields.

**Status:** placeholder. Frozen per protocol in Phase 1 (Modbus first).

**VERIFY before freeze:** exact ICSNPP field names and per-protocol detail-log
shapes against the *current* parsers — confirmed, never guessed from memory.

**Phase-0 spike findings** (recorded; nothing frozen yet):

- ICSNPP Modbus fields → `spikes/01-icsnpp-modbus-fields.md` (model the Modbus
  `detail` on `modbus_detailed.log`; re-pull against a pinned commit at freeze).
- scapy Modbus capability → `spikes/02-scapy-modbus-capability.md` (use scapy
  `contrib.modbus`).
- Sigma offline evaluation → `spikes/03-sigma-offline-evaluation.md` (Tier-1 harness
  walks the pySigma-parsed condition AST against `.jsonl`; no SIEM).
