# Event-log JSON schema (placeholder)

This document will be the binding contract for Substation's `.jsonl` event log:
the normalized envelope (`PRD.md` §6.3) plus per-protocol `detail` objects modeled
on **ICSNPP** fields.

**Status:** placeholder. Frozen per protocol in Phase 1 (Modbus first).

**VERIFY before freeze:** exact ICSNPP field names and per-protocol detail-log
shapes against the *current* parsers — confirmed, never guessed from memory.
Phase 0 spike notes (Sigma offline evaluation mechanism, scapy capability, ICSNPP
fields) will be recorded here.
