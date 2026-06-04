# Adding a protocol (placeholder)

A finite, ordered checklist for adding a new protocol to Substation will live
here, derived from the DNP3/S7 experience (`ENGINEERING_CHECKLIST.md` Phase 5).

**Status:** placeholder — the ordered checklist is written in Phase 5. The notes
below are raw friction captured while adding DNP3 (Phase 3), to feed that checklist.

## DNP3 friction notes (Phase 3 — feed into the Phase-5 checklist)

The DNP3 slice reused the Modbus pattern end-to-end. What was **mechanical** (good):
the scenario model + loader, the typed event dataclass, the shared "one model →
`event_to_dict` (JSON) + `write_pcap` (PCAP)" split, the metadata-driven registry +
contract harness (D1–D4 were auto-discovered with **zero** test-code changes), and
the coverage generator. The friction worth smoothing before the next protocol:

1. **The emit layer was Modbus-shaped.** `emit/json_emitter.py` and
   `emit/pcap_emitter.py` were named generically but imported `ModbusEvent`
   directly. Adding DNP3 required generalizing the JSON writer to take
   already-rendered **envelope dicts** (`write_jsonl(records, …)`) and moving the
   per-protocol `event_to_dict` into each `protocols/<proto>.py`, then dispatching
   in `emit/__init__.py` via a `{Protocol: (build_events, event_to_dict, write_pcap)}`
   table. *Checklist item:* a new protocol should only need to add a
   `protocols/<proto>.py` (model + `build_events` + `event_to_dict`) and a PCAP
   writer, then register the triple — no edits to the JSON writer.

2. **PCAP fidelity is not uniform across protocols.** Modbus uses
   `scapy.contrib.modbus`; **scapy 2.7.0 ships no DNP3 layer** (spike 05), so DNP3's
   PCAP is hand-built bytes (data-link + transport + application, with the DNP3 CRC
   verified against a real capture). S7 is expected to be hand-built/template too.
   *Checklist item:* run the scapy-capability spike **first** and record the verdict;
   budget for a hand-built encoder + a CRC/parse-fidelity check against a real trace.

3. **The synthetic-TCP-stream framing is duplicated per emitter.** Both
   `pcap_emitter.py` (Modbus) and `dnp3_pcap.py` (DNP3) carry a near-identical
   `_TcpFlow` (handshake → PSH/ACK data → FIN, per-flow seq/ack, deterministic
   MAC/ISN). *Checklist item:* extract a shared `emit/_tcp.py` so a protocol emitter
   only supplies "bytes for this message" — do this when S7 lands rather than
   triplicating it. (Deferred here to avoid perturbing the byte-stable Modbus PCAP.)

4. **Request/response shape differs from Modbus.** Modbus echoes the function code
   on the response; DNP3 does not — a request is `READ`/`OPERATE`/… and its reply is
   `RESPONSE` (0x81) with a separate IIN, plus outstation-initiated
   `UNSOLICITED_RESPONSE` (0x82) with **no** request. The event model classifies the
   master vs outstation **by actor role** (not by exchange source/target) so the
   master is always the TCP originator and an unsolicited response is a single
   `is_orig=false` event. *Checklist item:* the per-protocol model decides
   request→response synthesis and direction; don't assume the Modbus 1:1
   request-echo-response shape.

5. **`action_class` needs a per-protocol mapping + a "responses inherit" rule.**
   DNP3 lumps output/device/reporting control under `control`, so the per-command
   detections key on `func_name`, not `action_class`. Solicited responses inherit the
   request's verb. *Checklist item:* document the `func → action_class` table in
   `docs/schema.md` alongside the frozen `detail`, and state the response rule.
