# Adding a protocol

A **finite, ordered checklist** for adding a whole new protocol to Substation
(post-v1: IEC-104, EtherNet/IP-CIP, BACnet, … — `PRD.md` §2). It is derived from
actually adding DNP3 (Phase 3) and S7 (Phase 4) on top of the Modbus slice; the
raw friction that shaped it is preserved at the bottom. Each detection you ship
for the new protocol must still satisfy the **Detection Contract** — once the
protocol plumbing below is in place, follow
[`adding-a-detection.md`](./adding-a-detection.md) per detection.

> Scope note (`PRD.md` §2): the v1 set (Modbus/DNP3/S7) is closed; new protocols
> are post-v1 contributions. Confirm scope with the lead before starting.

## Ordered checklist

1. **Spike the parser fields (VERIFY).** Pull the **current** Zeek/ICSNPP field
   names and per-protocol detail-log shapes from the live parser — never from
   memory (`CLAUDE.md` VERIFY gate). Write a spike note under `docs/spikes/`
   recording the verified fields, value tables, and the source + date (as
   `01`/`04`/`06` do).

2. **Spike scapy capability (VERIFY).** Determine whether scapy can assemble this
   protocol's PDUs or whether you hand-build bytes / splice template PCAPs. Record
   the verdict per protocol in a spike note (`02`/`05`/`07`). Budget for a
   hand-built encoder + a CRC/parse-fidelity check against a **real** capture if
   scapy lacks a layer (DNP3 and S7 both did).

3. **Freeze the schema `detail`.** Add the protocol to the event-log JSON Schema:
   - extend `docs/schema.md` with the envelope (`PRD.md` §6.3) + this protocol's
     `detail` from the **verified** spike fields, and document its
     `func → action_class` mapping and the "responses inherit the request's verb"
     rule;
   - add the `proto == <name>` branch + `<proto>_detail` `$defs`
     (`additionalProperties: false`) to `substation/schema/event-log.schema.json`;
   - add golden events at `tests/data/events/<proto>/valid.jsonl` (validated by
     `make schema`).
   Also add the protocol to the `Protocol` enum (`substation/scenarios/model.py`)
   and the loader/registry protocol sets.

4. **Build the shared event model + emitters.** Add `substation/protocols/<proto>.py`
   with the typed event dataclass, `build_events()` (scenario → events), and
   `event_to_dict()` (event → envelope dict). **One** model must drive **both**
   emitters so PCAP and JSON cannot drift (`PRD.md` §6.1):
   - JSON: reuse the shared `write_jsonl` (it validates against the frozen schema);
   - PCAP: add a writer (scapy contrib, or hand-built bytes per the step-2 verdict);
   - register the `(build_events, event_to_dict, write_pcap)` triple in
     `emit/__init__.py`. No edits to the JSON writer should be needed.
   Keep the **files-only invariant** (`PRD.md` §6.4): emission must open no
   sending socket (the guard + `tests/test_files_only.py` enforce it).

5. **Author the benign baseline scenario.** `scenarios/<proto>/benign-baseline.yaml`
   modelling a legitimate master/HMI/EWS and **continuous benign traffic**
   (`PRD.md` §8) — the canonical quiet ground truth every detection for this
   protocol must stay silent on. List `X1` in its `exercises.quiet` so the
   cross-protocol baseline learns this protocol's legitimate talkers/pairs too.

6. **Add detections per the Detection Contract.** For each target detection,
   follow [`adding-a-detection.md`](./adding-a-detection.md): rule → verify ATT&CK
   IDs → anomalous + benign scenarios → register → harness → doc (with FP profile)
   → coverage. Ship at least one **Sigma** and one **Zeek** detection so both rails
   are exercised (`PRD.md` §6.5), mirroring Modbus (M1/M2 Sigma + M3 Zeek).

7. **Add an emitter test.** `tests/test_emit_<proto>.py` proving one wire PDU per
   JSON event, matching function codes/order, valid framing/CRCs, and byte
   determinism (mirror `test_emit_dnp3.py` / `test_emit_s7comm.py`).

8. **Regenerate coverage + run the gate once.** `make coverage-build` then
   `make ci` (green). Record any friction you hit in the notes below so the next
   protocol is smoother, and open a PR with the template.

## Done when

The new protocol runs scenario → PCAP + JSON → detections → harness → coverage
rows end to end; every shipped detection satisfies the Detection Contract; the
files-only invariant holds; and `make ci` is green.

-----

## DNP3 friction notes (Phase 3 — captured while adding DNP3)

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

## S7 friction notes (Phase 4 — captured while adding S7)

S7 confirmed the checklist above and added two protocol-specific lessons:

6. **Layered framing (TPKT/COTP/S7comm) needs a connection handshake.** Unlike
   Modbus/DNP3, S7 runs S7comm over COTP over TPKT over TCP/102, with a COTP CR/CC
   handshake *per connection* before any S7 PDU. The emitter synthesizes that
   handshake once per connection; the event model still emits one TPKT/S7 PDU per
   JSON event. *Checklist item:* budget for multi-layer framing and any
   per-connection handshake when the transport is not "TCP + one PDU per message".

7. **Integrity-protected variants are dissector-derived, not spec-derived.**
   S7comm-plus is integrity-protected and has no open spec, so its opcode/function
   offsets come from the ICSNPP parser + Wireshark dissector and are a Tier-2
   fidelity item (spike 07). *Checklist item:* for protocols without an open spec,
   ground semantics in the live parser/dissector and flag anything unverifiable as
   a Tier-2 fidelity check rather than asserting it.
