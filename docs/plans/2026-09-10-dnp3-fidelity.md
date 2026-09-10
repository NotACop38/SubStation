# DNP3 message and detail fidelity

Base: `44c4becc5222bc11d60196939ad639eb7d091713`. Continue the authorized
review, implementation and GitHub merge workflow.

The standard Zeek DNP3 log overwrites consecutive requests and omits direction.
Use individual parser callbacks for the verification oracle; do not construct a
sensor importer that pretends this transaction log preserves every message.

1. Record each decoded application header and its associated object/control
   details, including connection ports, direction, function and response IIN.
   Compare messages in order within each connection, including unsolicited and
   no-response messages. Preserve explicit limitations for timing and payloads.
2. Reproduce and fix disagreements against current Zeek/ICSNPP, including CROB
   operation names. Exercise nonzero response indicators, packed binary objects,
   control-index and field-width boundaries, and consecutive no-response requests.
3. Add mutation checks so missing, duplicated, reordered or altered observations
   fail. Reject ignored scenario parameters exposed during this work.
4. Update the schema/evidence guides and qualification record. Run focused tests,
   full local CI and complete native Tier 2, review the full diff and public
   artifacts, then push through the required hook, review and merge the PR.

No detection expansion, ATT&CK remapping, live interfaces, or cloud CI. General
DNP3/S7 sensor import, SIEM equivalence and representative field data remain
separate qualification work.
