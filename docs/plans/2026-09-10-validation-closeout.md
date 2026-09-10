# Validation review closeout

Continue the authorized codebase review from the merged DNP3 fidelity work.
The core purpose remains an experimental, files-only detection regression pack.
Additional detections would amplify unqualified behavior; prioritize independent
checks of the existing output and rule exports.

1. Compare S7 request and response fields against the pinned native ICSNPP
   parser, covering all modeled operations and boundary parameters. Correct
   fabricated or omitted detail fields and reject unsupported encodings. Keep
   wire PDU references big-endian, with a documented compatibility check for the
   pinned parser's reversed reference representation. Check missing, extra,
   reordered and mutated observations, including COTP and S7-plus.
2. Exercise all seven authored and site-compiled Sigma rules with the official
   SQLite backend. Define the flattened-table contract and qualify actual hit
   identities on scenarios, external Modbus observations and policy boundaries.
   Record backend limitations explicitly; this is not a claim about other SIEMs.
3. Reconcile current qualification documentation and eliminate stale claims in
   active entry points. Keep representative operational traffic, full protocol
   semantics and Docker-image qualification distinct from local checks.
4. Review the full changes and public artifacts, run focused checks, local CI
   and complete native Tier 2, then open, review and merge a PR through the
   required pre-push gate. Verify GitHub and local main agree after merging.

No cloud CI, live interfaces, operational samples, or new exploit capabilities.

The complete S7 check exposed an upstream parser defect: non-terminated decimal
conversion produced nondeterministic block lengths, and empty filenames caused
an unchecked byte read. Include a minimal reviewed parser patch and reproducible
build helper; require its compatibility marker for complete verification. Record
this source change explicitly in the qualification boundary.
