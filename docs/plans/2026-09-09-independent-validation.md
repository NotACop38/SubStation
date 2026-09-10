# Independent validation, site policy and dependency evidence

Authorized by the user's request to implement the four follow-up recommendations
and merge after review. Base: `f6f33b76d37f7a7f2aec7a405ab2f2def7bca29b`.

## Outcomes and decisions

1. **Modbus sensor import and field comparisons.** Accept bounded ICSNPP
   `modbus_detailed.log` JSON/TSV. Native detailed records describe transactions,
   not individual packets: emit explicitly marked request/response projections
   only where the record supports them. Reject ambiguous/unmatched input and
   unsupported shapes, without partial output. Compare the supported core Modbus
   function fields, values, transaction identity and exception outcomes in Tier 2.
   Packet timing equivalence is outside the transaction log's information content.
2. **Site policies.** Validate a versioned YAML policy for Modbus writer, target,
   unit, address-space and complete-span permissions, and DNP3/S7 command channels.
   Generate ordinary Sigma with deterministic provenance. Use the same compiler
   for exported rules and `detect --policy`; preserve the bundled demo defaults.
3. **Independent regression corpus.** Derive bounded captures from CISA ICSNPP's
   independently authored Modbus test trace. Preserve protocol payloads, sanitize
   network identifiers and timestamps, retain the BSD license/notice and source
   revision/hashes, and record the exact transformation. Commit safe derived
   captures and normalized logs with explicit case labels and TP/FP/FN/TN metrics.
   Separate upstream benign operations from policy counterfactuals and exception
   indicators; do not call this a representative field-effectiveness measurement.
4. **Dependency evidence.** Replace version-only installation with a complete
   hash-checked lock and explicit regeneration. Record distribution dependency
   metadata; derive runtime/dev reachability and transitive CycloneDX relationships
   for the declared environment. Reject missing dependencies, stale metadata and
   invalid hashes. Keep regeneration/network access outside ordinary SBOM builds.

## Sequence and completion evidence

- Implement and test import, including independent values, malformed TSV/JSON,
  ambiguous records, changed fields and exception responses; commit the slice.
- Implement policy compiler/CLI and independent interval/channel oracles; commit.
- Add attributed external corpus, regeneration, offline report, Tier-1 regressions
  and native Tier-2 reparse checks; commit.
- Add locked artifact hashes, metadata and complete dependency graph, real pip
  hash-rejection evidence and clean installation; commit.
- Update PRD, checklist, user guides and packaging. Check public artifacts for
  secrets, local paths and inappropriate traffic. Run full `make ci`, complete
  native `make verify`, and installed-wheel user flows. No GitHub Actions.
- Push through the mandatory pre-push gate, review the complete base-to-head PR,
  resolve findings, wait for the existing automated security review, and merge.

## Source anchors

- CISA ICSNPP Modbus current main checked as
  `27f22b41fd9839c0bad1b98df9c6289e578fd02a`; `scripts/main.zeek`,
  `testing/traces/modbus_example.pcap`, `LICENSE.txt` and `NOTICE.txt`.
- pip secure installs: https://pip.pypa.io/en/stable/topics/secure-installs/
- CycloneDX relationships: https://cyclonedx.org/use-cases/software-dependencies/

All processing remains files-only. No capture replay, live device access, listener
activation, paid service or cloud CI is required.
