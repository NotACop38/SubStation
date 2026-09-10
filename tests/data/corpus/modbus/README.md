# External Modbus regression corpus

These two small captures are derivatives of CISA ICSNPP Modbus's analyzer test
trace at the revision in `manifest.json`. They were authored outside Substation's
simulator. BSD-3-Clause attribution and the upstream notice accompany the data.

`core.pcap` retains the first ten core transactions (eight reads, a single-coil
write, a single-register write); `exception.pcap` retains the two packets of an
illegal-address response. The latter is a partial connection, as in upstream.
Every selected TCP application payload byte is unchanged. Network headers are
rebuilt with documentation addresses, synthetic MACs/ports, relative sequence
numbers, fixed windows, no options, and timestamps shifted to start at 1 second.
Per-packet indices and payload hashes record the transformation. The script never
sends packets: `scripts/corpus/derive_modbus.py --source CHECKOUT --out NEW_DIR`.

The JSONL files come from native Zeek + ICSNPP, with fixture connection UIDs.
`observation` marks transaction projections and transaction timestamps. Fields
are rechecked from PCAP by `make verify`; Tier 1 checks hashes, schema and labels
with `make corpus` and tests. Regeneration requires review before updating hashes
or labels. The source trace and parser were checked against the manifest revision;
its parser is byte-identical to the runner's older pinned Modbus parser revision.

Labels are per event and per named rule. An empty positive list means all events
are negative for that rule; unlisted rules are unevaluated. M1's positive case
uses the same upstream bytes with a deny-all write policy. M2's positive is an
exception indicator, not evidence of malicious intent. Reported precision,
recall and false-positive rate are fractions over these explicit labels; an
undefined denominator is `null`. Counts are 42 event evaluations across three
cases using 22 unique observations. These are small regression tests, not field
traffic, confirmed attacks, or production effectiveness estimates. DNP3/S7 and
stateful Zeek rules do not yet have an external labeled corpus.
