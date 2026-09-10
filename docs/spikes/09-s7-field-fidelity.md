# S7 field and response fidelity — 2026-09-10

S7 validation now compares every modeled detail with independent ICSNPP output,
including both directions, addresses/ports and order within each connection/log.
It checks COTP CR/CC plus each application's DT frame; S7 headers, errors and
subfunctions; SZL method/ID/name/index/return status; transfer fields; and
S7-plus version/opcode/function. Missing, duplicate, reordered or changed rows
fail. Decoder diagnostics also fail the Tier-2 check.

## Source and representation

The live upstream head checked on this date was ICSNPP S7comm **1.3.0**, commit
`7ebeb03a0f954541369361651d1c27d09a64b5a3`, also used for the native Zeek build.
Sources: [log records](https://github.com/cisagov/icsnpp-s7comm/blob/7ebeb03a0f954541369361651d1c27d09a64b5a3/scripts/icsnpp/s7comm/main.zeek),
[value tables](https://github.com/cisagov/icsnpp-s7comm/blob/7ebeb03a0f954541369361651d1c27d09a64b5a3/scripts/consts.zeek),
and [decoder callbacks](https://github.com/cisagov/icsnpp-s7comm/blob/7ebeb03a0f954541369361651d1c27d09a64b5a3/src/s7comm-analyzer.pac).

**Verification-build patch:** the unmodified parser decoded the same Start Upload
block length as both 0 and 7. Its `get_number` copied length-delimited bytes into
an unterminated 32-byte stack buffer and passed it to `atoi`; it also lacked a
copy bound. The filename helper read byte 8 even for an empty filename. The
reviewed `scripts/verify/patches/icsnpp-s7comm-bounds.patch` replaces numeric parsing
with checked decimal accumulation, reports invalid/overflowed input as a Zeek
diagnostic, and checks filename length before reading byte 8. No PDU-reference
decoding or protocol field mapping is changed by the patch.

`scripts/verify/build_s7.py` verifies the upstream commit and clean checkout,
copies the committed source into a new output directory, applies the patch and
builds against installed Zeek headers. It records source/patch/version provenance
and preserves upstream license files. Existing source checkouts are untouched.
The plugin is labeled `substation-bounds-v1`; complete verification requires this
marker. Results apply to **1.3.0 plus this local patch**, not pristine upstream.
The marker is a compatibility check, not cryptographic binary attestation.

**PDU reference compatibility:** the wire/model use big-endian, as does
[Wireshark's S7 dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm.c)
(`hf_s7comm_header_pduref`, `ENC_BIG_ENDIAN`). ICSNPP 1.3.0 explicitly reverses
these bytes in its callbacks. The oracle applies that fixed transform to its
expected parser representation: model reference 1 must appear as 256. It never
accepts either byte order opportunistically. Recheck this compatibility rule
before qualifying another parser version. The normalized schema retains the
wire value; this comparator is not a general S7 log importer.

## Defects corrected

- ACK-Data and User-Data replies now include their encoded success error fields.
- Read-SZL requests now include the encoded `0xff` return code and its name.
- Transfer requests include status and session fields. Responses omit absent
  status rather than fabricating it; upload status, session and empty block
  length reflect the actual encoded fields.
- All defined SZL names are represented; high ID bits retain their value while
  the low byte selects the name, matching ICSNPP.
- Block numbers require exactly five ASCII decimal digits. The supported filename
  has fixed offsets (`_<type:2><number:5>P`); a one-byte total length does not make
  the embedded number variable-width. Invalid input fails before artifact writes.

`tests/data/fidelity/s7/operations.yaml` covers all 19 operation tokens, five
PLC-control services, block-number/type edges, SZL/index extremes and S7-plus
versions 1–3. It is included in complete Tier 2. The native pytest check also
exercises all 256 SZL low-byte names/defaults and the reference 255→256 boundary.
Hand-authored observations test the comparator without relying on a decoder;
native observations are mutated to verify every compared field is significant.

## Limits

No timing or cross-log arrival ordering claim, process-tag value semantics,
valid uploaded/downloaded program, complete transfer session, physical PLC
behavior, S7-plus integrity, encryption or sensor normalization is qualified.
The synthetic bodies remain minimal parser fixtures. Native Zeek results do not
qualify a Docker image. See [execution instructions](../verify-s7.md).
