# Import sensor logs, apply site policy, and inspect regression evidence

Substation now has an offline path from independently produced Modbus logs to
policy-specific Sigma results. Every rule remains experimental. This is a
bounded sensor adapter and regression corpus, not a qualified SIEM deployment.

## Modbus import

```sh
substation import-modbus modbus_detailed.log --out events.jsonl
substation validate events.jsonl
substation detect events.jsonl --policy site.yaml
```

The importer accepts native ICSNPP `modbus_detailed.log` in Zeek JSON or standard
TSV. It supports matched transactions for functions 1, 2, 3, 4, 5, 6, 15 and 16:
read coils/discrete inputs/holding registers/input registers, and single/multiple
coil/register writes. It validates connection addresses, field types, vector
lengths and exception outcomes. Numeric values stay in observed order.

ICSNPP combines a request and response into one transaction record. Substation
projects it into two explicitly marked rows sharing the sensor's transaction
`ts`. `observation` contains source `icsnpp-modbus`, kind `transaction_projection`,
timestamp `transaction`, and the physical input line. These are not packet
arrival times. Read response addresses/quantities come from the transaction;
write ACKs do not invent response values. Auxiliary padding/raw data and extended
function details are outside this adapter's comparison scope.

Unmatched or unknown-function records are rejected: the detailed log omits
`is_orig`, and a low function byte alone cannot identify the sending endpoint.
Unsupported functions, malformed headers, duplicate JSON/YAML keys, invalid UTF-8,
nonfinite timestamps and ambiguous records fail the whole import. The bounded
reader requires regular files (64 MiB / 100,000 input lines); output is also
bounded to 64 MiB / 100,000 projections. `--out` atomically replaces its destination
only after all inputs validate. No output is published on a parsing failure.

The field mapping was checked against [ICSNPP Modbus's pinned source](https://github.com/cisagov/icsnpp-modbus/blob/27f22b41fd9839c0bad1b98df9c6289e578fd02a/scripts/main.zeek).
Its parser matches the older pin already used by the Tier-2 runner; changes
between these revisions only affect the upstream README.

## Site permissions and portable Sigma

Profiles require explicit values; YAML anchors and aliases are rejected before
object construction to prevent expansion beyond the input byte limit.

Start with `detections/policies/bundled-demo.yaml`, replace the example addresses
and permissions, then select it explicitly. The default demo retains its existing
example rules. Site profiles require all five channel lists; an empty list permits
no channel for that rule. An empty Modbus write list permits no writes.

```yaml
schema: substation-site-policy/v1
name: example-site
modbus:
  writes:
    - sources: [192.0.2.10]
      destination: 192.0.2.50
      port: 502
      units: [1]
      address_space: holding-register
      ranges: [{start: 40, end: 49}]
channels:
  D1: []
  D2: []
  D3: []
  S1: []
  S2: []
```

Addresses are literal IPv4/IPv6; ranges are inclusive, zero-based Modbus offsets.
`address_space` is `coil` or `holding-register`. A complete write must fit within
one grant, with matching source, destination, service, unit and function family.
Overlapping/adjacent ranges within that grant are merged. Permissions in separate
grants do not combine to authorize a span crossing their boundaries. Single-write
functions require quantity 1. Multiple writes are bounded by protocol limits.

D1/D2/D3/S1/S2 channel entries each use `sources`, `destination`, and `port`.
They authorize only the commands already selected by the corresponding rule.
M2's anomaly predicate is unchanged. These IP-based permissions cannot establish
whether an approved host has been compromised. Profiles do not reconfigure the
stateful Tier-2 Zeek baselines.

```sh
substation policy compile site.yaml --out site-rules
substation detect events.jsonl --policy site.yaml --detection M1 M2
```

The compiler produces seven standard Sigma YAML files plus `manifest.json` in a
new directory. Export and `detect --policy` use the same compiled rule bytes.
Rule IDs derive from the base ID and profile digest; metadata records both policy
and source rule hashes. Permissions use portable equality/range selections, with
bounded quantity enumeration to enforce complete spans without custom fields.
Backend translation and field mapping still require separate qualification.

## Independent corpus

```sh
make corpus
make verify VERIFY_ARGS='--native --require-complete'
```

The [attributed corpus](../tests/data/corpus/modbus/README.md) preserves selected
payload bytes from an external analyzer test trace. Tier 1 verifies artifact
hashes, schema and per-event labels, then reports TP/FP/FN/TN, precision, recall
and false-positive rate. Tier 2 reparses the PCAPs and compares independent values,
spans, identities and exception outcomes with the committed normalized logs.

The three cases reuse 22 observations for 42 event evaluations. M1 has two labeled
positives under a deny-policy counterfactual; M2 has one exception indicator.
This is deliberately small test evidence. It does not measure production rates,
validate DNP3/S7 imports or provide an external corpus for stateful Zeek rules.
Eight core Modbus scenarios receive field comparisons; the illegal-function
scenario and S7 remain explicitly scoped to request tuple/count comparisons.
DNP3 now has message and detail comparisons, described below.
Packet timing, all protocol extensions and actual device behavior remain unqualified.

## DNP3 fixture fidelity

`make verify` observes individual Zeek parser events for every bundled DNP3
scenario and two dedicated boundary fixtures. It compares both directions,
connection addresses and ports, message order within each connection, function
codes/names, response IIN, object types/ranges/counts and CROB control fields.
Details stay attached to their message; dropped, duplicated, reordered or changed
observations fail, as do decoder diagnostics. Unsolicited responses and consecutive
no-response requests are included.

This uses a verification observer because the standard `dnp3.log` can overwrite
consecutive requests and omits direction. ICSNPP's object log also filters out
unsolicited responses and most request functions. A general DNP3 importer cannot
recover information absent from these logs. The observer is a fixture oracle,
not a supported sensor import format.

Boundary fixtures cover packed binary outputs, all seven supported object types,
16-bit ranges/indices, 32-bit control times, nonzero IIN, and single-frame limits.
These checks caught and corrected operation-label, IIN and point-width mismatches.
New JSON uses ICSNPP's spaced operation names (`Latch On`, for example); scenario
input continues to accept underscore spellings. `iin` follows Zeek's numeric
representation: `0x0102` corresponds to wire octets `01 02`.

The comparison does not qualify timing, application/transport sequence semantics,
point values, all function-specific payload requirements, real equipment behavior
or detection effectiveness. See the [source and regression record](spikes/08-dnp3-message-fidelity.md).

## Dependency evidence

`make dev` installs wheel artifacts from the exact lock with pip's `--require-hashes`
and `--only-binary=:all:` (no dependency source builds), installs the local
editable package without dependency resolution/build isolation, then runs `pip
check`. A clean install verifies artifact hashes; already installed packages are
not rehashed by pip. For a fresh verification, create a new virtual environment.
The initial pip bootstrap is supplied by the Python/venv installation.

`make lock` is an explicit network operation. It preserves existing version pins,
fetches official PyPI hashes, selects a compatible wheel, verifies its downloaded
hash, reads `METADATA` without executing package code, and checks dependency
closure before updating the lock and `requirements.metadata.json`. Review those
files together. A new Python/OS combination may need regenerated metadata and
additional version pins; hash mode fails when an unpinned dependency is required.

The offline CycloneDX builder lists all 53 locked packages and complete runtime/dev
relationships for the recorded marker environment, including explicit leaves.
It evaluates markers and extras, rejects missing/version-conflicting dependencies,
and distinguishes unreachable locked inventory from the resolved graph. Selected
wheel hashes identify the artifacts; other platform artifacts are allowed by the
lock but are not falsely claimed as inspected wheels. The evidence is a reviewed
source record, not a signature or a scan of the current machine's installed files.
Only dependency declarations affect its input fingerprint, so a release version
bump does not require network regeneration.

The secret scanner's reviewed digest exceptions bind exact source lines to exact
paths and the hexadecimal-entropy detector. The committed fingerprint file uses
no blanket file/path/field exclusion. Changing a digest or its line content
requires a new review. All flagged values were verified artifact, metadata,
source-revision or payload hashes. The existing documented unused diskcache
advisory acceptance remains in place.
