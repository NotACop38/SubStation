# Run the rules on your own data

The bundled scenarios prove each rule against synthetic traffic. To run the rules
on your own network you need two things: sensor output in Substation's event
schema, and permissions that describe your site instead of the demo's example
addresses. This guide covers both. Every rule remains `experimental`; this is a
bounded adapter and policy compiler, not a qualified SIEM deployment.

```sh
substation import-modbus modbus_detailed.log --out events.jsonl
substation validate events.jsonl
substation detect events.jsonl --policy site.yaml
substation policy compile site.yaml --out site-rules
```

## Import ICSNPP Modbus logs

`substation import-modbus` reads CISA ICSNPP `modbus_detailed.log` files in Zeek
JSON or standard TSV and writes Substation-schema JSONL. It supports matched
transactions for the eight core functions: read coils, discrete inputs, holding
registers and input registers (1–4), and single and multiple coil and register
writes (5, 6, 15, 16). DNP3 and S7 sensor import is not available.

ICSNPP records a request and its response as one transaction. The importer
projects each transaction into a request event and a response event that share
the transaction's timestamp; `observation` marks them as a `transaction_projection`
from `icsnpp-modbus` and records the input line. These are not packet arrival
times. Read responses take their address and quantity from the transaction, and
write acknowledgements do not invent response values.

| Input | Behavior |
|---|---|
| Unmatched transactions and unsupported functions | Skipped and counted on stderr, because the log omits direction and a function byte alone cannot identify the sender. `--strict` fails the import instead. |
| Value vectors cut by the sensor | Zeek logs at most 100 vector elements by default. A vector of exactly that length, shorter than its quantity, is dropped and named in `observation.truncated_values`; the transaction is kept. Pass `--zeek-container-limit N` if your sensor uses another limit, or raise `Log::default_max_field_container_elements` on the sensor. |
| Malformed input | Invalid headers, field types, addresses, vector lengths or exception outcomes, duplicate keys, invalid UTF-8 and non-finite timestamps fail the whole import. |
| Size | Inputs must be regular files; each file and the combined output are capped at 64 MiB and 100,000 lines. |

`--out` replaces its destination atomically, and only after every input
validated; nothing is written on failure. The field mapping was checked against
[ICSNPP Modbus at a pinned commit](https://github.com/cisagov/icsnpp-modbus/blob/27f22b41fd9839c0bad1b98df9c6289e578fd02a/scripts/main.zeek).

## Describe your site

The allow-list rules (M1, D1–D3, S1, S2) ship with the demo's example addresses.
A site profile replaces them. Start from
[`detections/policies/bundled-demo.yaml`](../detections/policies/bundled-demo.yaml),
replace the addresses and permissions, and pass it explicitly with `--policy`:

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

- **Every list is explicit.** A profile must name all five channel lists; an empty
  list permits no channel for that rule, and an empty Modbus `writes` list permits
  no writes.
- **Modbus writes** are granted per source, destination, port, unit and address
  space (`coil` or `holding-register`), over inclusive, zero-based ranges. A write
  must fit entirely inside one grant; overlapping or adjacent ranges within a grant
  merge, but separate grants never combine to authorize a span across them.
  Single-write functions must have quantity 1.
- **D1, D2, D3, S1 and S2 channels** each take `sources`, `destination` and
  `port`, and authorize only the commands the corresponding rule selects.
- **Addresses** are literal IPv4 or IPv6; write IPv4-mapped IPv6 addresses in
  their IPv4 form.
- YAML anchors and aliases are rejected, so a small file cannot expand into a huge
  one.

M2's illegal-code predicate does not depend on the profile, and profiles do not
change the stateful Zeek rules (M3, M4, D4, S3, X1), whose baselines and
thresholds are Zeek `redef`s. IP-based permissions cannot tell whether an approved
host has been compromised.

## Detect and export

```sh
substation detect events.jsonl --policy site.yaml
substation detect events.jsonl --policy site.yaml --detection M1 M2
substation policy compile site.yaml --out site-rules
```

`detect --policy` compiles the profile into the seven Tier-1 Sigma rules and runs
them in-process. `policy compile` writes the same compiled rules as standard Sigma
YAML plus a `manifest.json` into a new directory, for a SIEM backend of your
choice; export and detection use the same rule bytes. Rule IDs derive from the
base rule ID and the profile digest, and the metadata records both hashes.
Permissions compile to portable equality and range selections, with span
coverage enumerated within protocol limits, so no custom fields are needed.

`make verify-sigma` compares the hits of the authored and exported rules with the
official pySigma SQLite backend. Its table contract and the reproduced NULL and
expression-depth limits are in
[spike 10](spikes/10-sigma-backend-qualification.md). Other backends and field
mappings need their own qualification.
