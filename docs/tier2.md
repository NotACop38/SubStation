# Tier 2: validation in real Zeek

Tier 1 proves the rules against Substation's own JSON. Tier 2 checks that the
traffic is real: it parses every generated PCAP with pinned Zeek and CISA ICSNPP
parsers, compares what they decode with the JSON event log, and runs the Zeek
rules in the engine they were written for (`docs/design.md` §6.2).

```sh
make verify VERIFY_ARGS=--require-complete
```

`--require-complete` turns any skipped check into a failure. Use it whenever you
claim that Tier 2 passed; releases require it.

## What it checks

| Check | What is compared |
|---|---|
| Modbus fields | ICSNPP `modbus_detailed` transactions for every Modbus scenario: connection identity, address spans, values and exception outcomes. The illegal-function scenario compares request counts only: ICSNPP logs undefined functions without direction and cannot pair them with their exception responses. |
| External Modbus corpus | The [attributed corpus](../tests/data/corpus/modbus/README.md) PCAPs are reparsed and compared with their committed normalized logs. |
| DNP3 messages | A Zeek observer ([`dnp3-observe.zeek`](../scripts/verify/dnp3-observe.zeek)) records each parsed message: direction, connection order, function, IIN and object/control fields, for every DNP3 scenario and two boundary fixtures. |
| S7 fields | ICSNPP S7comm logs: COTP frames, direction and order, S7 headers and every modeled detail field, for every S7 scenario and a fixture covering all modeled operations. |
| Decoder diagnostics | Any `weird.log` entry fails the comparison. |
| Zeek rules | M3, M4, D4, S3 and X1 run over every scenario that lists them in `exercises`; each must raise its notice on `fires` scenarios and stay silent on `quiet` ones. X1's learned baseline is derived from the benign baselines and injected with `redef`. |

Zeek truncates logged vectors to 100 elements by default; the runner raises that
limit ([`zeek-log-limits.zeek`](../scripts/verify/zeek-log-limits.zeek)) so long
register vectors compare in full. Suricata is reported as "no rules": none ship.

## Docker (default)

The runner uses the digest-pinned `zeek/zeek:8.2` image. It clones the Modbus and
DNP3 ICSNPP script packages at pinned commits into `.verify-cache/` on the host and
mounts them read-only; a cached clone is used only if it is exactly the pinned
commit with no local changes, hidden index flags or extra files, and is otherwise
cloned again.

The S7comm analyzer is a compiled C++ plugin, which the runtime image cannot
build. On first use the runner builds a local image,
`substation-verify/zeek-s7comm:<hash>`, from the pinned upstream commit plus the
reviewed bounds patch ([`zeek-s7comm.Dockerfile`](../scripts/verify/zeek-s7comm.Dockerfile)).
The tag hashes the Dockerfile, patch, pin and base image, so any change rebuilds
it. `make verify-image` builds it ahead of time. Analysis containers run with
`--network none`; only the image pull and parser fetches need network access.

| Option | Effect |
|---|---|
| `--require-complete` | Fail if any shipped check is skipped. |
| `--no-s7-build` | Do not build the S7 image; the S7 checks are then skipped. |
| `SUBSTATION_ZEEK_S7_IMAGE=<image>` | Use your own image with the S7 plugin instead of building one. It must pass the same plugin probe. |

## Native Zeek

A host with Zeek installed can run the same checks without Docker:

```sh
make verify VERIFY_ARGS='--native --require-complete'
```

For the S7 checks, build the patched plugin against the host's Zeek (needs Git,
CMake, a C++ compiler and Zeek development headers) into a new directory:

```sh
S7_BUILD_ROOT="$(mktemp -d)/qualified"
python scripts/verify/build_s7.py --out "$S7_BUILD_ROOT"
export ZEEK_PLUGIN_PATH="$S7_BUILD_ROOT/build"
export ZEEKPATH="$S7_BUILD_ROOT/source/scripts:$(zeek-config --zeekpath)"
make verify VERIFY_ARGS='--native --require-complete'
```

`build_s7.py` fetches the pinned commit (or takes `--source` pointing at a clean
checkout of it), refuses an existing output directory, and writes
`provenance.json` with the source commit, patch hash and Zeek version. With the
same environment, `make ci` also runs the native S7 pytest checks, which cover
every SZL low-byte name and PDU references crossing 255→256. Native results
qualify the host's Zeek, not the pinned Docker image.

## The S7 plugin and its patch

ICSNPP S7comm 1.3.0 (commit `7ebeb03a0f954541369361651d1c27d09a64b5a3`) has two
reproduced defects: numeric fields were parsed with `atoi` over an unterminated
stack buffer, so one Start Upload length decoded as both 0 and 7, and the
filename helper read past an empty filename. The reviewed patch
([`icsnpp-s7comm-bounds.patch`](../scripts/verify/patches/icsnpp-s7comm-bounds.patch))
bounds both without changing any field mapping. Details and sources are in
[spike 09](spikes/09-s7-field-fidelity.md).

The patched plugin identifies itself as `substation-bounds-v1`. The runner treats
the plugin as available only when `zeek -N` shows that marker **and**
`@load icsnpp/s7comm` succeeds; a plugin name alone is not enough. Results apply
to 1.3.0 plus this patch, not to pristine upstream.

ICSNPP 1.3.0 also reverses the bytes of the S7 PDU reference relative to the wire
and to Wireshark. The comparison applies exactly that transformation (model
reference 1 must appear as 256) and never accepts either byte order, so a parser
upgrade that changes this is caught.

## Evidence boundary

Tier 2 shows that independent parsers decode Substation's traffic to the fields
the JSON claims, and that the Zeek rules behave as declared on the bundled
scenarios. It does not qualify packet timing, complete session semantics, PLC or
outstation behavior, valid programs, S7comm-plus integrity or encryption, or a
general DNP3/S7 sensor importer. See [`validation.md`](validation.md) for the
latest recorded run.
