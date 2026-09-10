# Tier-2 validation with Zeek and the S7 plugin

The default `make verify` uses a digest-pinned Zeek Docker image and pinned
Modbus/DNP3 ICSNPP scripts. The stock image has no compiled S7 plugin. Missing S7
checks are explicit skips; they are **failures with `--require-complete`**.
Releases require complete Tier 2 unless explicitly waived with `--no-verify` or
`--skip-gate`.

```sh
make verify VERIFY_ARGS=--require-complete
```

The runner compares core Modbus transaction fields, DNP3 message/object/control
fields, and S7 COTP frames and modeled request/response details against independent
parsers, then runs the Zeek detections' fire and quiet scenarios. Unsupported
Modbus functions retain request-count checks. Timing, complete session semantics,
PLC process behavior and encrypted S7 traffic remain outside this qualification.

## Docker

Build a Zeek image with the
[CISA ICSNPP S7comm plugin](https://github.com/cisagov/icsnpp-s7comm) and scripts,
then select it explicitly:

```sh
export SUBSTATION_ZEEK_S7_IMAGE=your-registry/zeek-icsnpp-s7comm:tag
make verify VERIFY_ARGS=--require-complete
```

Use the upstream commit and reviewed bounds patch below when building the image;
pin its digest when recording reproducible qualification. The plugin must appear
in `zeek -N` with `substation-bounds-v1`, and `zeek --parse-only -e '@load icsnpp/s7comm'` must
succeed. A plugin name alone is insufficient. Analysis containers have no network
access; first-time image pulls and parser-source fetches require network access.

## Native Zeek

A host with Zeek installed can run the same checks without Docker:

```sh
make verify VERIFY_ARGS='--native --require-complete'
```

The pinned upstream parser has a reproduced decimal-buffer defect and an unchecked
filename byte read. Build with the [reviewed bounds patch](spikes/09-s7-field-fidelity.md)
before qualifying field fidelity. With Git, CMake, a C++ compiler and native Zeek
development headers installed, use a new build directory:

```sh
S7_BUILD_ROOT="$(mktemp -d)/qualified"
python scripts/verify/build_s7.py --out "$S7_BUILD_ROOT"
export ZEEK_PLUGIN_PATH="$S7_BUILD_ROOT/build"
export ZEEKPATH="$S7_BUILD_ROOT/source/scripts:$(zeek-config --zeekpath)"
make ci
make verify VERIFY_ARGS='--native --require-complete'
```

The helper fetches a fixed upstream commit. Supply `--source /path/to/clean/checkout`
at that commit to avoid downloading. Existing output directories are rejected.
On this macOS host, Zeek's generator binaries could not write under Documents;
the temporary build directory above worked. `provenance.json` records the source
commit, patch hash and native Zeek version. Keep it with qualification evidence.

The runner prints the host version; native results do not qualify the pinned
Docker image. The September 2026 review used Zeek **8.2.2** and ICSNPP S7comm
**1.3.0** at commit `7ebeb03a0f954541369361651d1c27d09a64b5a3`. The
[current review](reviews/2026-09-10-validation-closeout.md) records the full gate
results. Suricata is optional because no rules are shipped.

## Evidence boundary

The [S7 field comparison](spikes/09-s7-field-fidelity.md) checks direction, ports,
connection order, COTP, errors, SZL/transfer details and S7-plus headers. Its
dedicated fixture covers every modeled operation. The native pytest checks also
cover all SZL low-byte names and PDU references crossing 255→256; run `make ci`
with the same native plugin environment to include them.

ICSNPP 1.3.0 reverses PDU-reference bytes relative to the wire and Wireshark.
The oracle requires that exact known transformation; it does not change the
wire/schema or accept multiple representations. Other parser versions require
review. This does not qualify a general sensor importer, timing, process values,
valid programs, complete transfer sessions or S7-plus integrity/encryption.

Field references:

- [Schema](schema.md)
- [S7 field spike](spikes/06-icsnpp-s7comm-fields.md)
- [Current review](reviews/2026-09-09-codebase-review.md)
