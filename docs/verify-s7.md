# Tier-2 validation with Zeek and the S7 plugin

The default `make verify` uses a digest-pinned Zeek Docker image and pinned
Modbus/DNP3 ICSNPP scripts. The stock image has no compiled S7 plugin. Missing S7
checks are explicit skips; they are **failures with `--require-complete`**.
Releases require complete Tier 2 unless explicitly waived with `--no-verify` or
`--skip-gate`.

```sh
make verify VERIFY_ARGS=--require-complete
```

The runner compares **request source/destination/function counts** between the
JSON model and independently parsed PCAPs, then runs the Zeek detections' fire and
quiet scenarios. These checks catch dropped messages, function mismatches and
rule regressions. They do not compare every address, value, response, timing edge
or session behavior. The simulator does not emulate a PLC process or encrypted
S7 traffic.

## Docker

Build a Zeek image with the
[CISA ICSNPP S7comm plugin](https://github.com/cisagov/icsnpp-s7comm) and scripts,
then select it explicitly:

```sh
export SUBSTATION_ZEEK_S7_IMAGE=your-registry/zeek-icsnpp-s7comm:tag
make verify VERIFY_ARGS=--require-complete
```

Pin that image's digest when recording reproducible qualification. The plugin
must appear in `zeek -N`, and `zeek --parse-only -e '@load icsnpp/s7comm'` must
succeed. A plugin name alone is insufficient. Analysis containers have no network
access; first-time image pulls and parser-source fetches require network access.

## Native Zeek

A host with Zeek installed can run the same checks without Docker:

```sh
make verify VERIFY_ARGS='--native --require-complete'
```

Build the S7 plugin against the installed Zeek version, following its upstream
build instructions. For a local build, expose the plugin and scripts using
`ZEEK_PLUGIN_PATH` and `ZEEKPATH`. For example, substituting your actual paths:

```sh
export ZEEK_PLUGIN_PATH=/path/to/icsnpp-s7comm/build
export ZEEKPATH="/path/to/icsnpp-s7comm/scripts:$(zeek-config --zeekpath)"
make verify VERIFY_ARGS='--native --require-complete'
```

The runner prints the host version; native results do not qualify the pinned
Docker image. The September 2026 review used Zeek **8.2.2** and ICSNPP S7comm
**1.3.0** at commit `7ebeb03a0f954541369361651d1c27d09a64b5a3`. All three protocols'
request-count checks and all four Zeek rules passed: **41 passes, 0 failures**.
The sole optional skip was Suricata, for which no rules are shipped.

## Evidence boundary

The S7 parser checks exposed malformed synthetic download/User-Data messages and
an absent subfunction represented by `0xff`; those defects are fixed. They also
showed that matching function counts is not full field fidelity: S7 PDU reference
values in the tested parser output differed from the correctly encoded wire
reference. Detail-field equivalence remains unqualified. Preserve this boundary
when extending schemas or adapting real sensor logs.

Field references:

- [Schema](schema.md)
- [S7 field spike](spikes/06-icsnpp-s7comm-fields.md)
- [Current review](reviews/2026-09-09-codebase-review.md)
