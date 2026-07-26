# Enabling Tier-2 S7 (icsnpp-s7comm)

The stock `make verify` Zeek image (`zeek/zeek:8.2`) has **no** compiled
`icsnpp-s7comm` plugin. S3 fire/quiet, X1’s S7 path, and S7 fidelity are therefore
**explicit skips** with a reason — never silent passes.

## What “available” means

`scripts/verify/run.py` only reports `icsnpp-s7comm available: true` when:

1. `zeek -N` lists an s7comm analyzer in the image, **and**
2. `@load icsnpp/s7comm` succeeds (scripts are loadable, not merely present as a name).

If the plugin appears in `-N` but cannot be loaded, verify treats S7 as unavailable.

## Enabling S7 checks

Build (or pull) a Zeek image that includes the [cisagov/icsnpp-s7comm](https://github.com/cisagov/icsnpp-s7comm)
C++ plugin and its Zeek scripts, then point verify at it:

```bash
export SUBSTATION_ZEEK_S7_IMAGE=your-registry/zeek-icsnpp-s7comm:tag
make verify
```

Pin the image digest in your environment the same way the stock image is pinned
in `scripts/verify/run.py`.

Building that image requires a Zeek **build toolchain** (the runtime image is not
enough). Keeping a prebuilt image out of this repo avoids a large, slow CI
dependency; the path above is the supported opt-in.

## Field names

Do **not** invent ICSNPP S7 field names. The frozen schema and spike notes are
authoritative:

- `docs/spikes/06-icsnpp-s7comm-fields.md`
- `docs/schema.md` (S7 `detail`)
- Live parsers in your S7-capable Zeek image when extending fidelity mapping
