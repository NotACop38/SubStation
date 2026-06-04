# Substation research honeypot (optional, passive, isolated)

> **Read this before you run anything here.** This is an **opt-in research tool**,
> not part of the Substation headline path. It is the optional honeypot of
> [`PRD.md` §6.10](../../PRD.md) / Phase 5, and it is deliberately kept out of
> `make demo` and the one-command Tier-1 loop.

A minimal **passive Modbus/TCP probe logger**. It listens for inbound Modbus
requests, answers them with **stub** coil/register values (and standards-compliant
exception replies), and records every probe as a Substation event-log line so the
existing detections (M1/M2/M3, …) can be run against captured probe traffic.

It is **not** a PLC emulator. There is no process model — only banner/coil/register
stubs and exception responses.

## Safety invariants (non-negotiable)

- **Passive only.** It binds a *listening* socket and replies on the connections it
  `accept()`s. It **never** opens an outbound connection (`connect()`), never
  scans, and never touches real OT equipment.
- **Isolated by default.** It binds **loopback (`127.0.0.1`) only** unless you pass
  the explicit `--allow-external` opt-in. Binding a routable address is refused
  otherwise.
- **Deploy network-isolated only.** Run it on an air-gapped / lab / dedicated
  research VLAN segment with no path to production or OT. Never place it on, or
  bridged to, a live control network.
- **Stubs only.** No real values, no real device, no control logic. Do not point it
  at — or let it learn from — a real process.

## Legal / ethical cautions

- **Get authorization.** Only deploy on infrastructure you own or are explicitly
  authorized to operate. Running a service that solicits and records third-party
  connections can carry legal obligations.
- **You are capturing data from connecting hosts.** Source IPs and probe payloads
  may be personal/identifying data; handle, store, and retain the logs in line with
  the laws and policies that apply to you.
- **Do not entrap or attack back.** This tool only records; keep it that way.
- **No warranty.** Provided for defensive research under the repository
  [`LICENSE`](../../LICENSE). Use at your own risk.

## Run it

From a repo checkout (loopback-only, the safe default):

```sh
# Listen on 127.0.0.1:5020 (high port; no root needed) and log probes.
python -m substation.honeypot --port 5020 --log honeypot-probes.jsonl
```

Then point a Modbus client at `127.0.0.1:5020` to generate sample probes. The
default Modbus port `502` requires root/CAP_NET_BIND_SERVICE; prefer a high port.

To capture probes from other hosts **on an isolated research segment only**, opt in
explicitly:

```sh
python -m substation.honeypot --bind 10.99.0.5 --port 502 \
    --log honeypot-probes.jsonl --allow-external
```

Options: `--bind` (default `127.0.0.1`), `--port` (default `502`), `--log`
(default `./honeypot-probes.jsonl`), `--allow-external` (opt in to a non-loopback
bind).

## The logs conform to the event-log schema

Every line is a normalized-envelope event built through the **same**
`substation.protocols.modbus` mapping the simulator uses and validated against the
frozen [`docs/schema.md`](../../docs/schema.md) /
[`event-log.schema.json`](../schema/event-log.schema.json) before it is written.
So you can run the shipped Tier-1 detections directly over a probe capture, e.g.:

```sh
# Validate a probe capture against the frozen schema.
python -m substation.schema honeypot-probes.jsonl
```

Because the probe log uses the contract the detections bind to, a write from an
unrecognized source surfaces to **M1**, reserved/undefined function codes and the
honeypot's `ILLEGAL_FUNCTION` / `ILLEGAL_DATA_ADDRESS` exception replies surface to
**M2**, and function-code/unit sweeps surface to **M3** — no special-casing.

## What it is **not**

- Not a SIEM, IDS, or production monitoring tool.
- Not a high-interaction honeypot or a PLC emulator.
- Not part of the Substation demo, CI gate, or one-command path.
