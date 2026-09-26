# M4 — Modbus bulk read / address-space sweep

One source reading an unusually large share of a Modbus data table on one PLC
unit within a short window — the collection detection for the Modbus slice
(`docs/design.md` §5.1). **Coverage, not volume.**

| | |
|---|---|
| **Detection ID** | M4 |
| **Engine** | Zeek (Tier 2, over the PCAP via the base Modbus analyzer) |
| **Rule** | [`detections/zeek/modbus_m4_read_sweep.zeek`](../zeek/modbus_m4_read_sweep.zeek) |
| **Status** | experimental · **Notice** | `ModbusReadSweep::ReadSweep` |

## Behavior

Before manipulating a process, an adversary needs to know what the registers
mean. Scripted collection walks a device's address space with back-to-back,
maximum-size reads and records what comes back: process values, setpoints and
the layout of the point map. FrostyGoop, for example, read Modbus holding
registers on its targets. The hallmark is **breadth**: each request asks for
addresses the source has not read before.

Legitimate masters behave differently. A SCADA poller or HMI reads the same
configured blocks on every cycle, so however often it polls, the set of
addresses it has touched stops growing after the first cycle.

## Engine choice + rationale

**Zeek**, because the signal is **stateful**: the number of distinct addresses a
source has read from one table, accumulated over many requests. A single event
cannot show it, so a stateless Sigma selection cannot express it, and a Sigma
count correlation would measure request **volume** — the wrong signal, since
polling volume is high in normal operation (`docs/design.md` §8). Keeping a set of
distinct address pages per source is durable state, which the engine policy
assigns to Zeek (`docs/design.md` §6.5).

## Data source

Zeek's **base** Modbus analyzer (no ICSNPP dependency), request events only:

- `modbus_read_coils_request`, `modbus_read_discrete_inputs_request`,
  `modbus_read_holding_registers_request`, `modbus_read_input_registers_request`
  — each with `start_address` and `quantity`.
- `modbus_read_write_multiple_registers_request` — its read half
  (`read_start_address`, `read_quantity`) counts toward holding registers.
- `headers$uid` for the unit, `c$id$orig_h` / `c$id$resp_h` for source and PLC.

> **VERIFY.** The event signatures were checked against Zeek 8.2's
> `base/bif/plugins/Zeek_Modbus.events.bif.zeek` (in the pinned verification
> image) on 2026-09-26, not recalled from memory.

## Detection logic

State is kept per **(source, PLC, unit, table)**, where the table is coils,
discrete inputs, holding registers or input registers. Each read request adds
the address **pages** it spans to that key's set. A page is 32 bytes of table
data: 16 registers or 256 coils/discrete inputs, which keeps the work per request
small (at most nine pages for a legal read) and makes one threshold meaningful for
both register and bit tables.

When a key reaches `page_threshold` distinct pages within `read_window` of its
first read, the rule raises `ModbusReadSweep::ReadSweep` once. The alert flag
lives in the same record as the page set and expires with it, so a new sweep
after the window re-alerts. Quantities above the protocol maximum (125 registers,
2,000 bits) are clamped: coverage counts only what a compliant read could return.

| Knob (`&redef`) | Default | Meaning |
|---|---|---|
| `read_window` | `10min` | Window over which coverage accumulates (from the key's first read). |
| `page_threshold` | `64` | Distinct pages that constitute a sweep: about 1,024 registers or 16,384 bits. |
| `exempt_sources` | empty | Sources excluded entirely, for tools that legitimately read whole maps. |

## Scenarios

- **Fires:** [`anomalous-m4-read-sweep.yaml`](../../scenarios/modbus/anomalous-m4-read-sweep.yaml)
  — the trusted HMI walks holding registers 0–1124 in nine 125-register reads;
  coverage reaches 64 pages on the ninth read. M1, M2, M3 and **X1** stay quiet:
  the HMI, its PLC and the read function are all in X1's learned baseline, so
  novelty detection cannot see this collection. Coverage can.
- **Quiet:** [`benign-bulk-poll.yaml`](../../scenarios/modbus/benign-bulk-poll.yaml)
  — the volume boundary: twelve 125-register reads (1,500 register values, more
  than the sweep) over a fixed 500-register map, which never exceeds 32 pages.
- **Quiet:** every other Modbus scenario, including the benign baseline and the
  M3 function/unit sweep (one-address reads on several units).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Monitor Process State | **T0801** | Collection (TA0100) |
| Related | Point & Tag Identification | T0861 | Collection (TA0100) |

A bulk walk of a PLC's registers gathers the physical process state (T0801).
The live technique page cites FrostyGoop reading Modbus holding registers and
suggests monitoring protocol read functions. Mapping which addresses exist and
what they hold is also point identification (T0861). The same traffic informs
discovery; the registry records Collection as M4's single tactic.

> **VERIFY.** Verified against the **live** ATT&CK-for-ICS matrix on
> 2026-09-26. Sources: <https://attack.mitre.org/techniques/T0801/>,
> <https://attack.mitre.org/techniques/T0861/>,
> tactic <https://attack.mitre.org/tactics/TA0100/>.

## False-positive profile

- **Whole-map pollers.** A historian or SCADA master that polls more than about
  1,000 registers of one unit's table exceeds the default threshold on its first
  cycle, and again each window. Raise `page_threshold` above the largest known
  working set, or exempt the host (accepting that its compromise goes unseen).
- **Configuration backup and commissioning tools.** Engineering software that
  reads a device's full map during commissioning or backup fires, which is often
  useful to know. Correlate with change windows.
- **Why benign polling stays quiet.** Repeated reads of the same blocks add no
  new pages, so request volume does not matter. The bulk-poll scenario proves
  this with more read volume than the firing sweep.
- **Evasion boundaries.** A slow sweep that adds fewer than 64 pages per 10
  minutes, or one spread across many source addresses, stays below the
  threshold. A sweep across unit IDs with small reads is M3's signal instead.
