##! Substation detection M4 — Modbus bulk read / address-space sweep.
##!
##! Fires when a single source reads an unusually large share of one Modbus data
##! table (coils, discrete inputs, holding or input registers) on one PLC unit
##! within a window — the signature of scripted process-state collection and point
##! mapping (for example FrostyGoop reading holding registers). The signal is
##! address-space COVERAGE, deliberately NOT request volume: a SCADA master that
##! polls the same blocks every second never widens its coverage, while a sweep
##! walks new addresses with every request (docs/design.md §8).
##!
##! Engine: Zeek (docs/design.md §6.5). Coverage is state accumulated across many
##! requests — a set of distinct address pages per key — which a stateless Sigma
##! field match cannot express, and a Sigma count correlation would measure volume.
##! Full rationale, mapping and FP profile: detections/docs/M4-read-sweep.md.
##!
##! ATT&CK for ICS: T0801 Monitor Process State (tactic: Collection, TA0100);
##! related T0861 Point & Tag Identification.
##!
##! Data source: Zeek's base Modbus analyzer read-request events; no ICSNPP
##! dependency. Event signatures verified against Zeek 8.2's
##! base/bif/plugins/Zeek_Modbus.events.bif.zeek on 2026-09-26.

@load base/protocols/modbus
@load base/frameworks/notice

module ModbusReadSweep;

export {
	redef enum Notice::Type += {
		## One source read an unusually large span of distinct addresses from
		## one Modbus table on one PLC unit inside `read_window`.
		ReadSweep,
	};

	## Window (measured from a key's first read) over which coverage accumulates.
	## Coverage resets afterwards, so a source that slowly browses a few new
	## addresses per hour never accrues a false sweep.
	const read_window = 10min &redef;

	## Distinct pages that constitute a sweep. A page is 32 bytes of table data:
	## 16 registers or 256 coils/discrete inputs. The default, 64 pages, is about
	## 1,024 registers or 16,384 bits — above typical fixed SCADA working sets and
	## far below a walk of the 65,536-address table. Tune per site.
	const page_threshold = 64 &redef;

	## Sources that legitimately read entire register maps (for example a
	## historian or a configuration backup tool). Exempting a source also hides a
	## sweep by that host if it is compromised; prefer raising the threshold.
	const exempt_sources: set[addr] = {} &redef;
}

# Page sizes chosen so one page is 32 bytes of data in every table.
const register_page_size = 16;
const bit_page_size = 256;

# Protocol maxima for one read request (Modbus Application Protocol v1.1b3).
# Larger quantities are malformed and draw an exception, so they are clamped:
# coverage counts only what a compliant read could have returned.
const max_read_registers = 125;
const max_read_bits = 2000;

# Per (source, PLC, unit, table) state for one window. `alerted` lives in the
# same record, so alert suppression resets together with the coverage window.
type ReadState: record {
	pages: set[count];
	alerted: bool &default = F;
};

# &create_expire counts from the first read only; later reads do not extend it.
global coverage: table[addr, addr, count, string] of ReadState &create_expire = read_window;

function track(c: connection, headers: ModbusHeaders, space: string, start: count,
               quantity: count, page_size: count, max_quantity: count)
	{
	local src = c$id$orig_h;
	if ( quantity == 0 || src in exempt_sources )
		return;
	if ( quantity > max_quantity )
		quantity = max_quantity;

	local plc = c$id$resp_h;
	local unit = headers$uid;
	if ( [src, plc, unit, space] !in coverage )
		coverage[src, plc, unit, space] = ReadState($pages = set());

	# Records are reference types, so mutating `st` updates the stored entry.
	local st = coverage[src, plc, unit, space];
	if ( st$alerted )
		return;

	# Bounded work per request: at most one pass over the pages this read spans,
	# stopping as soon as the threshold is reached.
	local page = start / page_size;
	local last = (start + quantity - 1) / page_size;
	while ( page <= last && |st$pages| < page_threshold )
		{
		add st$pages[page];
		++page;
		}

	if ( |st$pages| < page_threshold )
		return;

	st$alerted = T;
	# No $identifier: the Notice framework's default suppression interval would
	# outlive read_window. The window-aligned `alerted` flag is the sole dedup.
	NOTICE([$note = ReadSweep,
	        $conn = c,
	        $msg = fmt("Modbus read sweep: source %s read %d distinct %s pages (%d addresses each) from %s unit %d",
	                   src, |st$pages|, space, page_size, plc, unit),
	        $sub = fmt("table=%s unit=%d pages=%d", space, unit, |st$pages|)]);
	}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                start_address: count, quantity: count)
	{
	track(c, headers, "coils", start_address, quantity, bit_page_size, max_read_bits);
	}

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, quantity: count)
	{
	track(c, headers, "discrete_inputs", start_address, quantity, bit_page_size, max_read_bits);
	}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                            start_address: count, quantity: count)
	{
	track(c, headers, "holding_registers", start_address, quantity, register_page_size,
	      max_read_registers);
	}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, quantity: count)
	{
	track(c, headers, "input_registers", start_address, quantity, register_page_size,
	      max_read_registers);
	}

event modbus_read_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                                   read_start_address: count,
                                                   read_quantity: count,
                                                   write_start_address: count,
                                                   write_registers: ModbusRegisters)
	{
	track(c, headers, "holding_registers", read_start_address, read_quantity,
	      register_page_size, max_read_registers);
	}
