##! Substation detection M3 — Modbus function-code / unit-ID sweep.
##!
##! Fires when a single source touches an anomalously *diverse* set of Modbus
##! function codes and/or unit IDs against one PLC within a short window — the
##! sweep/enumeration signal of reconnaissance (PRD.md §5.1, M3). The signal is
##! DIVERSITY, deliberately NOT request volume: SCADA masters poll constantly, so
##! a volume threshold fires on normal operation (PRD.md §8). We count the number
##! of *distinct* function codes and *distinct* unit IDs per source, not requests.
##!
##! Engine: Zeek (PRD.md §6.5). A sweep needs durable per-source state — sets of
##! distinct codes/units accumulated over a window — plus set-membership tests a
##! stateless Sigma field-match cannot express. This is the Modbus slice's
##! mandated Zeek rail (the slice ships ≥1 Sigma and ≥1 Zeek, PRD.md §6.5). Full
##! rationale, mapping and FP profile: detections/docs/M3-unit-function-sweep.md.
##!
##! ATT&CK for ICS: T0846 Remote System Discovery (tactic: Discovery, TA0102) —
##! sweeping Modbus unit IDs enumerates devices by logical identifier.
##!
##! Data source: Zeek's base Modbus analyzer `modbus_message` event
##! (`headers$function_code`, `headers$uid`); no ICSNPP dependency. Field names
##! verified against zeek/zeek base/protocols/modbus on 2026-06-04.

@load base/protocols/modbus
@load base/frameworks/notice

module ModbusSweep;

export {
	redef enum Notice::Type += {
		## One source reached anomalous Modbus function-code / unit-ID diversity
		## against a single PLC inside `sweep_window`.
		Sweep,
	};

	## Window (measured from first contact for a source→PLC pair) over which
	## per-source diversity is accumulated. Diversity resets after the window, so
	## a benign source that touches a few codes/units over a long run never
	## accrues a false sweep.
	const sweep_window = 60sec &redef;

	## Distinct function codes from one source to one PLC within the window that
	## constitute a sweep. Tuned conservatively above a busy-but-legitimate
	## master's working set of read/write codes so routine multi-function polling
	## stays quiet (see the doc's FP profile).
	const func_code_threshold = 8 &redef;

	## Distinct unit IDs from one source to one PLC within the window that
	## constitute a sweep. The high-confidence arm: legitimate masters target a
	## small, known set of unit IDs (often one), so sweeping several is the strong
	## enumeration signal.
	const unit_id_threshold = 3 &redef;
}

# Distinct function codes seen per (source, PLC), expired `sweep_window` after the
# pair is first seen so the detector measures diversity within a window.
global funcs_seen: table[addr, addr] of set[count] &create_expire = sweep_window;

# Distinct unit IDs seen per (source, PLC); same window semantics.
global units_seen: table[addr, addr] of set[count] &create_expire = sweep_window;

# (source, PLC) pairs already alerted this window — one notice per sweep, so a
# continuing sweep does not spam and a benign pair is never revisited.
global reported: set[addr, addr] &create_expire = sweep_window;

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	# Only requests reveal what a source is probing; the matched response comes
	# from the PLC and would otherwise inflate the source's apparent diversity.
	if ( ! is_orig )
		return;

	local src = c$id$orig_h;
	local plc = c$id$resp_h;

	# Aggregates are reference types in Zeek, so the locals below alias the sets
	# stored in the tables; `add` through them mutates the stored diversity sets.
	if ( [src, plc] !in funcs_seen )
		funcs_seen[src, plc] = set();
	if ( [src, plc] !in units_seen )
		units_seen[src, plc] = set();

	local fcodes = funcs_seen[src, plc];
	local funits = units_seen[src, plc];
	add fcodes[headers$function_code];
	add funits[headers$uid];

	# Already alerted on this pair within the window — stay quiet.
	if ( [src, plc] in reported )
		return;

	local n_funcs = |fcodes|;
	local n_units = |funits|;

	if ( n_funcs >= func_code_threshold || n_units >= unit_id_threshold )
		{
		add reported[src, plc];
		NOTICE([$note = Sweep,
		        $conn = c,
		        $msg = fmt("Modbus function-code/unit-ID sweep: source %s touched %d distinct function codes and %d distinct unit IDs on %s",
		                   src, n_funcs, n_units, plc),
		        $sub = fmt("func_codes=%d unit_ids=%d", n_funcs, n_units),
		        $identifier = fmt("%s-%s", src, plc)]);
		}
	}
