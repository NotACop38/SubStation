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

# Per (source, PLC) state for one diversity window: the distinct function codes
# and unit IDs seen, plus whether we have already alerted this window.
#
# The `alerted` flag lives in the SAME record as the diversity sets, and the
# whole entry expires `sweep_window` after first contact (&create_expire below),
# so alert suppression is tied to the diversity window: when the window resets,
# the flag resets with it. A genuinely new sweep that starts after the reset
# re-alerts — it is not masked by a suppression timer that began at the previous
# alert (which could sit late in the window and outlive the diversity reset).
type SweepState: record {
	funcs: set[count];
	units: set[count];
	alerted: bool &default = F;
};

# Keyed per (source, PLC); the entry — and with it the `alerted` flag — expires
# `sweep_window` after the pair is first seen. &create_expire counts from
# creation only: the per-request `add`s below do not extend it, which is exactly
# the "diversity within a window from first contact" semantics we want.
global sweeps: table[addr, addr] of SweepState &create_expire = sweep_window;

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	# Only requests reveal what a source is probing; the matched response comes
	# from the PLC and would otherwise inflate the source's apparent diversity.
	if ( ! is_orig )
		return;

	local src = c$id$orig_h;
	local plc = c$id$resp_h;

	if ( [src, plc] !in sweeps )
		sweeps[src, plc] = SweepState($funcs = set(), $units = set());

	# Records are reference types, so mutating `st` updates the stored entry.
	local st = sweeps[src, plc];
	add st$funcs[headers$function_code];
	add st$units[headers$uid];

	# Already alerted this window — one notice per sweep episode.
	if ( st$alerted )
		return;

	local n_funcs = |st$funcs|;
	local n_units = |st$units|;

	if ( n_funcs >= func_code_threshold || n_units >= unit_id_threshold )
		{
		st$alerted = T;
		# No $identifier: the Notice framework's default suppression interval
		# (≈1h) would outlive sweep_window and re-introduce exactly the gap we
		# avoid above. The window-aligned `alerted` flag is the sole dedup.
		NOTICE([$note = Sweep,
		        $conn = c,
		        $msg = fmt("Modbus function-code/unit-ID sweep: source %s touched %d distinct function codes and %d distinct unit IDs on %s",
		                   src, n_funcs, n_units, plc),
		        $sub = fmt("func_codes=%d unit_ids=%d", n_funcs, n_units)]);
		}
	}
