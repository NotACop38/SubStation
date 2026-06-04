##! Substation detection D4 — DNP3 function-code enumeration / scanning.
##!
##! Fires when a single source issues an anomalously *diverse* set of DNP3
##! application function codes against one outstation within a short window — the
##! enumeration signal of reconnaissance mapping which functions a device supports
##! (PRD.md §5.2, D4). The signal is DIVERSITY, deliberately NOT request volume:
##! SCADA masters poll constantly, so a volume threshold fires on normal operation
##! (PRD.md §8). We count the number of *distinct* request function codes per
##! source, not requests.
##!
##! Engine: Zeek (PRD.md §6.5). Enumeration needs durable per-source state — the set
##! of distinct function codes accumulated over a window — plus a set-membership /
##! cardinality test a stateless Sigma field-match cannot express. This is the DNP3
##! slice's Zeek rail, mirroring Modbus M3. Full rationale, mapping and FP profile:
##! detections/docs/D4-function-enumeration.md.
##!
##! ATT&CK for ICS: T0888 Remote System Information Discovery + T0846 Remote System
##! Discovery (tactic: Discovery, TA0102) — enumerating supported DNP3 functions
##! gathers device capability/configuration information.
##!
##! Data source: Zeek's base DNP3 analyzer `dnp3_application_request_header` event
##! (`fc`, `c$id$orig_h`); no ICSNPP dependency. Function-code field/event names
##! verified against zeek/zeek base/protocols/dnp3 on 2026-06-04 (spike 04).

@load base/protocols/dnp3
@load base/frameworks/notice

module Dnp3Enum;

export {
	redef enum Notice::Type += {
		## One source reached anomalous DNP3 function-code diversity against a
		## single outstation inside `enum_window`.
		Enumeration,
	};

	## Window (measured from first contact for a source->outstation pair) over which
	## per-source function-code diversity is accumulated. Diversity resets after the
	## window, so a benign source that legitimately uses a handful of codes over a
	## long run never accrues a false enumeration.
	const enum_window = 60sec &redef;

	## Distinct request function codes from one source to one outstation within the
	## window that constitute enumeration. Tuned conservatively above a
	## busy-but-legitimate master's working set (READ, WRITE, ENABLE/DISABLE
	## unsolicited, SELECT/OPERATE, an occasional restart) so routine multi-function
	## operation stays quiet (see the doc's FP profile).
	const func_code_threshold = 6 &redef;
}

# Per (source, outstation) state for one window: the distinct request function
# codes seen, plus whether we have already alerted this window. The `alerted` flag
# lives in the SAME record as the diversity set and the whole entry expires
# `enum_window` after first contact (&create_expire below), so alert suppression is
# tied to the diversity window: when the window resets, the flag resets with it. A
# genuinely new sweep after the reset re-alerts — it is not masked by a suppression
# timer that outlives the diversity reset (the Modbus M3 review fix, carried over).
type EnumState: record {
	funcs: set[count];
	alerted: bool &default = F;
};

# Keyed per (source, outstation); the entry — and with it `alerted` — expires
# `enum_window` after the pair is first seen. &create_expire counts from creation
# only: the per-request `add`s below do not extend it, which is exactly the
# "diversity within a window from first contact" semantics we want.
global enums: table[addr, addr] of EnumState &create_expire = enum_window;

event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count)
	{
	# Only requests reveal what a source is probing; the matched response comes from
	# the outstation and carries fc 0x81 regardless, which would not reflect probing.
	if ( ! is_orig )
		return;

	local src = c$id$orig_h;
	local outstation = c$id$resp_h;

	if ( [src, outstation] !in enums )
		enums[src, outstation] = EnumState($funcs = set());

	# Records are reference types, so mutating `st` updates the stored entry.
	local st = enums[src, outstation];
	add st$funcs[fc];

	# Already alerted this window — one notice per enumeration episode.
	if ( st$alerted )
		return;

	local n_funcs = |st$funcs|;

	if ( n_funcs >= func_code_threshold )
		{
		st$alerted = T;
		# No $identifier: the Notice framework's default suppression (~1h) would
		# outlive enum_window and re-introduce the gap the window-aligned `alerted`
		# flag avoids. That flag is the sole dedup.
		NOTICE([$note = Enumeration,
		        $conn = c,
		        $msg = fmt("DNP3 function-code enumeration: source %s issued %d distinct function codes to outstation %s",
		                   src, n_funcs, outstation),
		        $sub = fmt("func_codes=%d", n_funcs)]);
		}
	}
