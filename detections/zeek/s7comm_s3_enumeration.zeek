##! Substation detection S3 — S7 module-info / SZL enumeration (recon).
##!
##! Fires when a single source reads an anomalously *diverse* set of S7comm SZL
##! system-status lists (module identity, CPU characteristics, component
##! identification, memory/system areas, block types, …) against one PLC within a
##! short window — the enumeration signal of reconnaissance mapping a device's
##! identity and configuration (PRD.md §5.3, S3). The signal is DIVERSITY,
##! deliberately NOT request volume: an engineering tool legitimately reads module
##! identity on connect, so a volume threshold fires on normal operation (PRD.md §8).
##! We count the number of *distinct* SZL-IDs requested per source, not requests.
##!
##! Engine: Zeek (PRD.md §6.5). Enumeration needs durable per-source state — the set
##! of distinct SZL-IDs accumulated over a window — plus a set-membership /
##! cardinality test a stateless Sigma field-match cannot express. This is the S7
##! slice's Zeek rail, mirroring Modbus M3 / DNP3 D4. Full rationale, mapping and FP
##! profile: detections/docs/S3-enumeration.md.
##!
##! ATT&CK for ICS: T0888 Remote System Information Discovery + T0846 Remote System
##! Discovery (tactic: Discovery, TA0102) — reading PLC identity/module info and
##! enumerating blocks gathers device capability/configuration information.
##!
##! Data source: ICSNPP-S7comm `s7comm_read_szl` event (`szl_id`, `is_orig`,
##! `c$id$orig_h`). Event/field names verified against cisagov/icsnpp-s7comm
##! scripts/icsnpp/s7comm/main.zeek on 2026-06-04 (spike 06). Requires the
##! icsnpp-s7comm plugin (Tier 2).

@load base/frameworks/notice
# No @load for the S7 analyzer: the s7comm_read_szl event handled below is
# provided by the icsnpp-s7comm package, which the Tier-2 container (and any
# production deployment) loads alongside this script (e.g. `zeek ... icsnpp/s7comm`).

module S7Enum;

export {
	redef enum Notice::Type += {
		## One source reached anomalous S7 SZL-ID diversity against a single PLC
		## inside `enum_window`.
		Enumeration,
	};

	## Window (measured from first contact for a source->PLC pair) over which
	## per-source SZL-ID diversity is accumulated. Diversity resets after the window,
	## so a source that legitimately reads a couple of SZLs over a long run never
	## accrues a false enumeration.
	const enum_window = 60sec &redef;

	## Distinct SZL-IDs from one source to one PLC within the window that constitute
	## enumeration. Tuned conservatively above an engineering tool's connect-time
	## working set (module identification, an occasional component-identification
	## read) so routine engineering stays quiet (see the doc's FP profile).
	const szl_id_threshold = 5 &redef;
}

# Per (source, PLC) state for one window: the distinct SZL-IDs seen, plus whether we
# have already alerted this window. The `alerted` flag lives in the SAME record as the
# diversity set and the whole entry expires `enum_window` after first contact
# (&create_expire below), so alert suppression is tied to the diversity window: when
# the window resets, the flag resets with it. A genuinely new sweep after the reset
# re-alerts — it is not masked by a suppression timer that outlives the diversity
# reset (the Modbus M3 / DNP3 D4 review fix, carried over).
type EnumState: record {
	szl_ids: set[count];
	alerted: bool &default = F;
};

# Keyed per (source, PLC); the entry — and with it `alerted` — expires `enum_window`
# after the pair is first seen. &create_expire counts from creation only: the
# per-request `add`s below do not extend it, which is exactly the "diversity within a
# window from first contact" semantics we want.
global enums: table[addr, addr] of EnumState &create_expire = enum_window;

event s7comm_read_szl(c: connection, is_orig: bool, pdu_reference: count, method: count, return_code: count, szl_id: count, szl_index: count)
	{
	# Only requests reveal what a source is probing; the matched response carries the
	# same szl_id back and would double-count the same probe.
	if ( ! is_orig )
		return;

	local src = c$id$orig_h;
	local plc = c$id$resp_h;

	if ( [src, plc] !in enums )
		enums[src, plc] = EnumState($szl_ids = set());

	# Records are reference types, so mutating `st` updates the stored entry.
	local st = enums[src, plc];
	add st$szl_ids[szl_id];

	# Already alerted this window — one notice per enumeration episode.
	if ( st$alerted )
		return;

	local n_szl = |st$szl_ids|;

	if ( n_szl >= szl_id_threshold )
		{
		st$alerted = T;
		# No $identifier: the Notice framework's default suppression (~1h) would
		# outlive enum_window and re-introduce the gap the window-aligned `alerted`
		# flag avoids. That flag is the sole dedup.
		NOTICE([$note = Enumeration,
		        $conn = c,
		        $msg = fmt("S7 SZL enumeration: source %s read %d distinct SZL-IDs from PLC %s",
		                   src, n_szl, plc),
		        $sub = fmt("szl_ids=%d", n_szl)]);
		}
	}
