##! Substation detection X1 — cross-protocol baseline deviation.
##!
##! The flagship cross-protocol detection (PRD.md §5.4). Fires when a
##! source/destination/function combination appears that is NOT in the learned
##! baseline, across ANY supported protocol (Modbus, DNP3, S7comm). Three
##! deviation classes, in precedence order:
##!
##!   1. NEW TALKER     — an originator host never seen in the baseline at all.
##!   2. NEW ASSET PAIR — a known talker reaching a (src→dst) pair never seen
##!                       baselined (lateral movement to a new asset).
##!   3. NEW FUNCTION   — a known pair exercising a normalized function/verb never
##!                       seen for that pair (e.g. a polling-only link suddenly
##!                       issuing a control).
##!
##! Only the HIGHEST-precedence novelty is reported per observation: a brand-new
##! talker is reported as NEW TALKER (not also as a new pair / new function),
##! because the talker itself is the headline. Each distinct novel tuple alerts
##! at most once (it is folded into the baseline after alerting), so a sustained
##! anomalous flow is one notice, not a storm.
##!
##! Engine: Zeek (PRD.md §6.5). This is the canonical reason the engine policy
##! reserves Zeek for "real state": X1 needs durable LEARNED STATE (the baseline
##! sets) plus SET-MEMBERSHIP tests across protocols — neither expressible as a
##! stateless Sigma field-match. It is also the flagship justification for the
##! normalized envelope (PRD.md §6.3): the per-protocol Zeek/ICSNPP logs are not
##! uniformly shaped, so X1 normalizes every protocol event down to one
##! (orig_h, resp_h, func) tuple and runs ONE baseline over all three.
##!
##! Learned state: the baseline is a set of known talkers / pairs / functions. It
##! is supplied two ways (use either or both):
##!   * INJECTED (production + the Tier-2 runner): redef `known_talkers`,
##!     `known_pairs`, `known_funcs` with the allow-set derived from a known-good
##!     learning period (e.g. Substation's benign baseline scenarios). This is the
##!     "learned state" of PRD.md §5.4 — computed once offline, then enforced.
##!   * SELF-LEARN (optional, standalone): set `learn_period` > 0; every tuple
##!     observed within `learn_period` of the first packet seeds the baseline,
##!     and only deviations AFTER the window alert. Default is 0secs (off) so the
##!     detection relies on the injected baseline and never silently "learns away"
##!     an attacker that is present from the first packet.
##!
##! ATT&CK for ICS: T0846 Remote System Discovery (tactic: Discovery, TA0102) — a
##! new talker / new asset pair is the network signature of an actor discovering
##! and reaching OT assets it has not legitimately spoken to before. PRD.md §5.4
##! also relates X1 to Lateral Movement (TA0109); the verified primary mapping is
##! Discovery/T0846 (matches M3/D4/S3, verified against the live matrix
##! 2026-06-04). Full rationale, mapping and FP profile:
##! detections/docs/X1-cross-protocol-baseline.md.
##!
##! Data sources (per-protocol, normalized into one tuple):
##!   * Modbus — base `modbus_message` (`headers$function_code`); verified for M3.
##!   * DNP3   — base `dnp3_application_request_header` (`fc`); verified for D4.
##!   * S7comm — ICSNPP `s7comm_header` for every S7comm request; `s7comm_read_szl`
##!              keeps the existing SZL-ID-specific baseline detail for Read SZL.
##!   * S7comm-plus — ICSNPP `s7comm_plus_header` for S7comm-plus requests.

@load base/protocols/modbus
@load base/protocols/dnp3
@load base/frameworks/notice

module CrossProtoBaseline;

export {
	redef enum Notice::Type += {
		## A source originated traffic to a destination/function combination not
		## present in the learned cross-protocol baseline.
		BaselineDeviation,
	};

	## The learned baseline (PRD.md §5.4 "learned state"). Inject the known-good
	## allow-set here (redef) from a learning period; membership in these sets is
	## what keeps legitimate traffic quiet.
	##
	## `known_talkers` — originator hosts that legitimately speak any protocol.
	global known_talkers: set[addr] &redef;
	## `known_pairs` — legitimate (originator, responder) asset pairs.
	global known_pairs: set[addr, addr] &redef;
	## `known_funcs` — legitimate (originator, responder, normalized-func) tuples.
	## `func` is the cross-protocol normalized verb produced by `norm_func()`
	## below (e.g. "modbus:3", "dnp3:1", "s7comm:szl=0x11"), so one baseline spans
	## every protocol.
	global known_funcs: set[addr, addr, string] &redef;

	## Optional self-learning window (see file header). Within `learn_period` of
	## the first observed packet, every tuple seeds the baseline instead of
	## alerting. Default 0secs = rely on the injected baseline only.
	const learn_period = 0secs &redef;
}

# Normalize a per-protocol function/command code into one cross-protocol token.
# Keeping the protocol prefix means a Modbus code 3 and a DNP3 code 3 are distinct
# functions in the shared baseline (they are unrelated verbs).
function norm_func(proto: string, code: string): string
	{
	return fmt("%s:%s", proto, code);
	}

# Normalize the general ICSNPP S7comm header into a stable function token. Include
# ROSCTR so Job Read Variable (function 0x04) and User-Data CPU Functions / Read
# SZL (also function group 0x04) remain distinct. Include subfunction and PLC
# control service when present because those fields are the actual verb within
# User-Data and PLC Control requests.
function norm_s7comm_header_func(rosctr: count, function_code: count, subfunction: count, plc_control: string): string
	{
	local func = fmt("rosctr=0x%02x,function=0x%02x", rosctr, function_code);
	if ( subfunction != 0 )
		func = fmt("%s,subfunction=0x%02x", func, subfunction);
	if ( plc_control != "" )
		func = fmt("%s,plc_control=%s", func, plc_control);
	return func;
	}

# Set on the first observation; gates the optional self-learning window.
global first_seen: time = double_to_time(0);

# Core normalizer: every protocol event funnels here with its (src, dst, func).
# Decides learn-vs-detect, classifies the highest-precedence novelty, alerts once
# per novel tuple, and folds the tuple into the baseline so it never re-alerts.
function observe(c: connection, func: string)
	{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( first_seen == double_to_time(0) )
		first_seen = network_time();

	# Self-learning window: seed the baseline, do not alert.
	local learning = learn_period > 0secs && network_time() <= first_seen + learn_period;

	local new_talker = src !in known_talkers;
	local new_pair = [src, dst] !in known_pairs;
	local new_func = [src, dst, func] !in known_funcs;

	# Always extend the baseline with what we just saw (learning or post-learning):
	# this both seeds the window and de-dups alerts (each novel tuple fires once).
	add known_talkers[src];
	add known_pairs[src, dst];
	add known_funcs[src, dst, func];

	if ( learning )
		return;

	# Nothing novel — legitimate, baselined traffic. Stay quiet.
	if ( ! new_talker && ! new_pair && ! new_func )
		return;

	# Report only the highest-precedence novelty (talker > pair > function).
	local deviation: string;
	if ( new_talker )
		deviation = fmt("new talker %s", src);
	else if ( new_pair )
		deviation = fmt("new asset pair %s -> %s", src, dst);
	else
		deviation = fmt("new function %s for pair %s -> %s", func, src, dst);

	# No $identifier: the per-tuple baseline fold above is the sole dedup, so the
	# Notice framework's hour-long default suppression cannot mask a genuinely
	# different deviation that arrives shortly after.
	NOTICE([$note = BaselineDeviation,
	        $conn = c,
	        $msg = fmt("Cross-protocol baseline deviation: %s (func=%s)", deviation, func),
	        $sub = func]);
	}

# --- per-protocol entry points: normalize, then hand to observe() ------------

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	# Requests only: the matched response echoes the function code and would
	# inflate the source's apparent behaviour with the responder's reply.
	if ( ! is_orig )
		return;
	observe(c, norm_func("modbus", fmt("%d", headers$function_code)));
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count)
	{
	# Requests only; the outstation reply carries fc 0x81 regardless of probing.
	if ( ! is_orig )
		return;
	observe(c, norm_func("dnp3", fmt("%d", fc)));
	}

event s7comm_header(c: connection, is_orig: bool, rosctr: count, pdu_reference: count, function_code: count, subfunction: count, plc_control: string, error_class: count, error_code: count)
	{
	# Requests only; responses repeat the function/subfunction and would double-count.
	if ( ! is_orig )
		return;

	# Read SZL is handled below with the SZL ID to preserve the original
	# S7-specific baseline precision while this general header path covers the
	# rest of the S7comm surface (Setup Communication, Read/Write Variable,
	# upload/download functions, PLC Control/Stop, List Blocks, etc.).
	# User-Data Read SZL request FUNC is 0x44 (request nibble 0x4 |
	# CPU-functions group 0x04), not the bare group value 0x04.
	if ( rosctr == 0x07 && function_code == 0x44 && subfunction == 0x01 )
		return;

	observe(c, norm_func("s7comm", norm_s7comm_header_func(rosctr, function_code, subfunction, plc_control)));
	}

event s7comm_read_szl(c: connection, is_orig: bool, pdu_reference: count, method: count, return_code: count, szl_id: count, szl_index: count)
	{
	# Requests only; the response returns the same szl_id and would double-count.
	if ( ! is_orig )
		return;
	observe(c, norm_func("s7comm", fmt("szl=0x%x", szl_id)));
	}

event s7comm_plus_header(c: connection, is_orig: bool, version: count, opcode: count, function_code: count)
	{
	# Requests only; responses/notifications would double-count the originator's
	# behavior. The opcode is retained because S7comm-plus verbs are opcode-scoped.
	if ( ! is_orig )
		return;
	observe(c, norm_func("s7comm-plus", fmt("opcode=0x%02x,function=0x%04x", opcode, function_code)));
	}
