# DNP3 message and field fidelity

Verified 2026-09-10 with native Zeek 8.2.2 and the Tier-2 runner's pinned
ICSNPP-DNP3 scripts. The current upstream revision changes only its README
relative to that pin; parser code and constant tables are identical.

## Authoritative sources

- [Zeek 8.2.2 transaction logger](https://github.com/zeek/zeek/blob/v8.2.2/scripts/base/protocols/dnp3/main.zeek)
  overwrites `fc_request` on each request, then logs on a response or connection
  finalization. It omits direction and does not retain a request queue.
- [Zeek's parser](https://github.com/zeek/zeek/blob/v8.2.2/src/analyzer/protocol/dnp3/dnp3-protocol.pac)
  exposes individual request/response headers and object callbacks. Its IIN
  integer is read in big-endian order. Binary Output group 10 variation 1 packs
  eight points per byte.
- [Zeek's object layouts](https://github.com/zeek/zeek/blob/v8.2.2/src/analyzer/protocol/dnp3/dnp3-objects.pac)
  include status octets in analog output blocks, beyond the 16/32-bit value.
- [Current ICSNPP constants](https://github.com/cisagov/icsnpp-dnp3/blob/b31dbadeceb1cbcda16aef89c650559cd177dd7e/scripts/consts.zeek)
  use spaced operation names, such as `Latch On`. Earlier schema notes followed
  the README's underscore spellings instead of the executable table.
- [Current ICSNPP logging](https://github.com/cisagov/icsnpp-dnp3/blob/b31dbadeceb1cbcda16aef89c650559cd177dd7e/scripts/main.zeek)
  emits object records for READ requests and RESPONSE replies only, omitting
  unsolicited responses and other request functions.
- [OpenDNP3's outstation dispatcher](https://github.com/dnp3/opendnp3/blob/release/cpp/lib/src/outstation/OutstationContext.cpp)
  handles CONFIRM through confirmation state, separately from requests that
  construct a RESPONSE; it must not generate a synthetic reply for each CONFIRM.

## Decision and corrected behavior

Use a small offline verification observer over the native parser callbacks.
Retain each header, direction and per-connection message ordinal, and associate
object/control callbacks with that header. Resolve labels using upstream tables.
Compare these observations with the independently generated JSON fields. Do not
project the lossy transaction log into a supposedly complete sensor event stream.

The initial regression run failed on operation-label mismatches, nonzero IIN and
packed binary output encoding. Corrections now emit spaced operation labels,
preserve Zeek's IIN representation, bit-pack binary outputs and include analog
output status octets. Frame-size limits account for those encoded widths.
CONFIRM no longer gets a synthesized reply. No-response functions reject IIN;
request-only object functions reject unused response ranges/counts.

Fixtures cover all seven supported object types, upper range/index boundaries,
control flags/times, asymmetric IIN octets, unsolicited responses and consecutive
no-response requests. Dedicated mutations change identity, direction, IIN,
operation/index/time/type/range/count, message association and row multiplicity;
each must make the comparator fail. Source archives include the observer and
fixtures so the same gate is available outside a Git checkout.

Temporarily restoring the previous analog-output widths in an isolated Python
process produced ten comparison differences on the boundary fixture, confirming
that the independent gate detects those regressions too.

## Limits

This qualifies message and selected field agreement on synthetic fixtures, not
a general DNP3 importer or representative operational corpus. The comparison
does not validate timing, application/transport sequencing, all function-specific
payload requirements, point values/status semantics, physical equipment behavior
or detection effectiveness. A parser accepting a frame is not proof that a real
outstation would accept the operation. Docker image qualification remains
separate from the native engine evidence.
