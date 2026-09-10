# Independent Sigma execution — 2026-09-10

`make verify-sigma` compiles all seven authored rules and the bundled site-policy
exports with the official [SigmaHQ SQLite backend](https://github.com/SigmaHQ/pySigma-backend-sqlite).
The unmodified SQL executes in an in-memory SQLite database. Hit **indices** must
equal the Python evaluator's results; equal counts alone are insufficient.
The check covers 223 catalog events plus 22 external Modbus observations. It also
runs under `make ci`, with separate interval-oracle, target and empty-policy tests.

The development environment pins `pysigma-backend-sqlite==1.2.4` and
`pysigma==1.3.3`. The backend is excluded from the product's runtime dependencies.
The command reports backend, pySigma and SQLite versions so evidence can be tied
to the executing environment. Artifact hashes and wheel metadata are locked.

## Tested table contract

`scripts/verify/sigma_backend.py` defines the exact flat column names, including literal
dots (`conn.orig_h`, `detail.quantity`, etc.). Connection, enum and subfunction
strings use SQLite `NOCASE` collation, which covers ASCII case comparisons.
Numbers remain numbers and booleans are stored as SQLite integers. Columns have
no affinity that could turn numbers into text. Values are inserted with bound
parameters; absent values stay SQL `NULL`. This is a development fixture table,
not a production sensor mapping or a supported query-export CLI.

## Discovered deployment limits

| Case | Python evaluation | Official SQLite backend |
|---|---|---|
| Catalog, external observations and complete small-span policy fixtures | Tested hit identities | Same hit identities |
| Authorized-channel Modbus write with absent quantity | Missing selection is false, so negated permission alerts | `NOT NULL` stays unknown and the row does not alert |
| Full coil grant, range 0–65535 | Bounded quantity expansion is evaluable | 1,968 alternatives exceed the standard SQLite expression-depth limit of 1,000 |

Both failures are explicit regressions, not skipped checks or qualified cases.
The JSON Schema permits optional detail fields, so schema validation alone does
not guarantee the first case cannot occur. Real deployment needs a sensor mapping
that enforces the predicate's required fields and a deliberate policy for missing
telemetry, plus tests of the actual backend's null semantics. Large span policies
need a backend that accepts the generated expression, or a separately qualified
normalization/compiler strategy. A successful `policy compile` validates Sigma
authoring and the local subset; it does not promise that every backend accepts it.

SQLite's ASCII collation also does not establish Unicode case-folding equivalence.
This work qualifies the listed fixtures with one backend, not arbitrary input,
all Sigma syntax, all site policies, Elasticsearch, Splunk or any SIEM deployment.
Do not turn a green comparison into a production-readiness claim.
