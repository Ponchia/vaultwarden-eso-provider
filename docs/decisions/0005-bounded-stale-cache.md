# 0005. Bounded stale cache on transient upstream errors

Status: Accepted, 2026-07-22.

## Context

Every resolve after the cache lifetime requires an upstream login and sync.
Returning the upstream failure is the safest default, but it
also means a short upstream or network outage prevents ESO from reconciling a
Secret even when the provider has a recent successful sync in memory.

Serving cached data indefinitely would hide outages and could preserve a value
after an operator changed or revoked it. Retrying on every ESO request would
also turn a reconcile burst into repeated login attempts against an unhealthy
upstream service.

## Decision

Keep upstream refresh failures fail closed by default. Add an opt-in stale
window with these constraints:

- A stale resolve requires a cache populated by a previous successful login and
  sync in the current process.
- The configured stale duration extends the normal cache lifetime. The provider
  never serves an entry after the combined age limit.
- Only transport failures, HTTP `408`, HTTP `429`, and HTTP `5xx` responses can
  activate the fallback.
- Authentication and authorization failures, invalid or oversized responses,
  KDF errors, and decryption errors remain explicit failures.
- After a transient refresh failure, a configurable retry interval suppresses
  repeated upstream attempts while eligible stale data is served.
- `bweso_cache_stale_serves_total` counts stale resolves without labels or vault
  metadata. Existing refresh-failure and last-success-age metrics remain
  available.

The command-line and Helm defaults set the stale duration to zero. Operators
must choose a nonzero duration deliberately.

## Consequences

- Short upstream outages can stop blocking ESO reconciliation when the operator
  accepts the delayed-update trade-off.
- A changed vault value can remain in Kubernetes until the upstream recovers or
  the stale age limit expires.
- Provider restarts clear the in-memory cache, so this mechanism is not a
  persistent disaster-recovery store.
- The retry interval bounds login pressure during an outage, while the age
  check remains authoritative even when the retry deadline is later.
