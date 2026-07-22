# 0006. Add capability-scoped webhook authentication

Status: Accepted, 2026-07-22

## Context

The original webhook authentication model accepted one bearer token. Every
`SecretStore` that knew that token could request every selector allowed by the
provider's global policy. Namespace-local Kubernetes Secrets improved token
placement but did not create independent capabilities when each Secret carried
the same value.

Running one provider deployment per trust boundary remains the strongest
isolation model, but it repeats upstream credentials, cache state, and
operational resources. A shared deployment needs a way to distinguish callers
without trusting ESO request bodies or network metadata as identity.

## Decision

Add an optional Secret-mounted JSON auth policy with versioned capabilities.
Each capability has a unique name, one or more bearer tokens, and a non-empty
exact/prefix selector allowlist.

- Authentication returns the matching capability's selector rules.
- A resolve succeeds only when both the capability policy and existing global
  selector policy allow the item key.
- Multiple tokens may share one capability to support overlap during rotation.
- Tokens must contain 32–4096 printable ASCII, non-whitespace bytes. The
  provider hashes them with SHA-256 during policy loading, zeroizes parsed token
  strings, and retains only fixed-size digests for constant-time comparison.
- Token values must be unique across capabilities. Capability names must also
  be unique. Empty policies, duplicate tokens, unknown JSON fields, unsupported
  versions, and oversized files fail at startup.
- The provider reads at most 1 MiB and accepts at most 1,024 capabilities and
  4,096 tokens, bounding startup parsing and request-time comparisons.
- The provider compares every configured token digest before selecting a scope.
  It does not return on the first match.
- Projected Secret updates are re-read on an interval and swapped atomically.
  Invalid reloads retain the last known-good rules. Operators may set the
  interval to `0` for rollout-gated changes.
- Logs and metrics expose only capability/token counts and reload outcomes.
  They never expose names, selector values, tokens, or token digests.
- Legacy single-token and explicitly unauthenticated test modes remain
  available and are mutually exclusive with scoped mode.

## Consequences

One provider can serve several namespace trust boundaries without giving every
namespace the full global allowlist. The global policy remains defense in depth
and an operator-reviewed upper bound.

Scoped authentication does not isolate the provider runtime. A process or
credential compromise can still expose everything visible to the configured
Vaultwarden/Bitwarden account. Deploy separate provider accounts and pods when
that boundary matters.

The policy duplicates item IDs already present in the global allowlist. This is
intentional: the global list answers what the deployment may read; each
capability answers what one caller may read.

Request authentication performs one SHA-256 operation and a bounded linear scan
over token digests. The configured token ceiling prevents an unbounded CPU
amplification path. Deployments needing thousands of independent callers should
use multiple providers or revisit indexed token identifiers in a future API.

Secret projection and the reload interval create a bounded propagation window.
Use overlapping tokens for rotation. Set the interval to `0` and roll the
provider when policy changes require coordinated activation.
