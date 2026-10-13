# Roadmap

This project should remain a small Vaultwarden-to-ESO bridge. ESO owns the
Kubernetes lifecycle; another controller, CRD or rollout engine is not a goal.
Released history belongs in the [changelog](../CHANGELOG.md), and publishing
requirements belong in the [release checklist](public-release-checklist.md).

## Qualify the next release

The Argon2 interoperability fix, conservative deletion signals, bounded KDF
work, scoped authentication and optional stale cache are unreleased. Release
qualification must test the exact candidate chart/image, not just source code.

Acceptance requires a passing current-head CI and interoperability run, release
artifact verification, and deliberate upgrade/rollback tests. Repeat the
Bitwarden Cloud smoke because the unlock path changed; historical PBKDF2 smoke
evidence must not be presented as current Argon2 or Cloud verification.
A maintainer must explicitly authorize publication.

## Failure behavior and operating evidence

Measure cold-start unlock cost, fresh-cache throughput, full-vault refresh
latency and memory using representative small and larger vaults. Include
CPU-throttled pods and account KDF settings within the configured budget.
The current name lookup scans/decrypts personal items; prefer exact IDs.

Add concurrent failure/backoff tests before changing refresh semantics. The
current refresh lock serializes work, but in default fail-closed mode it does
not share an error/backoff across waiting requests. The optional stale window
throttles retries only while an eligible previous snapshot can be served.
Do not confuse single-flight success with outage-rate limiting.

Record a defined soak interval and recovery exercises: upstream outage,
revocation, password rotation, provider restart, source trash and target Secret
recreation. A deployment existing for months is not evidence of these tests.

## Protocol assurance

Arrange an independent review of KDF handling, key unwrap, cipher parsing,
zeroization boundaries and deletion signals. Add fuzz targets beyond the
existing encrypted-string parser where they test meaningful invariants.
Passing tests and coverage do not constitute an audit.

Assess organization/shared-item support separately. Require independently
created personal/organization/per-item key fixtures, wrong-key rejection,
least-privilege account guidance and actual backend verification before
advertising it. This is the main feature gap for team adoption; it is not a
safe opportunistic cleanup change.

## Conditional work

Add attachments only after agreeing on size limits, mapping and key handling.
Consider a native ESO provider only when the webhook contract demonstrably
blocks required behavior. Keep built-in workload restarts, dynamic credentials,
Bitwarden Secrets Manager and a separate Kubernetes operator out of scope.

Review documentation and release automation when they impose more maintenance
than value. Do not add dashboards, badges or governance files as a substitute
for interoperability and operational evidence.
