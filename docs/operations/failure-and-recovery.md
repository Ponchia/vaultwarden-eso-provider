# Failure and recovery

These procedures describe the current source tree. Scoped authentication,
bounded stale cache and the corrected missing-property status are unreleased;
`v0.4.0` does not include them. Check the deployed image before applying a
procedure. Never paste credentials, item IDs or resolved values into issues.

## Missing values and deletion

ESO interprets webhook HTTP 404 as a source deletion signal. On the corrected
provider, a missing field is HTTP 422, duplicate custom fields are HTTP 409,
and a malformed sync payload or decryption failure is an error, not absence.
HTTP 404 is reserved for an absent or trashed source item. A name lookup that
cannot rule out an unsupported shared item also fails rather than asserting
absence. Prefer exact item IDs.

`deletionPolicy: Retain` controls source disappearance. It does not override
Kubernetes owner references when an `ExternalSecret` itself is deleted.
`creationPolicy: Orphan` avoids ESO ownership for conservative migrations;
`creationPolicy: Owner` permits garbage collection with the owning object.
Validate the combination against a disposable target before rollout.

The published `v0.4.0` provider also returns 404 for missing properties. Review
existing deletion policies before upgrading; never interpret a field typo as
proof that an item was intentionally removed.

## Upstream failures and cache

An upstream outage normally stops new resolves after the fresh cache expires.
A successful previous cache can be served only within an explicitly enabled
stale-if-error window for eligible errors. Authentication, payload, KDF and
decryption errors are not turned into stale success. A cached secret may still
be old even after the source credential or value changes; caching is not
instant revocation.

Failed refreshes share a cooldown, including cold-cache and authentication
failures. During it the provider fails closed with HTTP 503 `upstream_backoff`
unless the separate stale policy already permits a cached value. The default
cooldown is 15 seconds; `cacheRefreshRetryIntervalSeconds: 0` restores per-request
retries. Watch refresh failures and resolve error metrics during outages.
Do not enable stale data just to hide a persistent
credential/configuration failure. Existing Kubernetes Secrets are governed by
ESO policies, not erased by this provider.

`/livez` means the HTTP process is alive. `/readyz` means it is not shutting
down; neither performs an upstream login. A ready pod can have invalid upstream
credentials. Use ESO status and refresh metrics for end-to-end health rather
than making upstream outages trigger liveness restart loops.

## Policy updates and revocation

ConfigMap and Secret projection plus the configured reload interval delay
policy activation. Missing, malformed or empty policy reloads retain the last
known-good configuration. Deleting or emptying a policy file is **not** a
revoke-all mechanism. Inline policy entries are unioned with file entries and
cannot be revoked by editing the file alone.

For a scoped token, remove its capability or token from an otherwise valid,
nonempty policy. Check successful reload metrics and verify the old token
receives 401 from every provider replica. A successful ConfigMap/Secret apply
alone does not prove that the running process has revoked access. During normal
rotation, overlap a replacement token, move the caller, then remove the old one.

For immediate full revocation, isolate/stop the affected provider deployment
and rotate compromised upstream credentials and caller tokens before restoring
service. Account isolation determines the blast radius. Removing a webhook
token does not retract values already copied into Kubernetes Secrets or read
by consumers. Rotate those downstream credentials separately where required.

Upstream client ID, client secret and master password are read at startup; file
mount changes alone do not reload them. Update the Secret and roll the provider.
Legacy single-token authentication also needs a rollout to change its token.

## KDF and resource failures

On current source, Argon2 account costs above `config.argon2MemoryLimitMiB`
fail before allocation. The default budget is 64 MiB and the chart memory limit
is 256 MiB. Increase the memory limit together with the budget, allowing for
responses, encrypted cache, decrypted values and allocator overhead.
The budget does not bound total process memory. CPU throttling can extend cold
unlocks; align ESO timeout with the measured cold path and upstream deadlines.
Do not lower the account's KDF merely to fit a small pod.

## Bootstrap and rollback

Keep Vaultwarden's own bootstrap credentials, ESO/bootstrap dependencies and
the provider's credentials recoverable outside the secret chain they start.
Otherwise a restored cluster can depend on a provider that cannot yet log in.
Maintain a tested backup/restore path without writing raw secrets into Git.

For a failed upgrade, stop reconciliation as appropriate, restore the previous
pinned image/chart and confirm compatibility of its configuration. Restore any
changed downstream credentials deliberately; rolling back software does not
undo source rotation or resurrect a deleted secret. Verify consumer health
without printing secret data.
