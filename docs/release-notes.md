# 0.5.0-rc.1 upgrade notes

This is a prerelease of the Vaultwarden-to-ESO bridge. Independent native
AMD64/ARM64 package tests exercise Vaultwarden with both PBKDF2 and Argon2,
private-CA TLS, authorization, source rotation, deletion behavior and rollback.
Fresh Bitwarden Cloud acceptance is still incomplete (#75). External review
and a defined load/soak qualification remain deferred (#76). This is not a
claim of general availability or an independent security audit.

## Changes operators must account for

Missing properties now return HTTP 422, not 404. Only actual absent/trashed
items signal deletion; malformed vault responses and ambiguous fields fail
without becoming deletion. Review ESO deletion policies before an upgrade.

Argon2 salt preprocessing is corrected. Do not lower the account KDF as a
workaround for the previous release. The default accepted Argon2 memory cost
is 64 MiB; the default pod limit is 256 MiB. An existing Helm values override
of 128 MiB does not automatically increase: review resource overrides with the
account cost and allow operational headroom.

Failed upstream refreshes now share a 15-second cooldown, even with a cold
cache. That does not enable stale values. Bounded stale fallback remains off
unless explicitly configured. Existing single-token authentication continues
to work; adopting scoped tokens requires a separate deliberate policy change.

## Installation and rollback

Pin both the chart version and image digest from release evidence. Preserve
existing credentials, reviewed selector policy, trusted network controls and
consumer target names. Test in a disposable namespace before replacing a
working provider; do not delete consumer Secrets as part of an upgrade.

For rollback, restore the previous pinned chart, image and values through your
GitOps source. The `v0.4.0` PBKDF2 path is covered by package recovery tests,
but its known Argon2 bug is not a valid fallback for an Argon2 account. Restore
a known-working fixed candidate instead. Rolling back a binary cannot reverse
a source credential rotation or restore a deleted consumer Secret.
