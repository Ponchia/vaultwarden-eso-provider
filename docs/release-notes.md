# 0.5.0-rc.2 upgrade notes

These notes describe the `0.5.0-rc.2` security maintenance prerelease candidate.
The GitHub Releases page is the source of truth for available versions.
**Release qualification scope: Vaultwarden only.** Bitwarden Cloud acceptance
is deferred in #75 and is not a blocker for this release. Cloud support remains
unverified, not passed; split-endpoint implementation is not certification.
The exact-head Vaultwarden, security, native-package and signed-artifact gates
still apply; see [stable readiness](stable-readiness.md).

The locked TLS dependency is patched to rustls 0.23.46 for four published
advisories. The October maintenance also updates the certificate verifier,
trusted roots and constant-time utility dependencies for RUSTSEC-2026-0381,
RUSTSEC-2026-0382 and RUSTSEC-2026-0385. Dependency notices and exact-head
qualification follow the patched lockfile.

The `0.5.0-rc.2` distribution adds native AMD64/ARM64 archives, exact executable and
Cargo dependency SPDX inventories, dependency notices and a signed complete
release checksum inventory. Native archives contain the same executable as the
container image. The lockfile fixes five optional QUIC advisories; the provider
does not enable HTTP/3. Whole-lock auditing prevents inactive dependencies from
being overlooked by configured-graph security checks.

Independent external review and a defined load/soak qualification remain
separate in #76. Pre-1.0 stable does not imply an independent security audit,
long-term support or support for organization/shared items and attachments.

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
