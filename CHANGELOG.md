# Changelog

All notable user-facing changes are tracked here. GitHub Releases are the
source of truth for published artifact digests, generated release notes,
signatures, attestations, and chart archive checksums.

Release notes are generated from merged pull requests using
[`.github/release.yml`](.github/release.yml). Maintainers should label PRs
before release so generated notes land in the right category.

## Unreleased

- Added capability-scoped webhook authentication: a Secret-mounted JSON policy
  can define multiple bearer-token sets with independent exact/prefix selector
  allowlists. Scoped tokens are intersected with the existing global selector
  policy, support overlap during rotation, and hot-reload with last-known-good
  fallback and redacted metrics.
- Added opt-in bounded stale-cache fallback for transient upstream failures,
  with refresh retry throttling and a dedicated Prometheus counter. The default
  remains fail closed.

## v0.4.0 - 2026-07-22

- Reject ambiguous whole-item documents when custom fields collide with
  conventional login, notes, or SSH-key fields instead of silently replacing
  values.
- Allow concurrent reads from a fresh encrypted vault cache while retaining
  single-flight refreshes.
- Bound successful upstream JSON responses at 32 MiB and bound authenticated
  resolve-body reads at 10 seconds.
- Read and validate request bodies before taking a resolve-concurrency permit,
  preventing slow clients from occupying upstream/decryption capacity.
- Split missing-item and missing-property metrics into `item_not_found` and
  `property_not_found`, and add `ambiguous_document`, `upstream_payload`, and
  `request_timeout` error classes.

## v0.3.0 - 2026-06-12

- Breaking: hardened selector-policy defaults so installs must configure an
  allowlist or explicitly opt in to allow-all behavior.
- Breaking: when `networkPolicy.enabled=true`, the default empty ingress and
  egress rule lists are deny-all until operators provide cluster-specific
  rules.
- Added custom CA bundle validation, safer redacted debug output, and
  additional zeroization for plaintext/decrypted buffers.
- Tightened Helm NetworkPolicy defaults and added release evidence,
  signing, attestation, Scorecard, and release-note automation.
- Bumped the Docker build image to `rust:1.96-alpine`.
- Documentation: shortened the README and added a docs index, selector/policy
  reference, and GitHub Wiki strategy.

## v0.2.1 - 2026-05-17

- Published the renamed `vaultwarden-eso-provider` chart, image, and binary.
- Documented the current public `v0.2.1` baseline and install path.
- Kept historical Vaultwarden `v0.1.3` and Bitwarden Cloud `v0.1.1` smoke
  evidence for the unchanged login/sync protocol path.
