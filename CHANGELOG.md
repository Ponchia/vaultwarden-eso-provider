# Changelog

All notable user-facing changes are tracked here. GitHub Releases are the
source of truth for published artifact digests, generated release notes,
signatures, attestations, and chart archive checksums.

Release notes are generated from merged pull requests using
[`.github/release.yml`](.github/release.yml). Maintainers should label PRs
before release so generated notes land in the right category.

## v0.5.0 — Unreleased

- Patch the locked TLS dependency to rustls 0.23.46 for RUSTSEC-2026-0346
  through RUSTSEC-2026-0349; regenerate dependency notices and repeat the
  exact-head native qualification. Keep advisory auditing enforced.

- Update the optional locked QUIC dependency past five published advisories;
  keep disabled dependencies out of the actual distribution inventory.
- Keep redaction-test failures value-free without weakening assertions.

- Add Linux AMD64/ARM64 binary archives extracted from the exact container,
  runtime SPDX inventories, generated Cargo dependency notices, a complete
  release manifest, signed checksums and public-download verification.
- Include dependency notices in the container and reject stale attribution.
- Verify OCI chart manifest identity as well as signed chart archive bytes.
- Scope 0.5.0 release qualification to Vaultwarden only. Defer Bitwarden Cloud
  acceptance (#75) without fabricating a pass or blocking that release; retain
  exact-head source, security, interoperability and both native artifact gates.
  Ship the explicit deferral in the signed readiness record. `0.5.0` is not published.
- Add the project funding link and clarify supported-version expectations.

## v0.5.0-rc.1 - 2026-10-13

Prerelease: Vaultwarden packages are qualified on AMD64 and ARM64. Current
Bitwarden Cloud qualification remains open; see the release notes for exact
publication and validation evidence.

- Gate publishing on ten passing exact-commit source and packaged checks.
- Mark prereleases explicitly and preserve stable/latest container aliases.
- Verify signed published chart/image bytes without rebuilding them, including
  exact source and signer identity, before deployment qualification.
- Exercise packaged private-CA TLS, restart, target recreation and rollback to
  the pinned previous release and back. Retain only credential-free artifacts.

- Throttle failed refresh bursts even with a cold cache or authentication
  failure; cooldown responses fail closed and never grant stale reads.
- Raise the declared Rust minimum to 1.89 to match the selected AES dependency,
  and add a locked all-target build check on that minimum compiler.

- Add independently bootstrapped Vaultwarden/ESO CI without private credentials.
- Require explicit test account opt-in/context for release smoke testing; never
  adopt or clean an existing namespace or persist credentials in apply metadata.
- Consolidate operator and release documentation and check local links in CI.

- Correct Password Manager Argon2 salt preprocessing with independently
  generated interoperability vectors; the published v0.4.0 path is affected.
- Move KDF work off async workers and enforce an operator Argon2 memory budget.
- Return 422 for a missing property; reserve 404 for actual item absence.
- Reject malformed sync responses without a ciphers array instead of treating
  them as an empty vault, and exclude soft-deleted items from lookup.
- Propagate name-lookup decryption failures rather than report false absence.
- Reject duplicate single-property custom fields; wipe owned plaintext models
  and temporary unlock buffers on drop.
- Bound policy-file reads directly instead of relying on a preceding stat.
- Increase default pod memory to 256 MiB and ESO example timeouts to 90 seconds.

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
