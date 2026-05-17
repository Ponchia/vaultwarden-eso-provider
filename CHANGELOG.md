# Changelog

All notable user-facing changes are tracked here. GitHub Releases are the
source of truth for published artifact digests, generated release notes,
signatures, attestations, and chart archive checksums.

Release notes are generated from merged pull requests using
[`.github/release.yml`](.github/release.yml). Maintainers should label PRs
before release so generated notes land in the right category.

## Unreleased

Recommended next version: `v0.3.0`, because the unreleased changes include
pre-`v1.0.0` breaking runtime and chart defaults.

- Breaking: hardened selector-policy defaults so installs must configure an
  allowlist or explicitly opt in to allow-all behavior.
- Breaking: when `networkPolicy.enabled=true`, the default empty ingress and
  egress rule lists are deny-all until operators provide cluster-specific
  rules.
- Added custom CA bundle validation, safer redacted debug output, and
  additional zeroization for plaintext/decrypted buffers.
- Tightened Helm NetworkPolicy defaults and added release evidence,
  signing, attestation, Scorecard, and release-note automation.
- Documentation: shortened the README and added a docs index, selector/policy
  reference, and GitHub Wiki strategy.

## v0.2.1 - 2026-05-17

- Published the renamed `vaultwarden-eso-provider` chart, image, and binary.
- Documented the current public `v0.2.1` baseline and install path.
- Kept historical Vaultwarden `v0.1.3` and Bitwarden Cloud `v0.1.1` smoke
  evidence for the unchanged login/sync protocol path.
