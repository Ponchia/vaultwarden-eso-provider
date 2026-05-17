# Public Release Checklist

A tagged release is maintainer-initiated. Do not create a release tag, run the
release publishing workflow, or update docs to call an unreleased state the
current release unless a maintainer explicitly asks for a release.

Not every merged change needs a tagged release. Use normal pull requests for
documentation cleanup, repository hygiene, CI-only maintenance, governance
wording, and non-shipping examples unless users need a new installable chart or
image to consume the change.

When a maintainer asks for a release, release-worthy changes typically include
runtime behavior, the container image, the Helm chart, install instructions for
the current chart, dependency/security fixes users should consume, or a public
compatibility/security claim that needs to be tied to an exact artifact.

Required before calling a release generally usable:

- Commit the public collaboration files: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue templates, pull request template,
  and `CODEOWNERS`.
- Apply the GitHub repository settings documented in
  [`repository-governance.md`](repository-governance.md).
- Confirm the release branch is clean, pushed, and CI is green.
- Confirm `main` branch protection and release tag protection are active.
- Confirm merged PRs have release-note labels that match
  [`.github/release.yml`](../.github/release.yml), and update
  [`../CHANGELOG.md`](../CHANGELOG.md) for notable user-facing changes.
- Tag and publish a multi-arch image from GitHub Actions.
- Run `scripts/live-eso-smoke.sh` against real Vaultwarden and Bitwarden Cloud
  accounts with k3s or a kind cluster with ESO installed, with selector policy
  enabled. For packaging-only releases, verify the changed packaging path and
  record whether prior backend live evidence is being reused because provider
  runtime behavior did not change.
- Verify migration examples use `creationPolicy: Orphan`,
  `deletionPolicy: Retain`, and template `mergePolicy: Merge`, and that a
  deleted target Secret is recreated with identical data.
- Verify examples use `field.<key>` for migrated Kubernetes keys that collide
  with Bitwarden login field names such as `username` and `password`.
- Verify intentional empty target keys are documented and rendered through
  `target.template.data` with `mergePolicy: Merge`.
- Publish the Helm chart to GHCR as an OCI chart and attach the packaged chart
  artifact to the GitHub Release.
- Review the release image SBOM/provenance output.
- Verify the image has a keyless Sigstore signature and GitHub artifact
  attestation.
- Verify the chart archive has a Sigstore bundle and GitHub artifact
  attestation.
- Review logs for secret-value redaction under success and failure paths.
- Review metrics for secret-value and vault-item metadata redaction under success
  and failure paths.
- Review public HTTP error bodies for selector redaction because ESO can surface
  provider errors in `ExternalSecret` status and events.
- Generate Rust coverage with `cargo llvm-cov`; keep total line coverage above
  the conservative CI floor and review uncovered lines in security-sensitive
  paths before tagging.
- Verify `/livez`, `/readyz`, `/metrics`, default probes, and optional
  `ServiceMonitor` rendering.
- Import or lint the example Grafana dashboard and validate the example
  PrometheusRule before release.
- Keep Helm chart schema validation in sync with supported values.
- Verify provider-side selector policy returns redacted `403` failures.
- Verify selector policy documentation is clear that policy is item-key scoped,
  not property scoped.
- Verify unsupported organization/shared items and attachment properties fail
  explicitly and are documented.

## Artifact Evidence

Each GitHub Release must include:

- Git tag.
- Source commit.
- Image reference.
- Image index digest.
- Image signature evidence.
- Image provenance attestation evidence.
- OCI Helm chart reference.
- OCI Helm chart digest.
- Helm chart download URL.
- Helm chart SHA256.
- Helm chart Sigstore bundle.
- Helm chart provenance attestation evidence.

Generated artifact hashes belong in GitHub Release notes, not in a follow-up
post-tag commit that makes `main` look newer than the release for documentation
only.

The current public release notes are the source of truth for published artifact
digests, checksums, signatures, and attestations. See
[`release-verification.md`](release-verification.md) for consumer verification
commands.

Nice to have before `v1.0.0`:

- Native ESO provider assessment if the webhook contract becomes limiting.
- Disposable local kind integration coverage that does not need private
  credentials.
