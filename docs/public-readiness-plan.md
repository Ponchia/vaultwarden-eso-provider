# Release Readiness Plan

This file records the release-readiness decisions for Vaultwarden ESO Provider.
`v0.1.3` is public, so this document now describes the current baseline and the
rules for future releases.

## Product Shape

The project is an External Secrets Operator webhook provider for
**Vaultwarden** (and self-hosted Bitwarden Password Manager), with Bitwarden
Cloud Password Manager as a secondary supported target. Bitwarden Secrets
Manager is out of scope and is not implemented by Vaultwarden in any case.
The repository will be renamed to `vaultwarden-eso-provider` at `v0.2` (see
[roadmap.md](roadmap.md)); `v0.1.x` artifacts are being removed as part of
that rename and are not preserved for compatibility.

Do not build a native Kubernetes operator during the `v0.1.x` release line. ESO
already owns refresh intervals, target `Secret` lifecycle, deletion behavior,
status conditions, and GitOps integration. A native operator, native ESO
provider, Secrets Store CSI provider, and PushSecret support are later roadmap
items.

## Required For Public Releases

- Repository, binary crate, container image, and Helm chart are named
  `vaultwarden-eso-provider`. Project framing leads with Vaultwarden and
  self-hosted Bitwarden Password Manager; Bitwarden Cloud Password Manager
  is a secondary supported target.
- Require explicit `id:<item-id>` or `name:<item-name>` selectors. Bare
  unprefixed keys are rejected with `400 validation`. Recommend `id:` in
  production.
- Enforce optional provider-side selector policy with exact raw keys and raw key
  prefixes. Empty policy allows all keys visible to the configured account;
  configured policy denies every non-matching key with a redacted `403`.
  Document that the policy is item-key scoped, not property scoped.
- Fail selected shared organization items explicitly until organization-key
  decryption is implemented and live-tested.
- Fail `attachment.` and `attachments.` properties explicitly until attachment
  metadata lookup, download, decryption, and mapping are implemented.
- Expose low-cardinality metrics for HTTP requests, resolve outcomes, cache
  hits, cache refreshes, and last successful cache refresh age/timestamp.
- Ship Helm values and schema for selector policy and pod `hostAliases`.
- Provide examples for namespace-local `SecretStore`, warned
  `ClusterSecretStore`, common Kubernetes Secret types, Reloader, and
  NetworkPolicy starting points.
- Provide optional Grafana dashboard and PrometheusRule examples for the
  exported low-cardinality metrics.
- Document the tested migration target policy:
  `creationPolicy: Orphan`, `deletionPolicy: Retain`, and template
  `mergePolicy: Merge`.
- Recommend `field.<key>` for migrated Kubernetes keys to avoid collisions with
  Bitwarden login fields such as `username` and `password`.
- Document intentional empty target keys as ESO template data with
  `mergePolicy: Merge`.
- Keep chart NetworkPolicy opt-in for `v0.1.x`; backend, DNS, ESO, and
  Prometheus reachability is cluster-specific and a too-generic default can
  break first installs.
- Publish the packaged Helm chart to GHCR as an OCI chart and attach the same
  chart archive to tagged GitHub Releases after the release image manifest has
  been built and scanned.

## Current Validation Baseline

The public `v0.1.3` baseline has been validated with:

- CI gates for formatting, clippy, tests with coverage, Helm rendering,
  markdown linting, observability examples, Gitleaks, Trivy filesystem scanning,
  cargo-deny, Checkov, and Dockerfile build checks.
- CodeQL code scanning for Rust and GitHub Actions workflow files.
- Local advisory scans used during release review, including Semgrep and
  SonarQube where available. These are review tools unless they are present in
  the GitHub workflow for that commit.
- `scripts/live-eso-smoke.sh` against Vaultwarden on a k3s cluster with
  selector policy enabled.
- `scripts/live-eso-smoke.sh` against Bitwarden Cloud with selector policy
  enabled for the `v0.1.1` runtime path; releases without provider protocol
  changes may reuse that evidence.
- A tagged GitHub Release that publishes a multi-arch image, a GHCR OCI Helm
  chart, and a packaged Helm chart archive from the release commit.
- Public repository controls for branch protection, tag protection, secret
  scanning, Dependabot alerts, security policy, issue templates, and CODEOWNERS.

## Future Release Gate

Releases are maintainer-initiated. Do not tag or publish a release simply
because work has landed on `main`; wait until the maintainer says the current
state is ready to release.

Not every repository change needs a release. Documentation cleanup,
governance-only edits, CI-only maintenance, and source-tree hygiene can land on
`main` without a new tag when the latest published chart and image remain the
recommended installable artifacts.

For each release:

- Run the GitHub CI workflow to green.
- Run the release workflow from the exact tag or commit being released.
- Confirm the release OCI chart and attached chart artifact are published only
  after the image manifest and release image scan succeed.
- Run live smoke tests against Vaultwarden and Bitwarden Cloud with selector
  policy enabled when provider runtime behavior changes. Packaging-only releases
  may reuse prior backend live evidence if fake-server coverage and the changed
  packaging path are both verified.
- Record the image index digest and chart checksum in the GitHub Release notes.
  Generated artifact hashes should not require a follow-up commit after tagging.

## Deferred

- Organization/shared item decryption.
- Attachment support.
- Stale-cache-on-upstream-outage behavior.
- Disposable kind integration that does not require private credentials.
- GitHub Pages chart repository.
- Native operator or native ESO provider.
