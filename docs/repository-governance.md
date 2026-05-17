# Repository Governance

This document captures the public repository settings for Vaultwarden ESO
Provider.

## Current Repository Settings

- Visibility: public.
- Issues: enabled.
- Discussions: optional; enable only if issue traffic becomes noisy.
- Wiki: disabled. Keep docs in Git. If the wiki is enabled later, use it only
  as a curated mirror or navigation front door; see
  [`github-wiki.md`](github-wiki.md).
- Projects: disabled unless there is an active public roadmap board.
- Merge strategy: squash merge enabled, merge commits disabled, rebase merge
  disabled.
- Squash commit message: pull request title and description.
- Delete branch on merge: enabled.
- Auto-merge: keep manual for normal pull requests. Dependabot patch-only PRs
  may be merged automatically by the repository workflow after CI succeeds.
- Allow update branch: enabled.
- Topics: `bitwarden`, `vaultwarden`, `external-secrets`, `external-secrets-operator`,
  `kubernetes`, `rust`, `helm`, `secrets-management`.
- Security features: CodeQL code scanning, secret scanning, push protection,
  Dependabot alerts, Dependabot security updates, security policy, and private
  vulnerability reporting should stay enabled.
- Actions policy: selected actions only. Allow GitHub-owned actions and the
  explicitly listed third-party workflow actions used by this repository.
- Default workflow token permission: read-only. Jobs that publish images,
  upload code scanning results, or attach release artifacts must request their
  additional permissions explicitly.
- Package visibility: the release image and OCI Helm chart packages must be
  public so Kubernetes clusters can pull
  `ghcr.io/ponchia/vaultwarden-eso-provider:<version>` and
  `oci://ghcr.io/ponchia/charts/vaultwarden-eso-provider` without registry
  credentials.

## Main Branch Protection

Protect `main` with these rules:

- Require a pull request before merging.
- Require conversation resolution before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Required checks:
  - `Rust`
  - `Helm`
  - `Security`
  - `Docker`
  - `CodeQL Rust`
  - `CodeQL Actions`
- Include administrators.
- Block force pushes.
- Block deletions.

`OpenSSF Scorecard` runs on `main`, schedule, and manual dispatch and uploads
SARIF as post-merge security evidence. Do not make it a required PR check unless
the workflow is changed to report on pull-request commits.

For a solo-maintainer repository, do not require CODEOWNERS approval or one
approving review yet; self-authored maintenance PRs and Dependabot patch PRs
would otherwise be blocked without a second trusted reviewer. Add required
reviews and CODEOWNERS approval when there is at least one additional active
maintainer.

Do not require signed commits or a merge queue for now. Those can be added later
once external contribution volume justifies them.

## OpenSSF Scorecard Findings

Treat Scorecard findings as triage signals, not automatic policy. The following
open findings are accepted until the repository has more project history or a
second active maintainer:

- `Maintained`: the repository is public but still younger than 90 days.
- `Code-Review`: there are not yet enough approved pull requests for Scorecard
  to assign credit.
- `Branch-Protection`: requiring one approving review or CODEOWNERS approval
  would block a solo maintainer while administrator enforcement is enabled.
- `CII-Best-Practices`: pursue the OpenSSF Best Practices Badge before `v1.0.0`;
  it is not a `v0.3.0` release blocker.

Dismiss these alerts in GitHub code scanning with this rationale after each
Scorecard SARIF upload, unless the repository maintainer model has changed.

## Release Permissions

Only maintainers should be able to push tags matching `v*`. Release tags publish
multi-arch images and Helm chart artifacts, so tag protection must remain active
for those tags.

Release notes are generated from pull request labels with
[`.github/release.yml`](../.github/release.yml). Keep the label taxonomy in
[`.github/labels.yml`](../.github/labels.yml) aligned with release-note
categories.

## Allowed Workflow Actions

Keep the repository Actions policy restricted to GitHub-owned actions plus the
third-party action SHAs used by CI and release workflows:

- `aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514`
- `aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25`
- `azure/setup-helm@dda3372f752e03dde6b3237bc9431cdc2f7a02a2`
- `docker/build-push-action@bcafcacb16a39f128d818304e6c9c0c18556b85f`
- `docker/login-action@4907a6ddec9925e35a0a9e82d7399ccc52663121`
- `docker/metadata-action@030e881283bb7a6894de51c315a6bfe6a94e05cf`
- `docker/setup-buildx-action@4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd`
- `dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8`
- `ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a`
- `sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6`
- `softprops/action-gh-release@b4309332981a82ec1c5618f44dd2e27cc8bfbfda`
- `Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32`
- `taiki-e/install-action@7be9fd86bd1707236395105d6e9329dd1511a7e1`

`aquasecurity/setup-trivy` is not referenced directly by repository workflows;
it is the transitive setup action invoked by the pinned Trivy action.
When Dependabot updates a pinned action SHA, update this allowlist before
merging so the next workflow run is not blocked by selected-actions policy.

## Dependabot Policy

Dependabot patch-only PRs are safe to merge automatically after CI succeeds.
Minor and major updates stay manual because Rust `0.x` crates can contain API
changes in semver-minor updates, and Docker/toolchain updates can change clippy
behavior. Known incompatible RustCrypto block-cipher and reqwest 0.x
semver-minor updates are ignored until a maintainer plans those migrations.
Related RustCrypto KDF/MAC/hash crates are grouped so Dependabot does not open
incompatible one-crate-at-a-time updates.
