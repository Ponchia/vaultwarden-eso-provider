# Repository Governance

This document captures the public repository settings for Bitwarden ESO
Provider.

## Current Repository Settings

- Visibility: public.
- Issues: enabled.
- Discussions: optional; enable only if issue traffic becomes noisy.
- Wiki: disabled. Keep docs in Git.
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

For a solo-maintainer repository, do not require CODEOWNERS approval or one
approving review yet; self-authored maintenance PRs and Dependabot patch PRs
would otherwise be blocked without a second trusted reviewer. Add required
reviews and CODEOWNERS approval when there is at least one additional active
maintainer.

Do not require signed commits or a merge queue for now. Those can be added later
once external contribution volume justifies them.

## Release Permissions

Only maintainers should be able to push tags matching `v*`. Release tags publish
multi-arch images and Helm chart artifacts, so tag protection must remain active
for those tags.

## Allowed Workflow Actions

Keep the repository Actions policy restricted to GitHub-owned actions plus these
third-party action patterns used by CI and release workflows:

- `aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514`
- `aquasecurity/trivy-action@v0.36.0`
- `azure/setup-helm@v5`
- `docker/build-push-action@v7`
- `docker/login-action@v4`
- `docker/metadata-action@v6`
- `docker/setup-buildx-action@v4`
- `dtolnay/rust-toolchain@stable`
- `softprops/action-gh-release@v3`
- `Swatinem/rust-cache@v2`
- `taiki-e/install-action@v2`

`aquasecurity/setup-trivy` is not referenced directly by repository workflows;
it is the transitive setup action invoked by the pinned Trivy action.

## Dependabot Policy

Dependabot patch-only PRs are safe to merge automatically after CI succeeds.
Minor and major updates stay manual because Rust `0.x` crates can contain API
changes in semver-minor updates, and Docker/toolchain updates can change clippy
behavior. Related RustCrypto KDF/MAC/hash crates are grouped so Dependabot does
not open incompatible one-crate-at-a-time updates.
