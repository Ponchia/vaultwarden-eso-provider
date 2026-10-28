# Repository Governance

This document captures the public repository settings for Vaultwarden ESO
Provider.

## Current Repository Settings

- Visibility: public.
- Issues: enabled.
- Discussions: optional; enable only if issue traffic becomes noisy.
- Wiki: disabled. Keep one reviewed documentation source in Git rather than
  duplicating instructions across a wiki and the repository.
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
  - `Minimum Rust`
  - `Vaultwarden and ESO`
  - `License notices`
  - `Packaged provider (amd64)`
  - `Packaged provider (arm64)`
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

Use Scorecard findings as current review inputs, not automatic dismissal rules.
Read the actual result and repository settings. Do not carry historical claims
such as "younger than 90 days" into a later review. The solo-maintainer review
constraint above is explicit; it is not equivalent to independent code review.
Record any accepted risk with its reason and revisit it when maintainers or
project usage change. Badges do not replace security or compatibility evidence.

## Release Permissions

Only maintainers should be able to push tags matching `v*`. Release tags publish
multi-arch images and Helm chart artifacts, so tag protection must remain active
for those tags.

Release notes are generated from pull request labels with
[`.github/release.yml`](../.github/release.yml). Keep the label taxonomy in
[`.github/labels.yml`](../.github/labels.yml) aligned with release-note
categories.

## Allowed Workflow Actions

Keep selected-actions policy enabled. GitHub-owned actions are allowed; each
third-party action must match an explicitly reviewed immutable commit SHA.
Do not use wildcard allowlists to make a dependency PR pass.

The workflow files are the source of truth for direct action revisions. Inspect
the proposed action metadata and changes, then add its exact revision to the
existing repository allowlist **before running the PR checks**. Also review
transitive actions: the pinned Trivy action invokes
`aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514`.

### Actions-group qualification (28 October 2026)

The grouped Dependabot update originally opened as PR #89 changed seven
workflow files. The original CI, dependency-audit and interoperability
workflows failed at GitHub startup **before creating jobs**.
GitHub's annotations identified newly proposed immutable action SHAs
missing from the selected-actions policy.

After reviewing the upstream commits, the existing restricted policy was
extended by **only three exact refs**, preserving the previous 34 entries:

- Swatinem/rust-cache@c8037a86dde8214a8310e9f54a8fc61ab362aa31
- taiki-e/install-action@1e29709c0ec63babbe8f266397a465f29a825f91
- docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6

The CodeQL sub-actions are GitHub-owned and remain pinned to a single
matching revision. No wildcard allowance, verified-creator broadening,
workflow-token permission change, or protected-branch exception was made.

The original startup failures contain **no test evidence**. The action
changes are reproduced with the Dependabot commit attribution preserved in
a maintainer-owned qualification PR so GitHub can run the complete required
check matrix against a fresh exact head. Preserve the original PR as
historical context and close it as superseded only once the replacement
has passed required gates and merged.

Read the live allowlist with:

```bash
gh api repos/Ponchia/vaultwarden-eso-provider/actions/permissions/selected-actions
```

Preserve unrelated entries and permission flags. Keep old immutable pins while
supported release branches still reference them. Re-read the policy after a
change and compare sets rather than list ordering. A blocked workflow can fail
at startup without creating any required check; the absence of red check runs
is not a successful validation. Some startup failures cannot be rerun and need
a new PR commit after the exact pin is admitted.

Update every CodeQL sub-action together (`init`, `analyze`, `upload-sarif`).
Updating only `init` leaves a mixed-version pipeline. Dependabot groups Actions
updates to keep those revisions aligned.

## Dependabot Policy

Dependabot patch-only PRs may use the existing automated merge workflow only
after the required checks pass on the current head.
Minor and major updates stay manual because Rust `0.x` crates can contain API
changes in semver-minor updates, and Docker/toolchain updates can change clippy
behavior. Known incompatible RustCrypto block-cipher and reqwest 0.x
semver-minor updates are ignored until a maintainer plans those migrations.
Related RustCrypto KDF/MAC/hash crates are grouped so Dependabot does not open
incompatible one-crate-at-a-time updates.
