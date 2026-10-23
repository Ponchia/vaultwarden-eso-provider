# Stable 0.5.0 readiness

`v0.5.0` is **not published**. The source prepares `v0.5.0-rc.2`, a security
maintenance prerelease with refreshed TLS and constant-time dependencies.
GitHub Releases records publication and exact artifact evidence. The recorded
`v0.5.0-rc.1` acceptance remains historical evidence and does not qualify the
new dependency graph.

On 16 October 2026 the maintainer deferred Bitwarden Cloud acceptance. The
prepared `0.5.0` release now has **Vaultwarden-only qualification**: issue #75
is follow-up work, not a release blocker. Cloud support remains unverified;
no Cloud test was run or recorded as passed by changing this policy. External
review and measured load/soak work remain separate in #76; no audit is claimed.

## Backend release scope

`release-readiness.json` schema 2 declares `releaseScope: vaultwarden-only`
and `cloud: {status: deferred, issue: 75}`. Its `targetVersion` follows the exact
distribution version, currently `0.5.0-rc.2`. Both the admission script and the
signed distribution validator enforce that exact boundary. Missing/unknown
scopes, a changed target version, private fields or a fabricated Cloud pass are
refused. The deferral is shipped in the checksum-covered readiness attachment.

A passing backend-scope gate is not a completed release. The existing exact-head
Rust, security, interoperability and **both native Vaultwarden/ESO packaged
checks** remain mandatory through `release_gates.py`. Public artifact signatures,
checksums, provenance and post-publication verification remain unchanged.
The scope decision itself changes no endpoints, credentials or deployment.
A separately discovered rustls patch is included below and requires fresh
exact-head qualification. Publication still needs maintainer authorization.

## What the distribution includes

Release automation now assembles Linux AMD64 and ARM64 archives from the
**same binaries extracted from the published containers**, not another build.
Each archive includes `LICENSE` and `THIRD-PARTY-LICENSES.txt`. Dependency
notices are generated with checksum-pinned cargo-about 0.9.2 from the locked
runtime Cargo graph, and CI rejects stale notices. Container images include
those notices as well.

The complete release attachment set is the Helm archive and its Sigstore
bundle, both native archives, both runtime SPDX SBOMs, dependency notices,
`release-manifest.json`, the redacted `release-readiness.json`, `SHA256SUMS`,
and `SHA256SUMS.sigstore.json`.
The checksum signature covers the exact payload allowlist, including the
machine-readable inventory. GitHub provenance attests the distribution files.
The signature bundle cannot include its own checksum. Source archives are
provided separately by GitHub.

These attachments are produced by the updated release workflow. They are not
retroactively claimed as attachments of the earlier `0.5.0-rc.1` release.
Candidate Actions artifacts exercise the same native packaging and verify each
archive's binary against the actual image binary before retention.

An SPDX inventory includes the exact executable checksum and the locked,
target-filtered normal Cargo dependency graph with registry crate checksums.
Membership and relationships come from `cargo tree`; Cargo metadata alone can
include disabled optional dependencies and is used only for package details.
This avoids relying on image scanners that cannot enumerate static Rust
dependencies. Build-only and dev-only edges are excluded. The graph is declared
source-dependency evidence, not a byte-level linker inventory or a guarantee
that every embedded component has been identified. The notices and inventory
are not a legal opinion or a security certification. CI validates every
distributed inventory against the
checksum-pinned upstream SPDX 2.3 schema.

## Locked dependencies and static analysis

The CI run for this scope change also found four newly published rustls
advisories. `Cargo.lock` now selects **rustls 0.23.46** for
[RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346),
[RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html),
[RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) and
[RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html).
Dependency notices are regenerated. This patch changes the runtime-input
fingerprint, so source/native qualification must run again on its exact commit;
old binary evidence is not reused as proof for the patched artifact.
Advisory checks remain enabled; this is not a claim that every advisory was
reachable in the provider's configured feature set.

CI audits the complete lockfile as well as the configured dependency graph.
This catches vulnerable optional dependencies even when they are disabled in
the provider build. The `quinn-proto` lock entry is updated to 0.11.18 for
RUSTSEC-2026-0338 through RUSTSEC-2026-0342; the provider does not enable HTTP/3.
The active SPDX inventory excludes disabled optional entries.

Fixed cryptographic known-answer vectors belong to test-only modules.
Reviewed static-analysis false positives retain per-alert rationale; no
cryptography rule is disabled. Redaction tests keep their assertions while
avoiding value-bearing panic messages, even for synthetic fixtures.

## Deferred Bitwarden Cloud acceptance

Issue #75 retains the dedicated-account work for later. Do not start Cloud
account setup or run its acceptance as part of the Vaultwarden release. When
the maintainer resumes it, use only synthetic items and a dedicated test account;
authentication setup belongs in the private browser and secret manager.
Never paste credentials into public reports or GitHub Actions inputs.

The original Cloud-qualified record validator remains available and tested.
Before broadening the release's qualified backend scope, supply actual evidence:
version, Cloud region, time with timezone, architecture, source revision, exact
binary SHA-256 and runtime-input SHA-256; both PBKDF2 and Argon2 must pass
API-key unlock, field/map reads, missing property, selector denial, rotation,
restart and item deletion. A deferred or pending record cannot satisfy the
Cloud-qualified schema, and a Vaultwarden fixture cannot count as Cloud evidence.

That evidence's runtime fingerprint covers Cargo manifests/lock, Rust sources,
Dockerfile/build-context policy and the shipped Helm chart. Runtime changes or
Cloud evidence older than 30 days require requalification. Recording evidence
is not a security audit. See [live testing](live-testing.md) and
[release qualification](release-qualification.md) before resuming the work.

Inspect the prepared prerelease metadata without publishing:

```bash
bash scripts/verify-release-version.sh v0.5.0-rc.2
python3 scripts/stable_readiness.py --tag v0.5.0-rc.2
```

The prerelease admission does not claim completed stable qualification. The
signed distribution validator still requires the exact target version and
Vaultwarden-only scope with Cloud deferred. Promoting to stable requires matching
stable version metadata and fresh exact-commit evidence; a prerelease record
does not qualify `v0.5.0`.

## Complete the Vaultwarden-scoped release

Pass the exact-head source, interoperability and both native packaged checks
for the prepared `0.5.0-rc.2` candidate before creating that tag. Stable
`v0.5.0` publication remains a separate release decision. Cloud acceptance
stays deferred for the Vaultwarden-only scope.
Verify every published download and run `qualification.yml` with the tag as
both `ref` and `release_tag`. The same signed digests then go through the
existing canary and GitOps upgrade, preserving credentials and selectors.
Do not describe that Vaultwarden qualification as Bitwarden Cloud acceptance.
