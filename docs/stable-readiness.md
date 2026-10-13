# Stable 0.5.0 readiness

`v0.5.0` is **not published**. `v0.5.0-rc.1` remains the available prerelease;
its exact published packages and the maintainer's Vaultwarden installation
have passed the recorded acceptance tests. Fresh dedicated-account Bitwarden
Cloud verification is still pending in issue #75. External review and measured
load/soak work remain separate in #76; no independent audit is claimed.

## What the distribution includes

Release automation now assembles Linux AMD64 and ARM64 archives from the
**same binaries extracted from the published containers**, not another build.
Each archive includes `LICENSE` and `THIRD-PARTY-LICENSES.txt`. Dependency
notices are generated with checksum-pinned cargo-about 0.9.2 from the locked
runtime Cargo graph, and CI rejects stale notices. Container images include
those notices as well.

The complete release attachment set is the Helm archive and its Sigstore
bundle, both native archives, both runtime SPDX SBOMs, dependency notices,
`release-manifest.json`, `SHA256SUMS`, and `SHA256SUMS.sigstore.json`.
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
This avoids relying on image scanners that cannot enumerate static Rust
dependencies. Build-only and dev-only edges are excluded. The graph is declared
source-dependency evidence, not a byte-level linker inventory or a guarantee
that every embedded component has been identified. The notices and inventory
are not a legal opinion or a security certification.

## Remaining backend evidence

Use only a dedicated test account and synthetic items. Authentication setup
belongs in the operator's private browser and secret manager. Never paste
account credentials into a public report or GitHub Actions inputs. The existing
[live test instructions](live-testing.md) explain credential and cluster
boundaries; [release qualification](release-qualification.md) distinguishes
source builds, published packages and Cloud evidence.

Before stable publication, record the following in `release-readiness.json`:

- The `0.5.0` target version, Cloud region, time with timezone, architecture,
  tested source revision, exact binary SHA256 and runtime-input SHA256.
- A passed result for both PBKDF2 and Argon2: API-key unlock, field/map reads,
  missing property, selector denial, rotation, restart and item deletion.

The runtime-input fingerprint covers Cargo manifests/lock, Rust sources,
Dockerfile/build-context policy and the shipped Helm chart. It excludes the
report itself, so recording a result does not invalidate that result. A runtime
change invalidates the evidence; tests more than 30 days old must be repeated.
The public record intentionally has no fields for account identities, item
selectors, credentials, returned values or private URLs.

Inspect without publishing:

```bash
python3 scripts/stable_readiness.py --tag v0.5.0 --status
```

The release workflow invokes the strict form for stable tags and refuses
pending, stale, incomplete or unrelated Cloud evidence. This is a maintainer's
source-bound test record, not an independent verifier of the person who ran it.
A green CI build cannot turn a pending backend result into a pass.

## Complete the release

Finish the dedicated account, run the Cloud acceptance against the final
candidate and add its redacted result. Align all package/chart versions and
upgrade notes, then pass the exact-head source and both native packaged checks.
Create the authorized `v0.5.0` tag only after the strict readiness check passes.
Verify every published download and run `qualification.yml` with that tag as
both `ref` and `release_tag`. The same signed digests then go through the
existing canary and GitOps upgrade, preserving credentials and selectors.
