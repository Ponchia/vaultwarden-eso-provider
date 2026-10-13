# Release Verification

Each tag produced by the current release workflow publishes a multi-arch image,
an OCI Helm chart, a downloadable chart archive, generated release notes, and
release evidence. Older tags may have fewer evidence artifacts; use the exact
GitHub Release notes for the tag you install.

The release workflow verifies the GitHub Release after upload. A current tag
must have a non-empty release body, the chart archive, the chart Sigstore
bundle, and the digest/checksum evidence referenced below.

Use the exact image digest, chart digest, and chart archive SHA256 from the
release notes.

Set the version and evidence values from the GitHub Release:

```bash
VERSION="<published-version>"
SOURCE_COMMIT="<exact-source-commit-from-release-evidence>"
IMAGE="ghcr.io/ponchia/vaultwarden-eso-provider@sha256:<image-digest>"
CHART_REF="oci://ghcr.io/ponchia/charts/vaultwarden-eso-provider"
CHART_SHA256="<chart-archive-sha256>"
```

## Image Digest

Install by digest whenever possible:

```bash
helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --version "${VERSION}" \
  --set-string image.digest="${IMAGE#*@}"
```

Verify the keyless Sigstore signature attached to the image digest:

```bash
CERT_ID="https://github.com/Ponchia/vaultwarden-eso-provider/"
CERT_ID="${CERT_ID}.github/workflows/release.yml@refs/tags/v${VERSION}"

cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "${CERT_ID}" \
  "${IMAGE}"
```

Verify the GitHub artifact attestation for the image:

```bash
gh attestation verify "oci://${IMAGE}" \
  --repo Ponchia/vaultwarden-eso-provider \
  --signer-workflow \
  "Ponchia/vaultwarden-eso-provider/.github/workflows/release.yml" \
  --source-ref "refs/tags/v${VERSION}" \
  --source-digest "${SOURCE_COMMIT}" \
  --deny-self-hosted-runners
```

## Helm Chart

Pull the chart archive and verify its checksum:

```bash
helm pull "${CHART_REF}" --version "${VERSION}"
printf '%s  vaultwarden-eso-provider-%s.tgz\n' \
  "${CHART_SHA256}" "${VERSION}" | sha256sum -c -
```

Verify the chart archive provenance attestation:

```bash
gh attestation verify "vaultwarden-eso-provider-${VERSION}.tgz" \
  --repo Ponchia/vaultwarden-eso-provider \
  --signer-workflow \
  "Ponchia/vaultwarden-eso-provider/.github/workflows/release.yml" \
  --source-ref "refs/tags/v${VERSION}" \
  --source-digest "${SOURCE_COMMIT}" \
  --deny-self-hosted-runners
```

Verify the Sigstore bundle attached to the GitHub Release:

```bash
cosign verify-blob \
  --bundle "vaultwarden-eso-provider-${VERSION}.tgz.sigstore.json" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "${CERT_ID}" \
  "vaultwarden-eso-provider-${VERSION}.tgz"
```

The OCI Helm chart digest in the release notes is separate from the `.tgz`
archive SHA256. Use the OCI digest for registry audit trails and the archive
SHA256 for the file attached to the GitHub Release.

## Complete distribution bundles

The stable-preparation workflow adds `release-manifest.json`, `SHA256SUMS`,
its Sigstore bundle, Linux AMD64/ARM64 archives, runtime SPDX inventories and
Cargo dependency notices. Earlier releases, including `0.5.0-rc.1`, do not
contain that entire attachment set. Check the exact release before using this
verification path.

Verify `SHA256SUMS.sigstore.json` with `cosign verify-blob` using the **exact**
release workflow identity and tag, then run `sha256sum --check SHA256SUMS` in
the downloaded directory. A checksum fetched alongside files is not by itself
authenticity verification; verify its signature first. Native archives contain
the same executable extracted from the published container, not a separate
source build. They include the project license and dependency notices.

For a current checkout's stricter allowlist verification:

```bash
python3 scripts/release_bundle.py verify --directory /path/to/downloads
```

This checks both platform archives, safe member names and types, matching
notices, SPDX document shape, exact manifest hashes and checksum membership.
Signature/provenance verification is a separate prerequisite, not something
this offline structural check silently assumes it has performed.
