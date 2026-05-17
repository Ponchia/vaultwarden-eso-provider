# Release Verification

Each tag produced by the current release workflow publishes a multi-arch image,
an OCI Helm chart, a downloadable chart archive, generated release notes, and
release evidence. Older tags may have fewer evidence artifacts; use the exact
GitHub Release notes for the tag you install.

Use the exact image digest, chart digest, and chart archive SHA256 from the
release notes.

Set the version and evidence values from the GitHub Release:

```bash
VERSION="<published-version>"
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
CERT_ID_RE="https://github.com/Ponchia/vaultwarden-eso-provider/"
CERT_ID_RE="${CERT_ID_RE}.github/workflows/release.yml@refs/tags/v.*"

cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "${CERT_ID_RE}" \
  "${IMAGE}"
```

Verify the GitHub artifact attestation for the image:

```bash
gh attestation verify "oci://${IMAGE}" \
  --repo Ponchia/vaultwarden-eso-provider \
  --signer-workflow \
  "Ponchia/vaultwarden-eso-provider/.github/workflows/release.yml"
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
  "Ponchia/vaultwarden-eso-provider/.github/workflows/release.yml"
```

Verify the Sigstore bundle attached to the GitHub Release:

```bash
cosign verify-blob \
  --bundle "vaultwarden-eso-provider-${VERSION}.tgz.sigstore.json" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "${CERT_ID_RE}" \
  "vaultwarden-eso-provider-${VERSION}.tgz"
```

The OCI Helm chart digest in the release notes is separate from the `.tgz`
archive SHA256. Use the OCI digest for registry audit trails and the archive
SHA256 for the file attached to the GitHub Release.
