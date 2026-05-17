# Vaultwarden ESO Provider

[![CI](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Ponchia/vaultwarden-eso-provider?include_prereleases&sort=semver)](https://github.com/Ponchia/vaultwarden-eso-provider/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ponchia/vaultwarden-eso-provider/badge)](https://scorecard.dev/viewer/?uri=github.com/Ponchia/vaultwarden-eso-provider)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Unofficial [External Secrets Operator](https://external-secrets.io/) webhook
provider for **Vaultwarden**, self-hosted **Bitwarden Password Manager**, and
**Bitwarden Cloud Password Manager** vault items.

The provider lets ESO read Password Manager vault items and materialize normal
Kubernetes Secrets. It is not a Bitwarden Secrets Manager (`bws`) integration;
that is a separate Bitwarden product surface and Vaultwarden does not implement
it.

```text
Vaultwarden or Bitwarden Password Manager
        |
        | user API key + master-password unlock + local item decryption
        v
vaultwarden-eso-provider
        |
        | ESO webhook provider
        v
External Secrets Operator
        |
        v
Kubernetes Secret
```

This repository is not affiliated with Bitwarden, Vaultwarden, 1Password, or
the External Secrets Operator project.

## Status

`v0.2.1` is the current public release. The provider is functional and has been
smoke-tested end-to-end against released chart and image paths, but it is still
pre-`v1.0.0`: chart values, image tags, and crate APIs may change, there is no
production soak time, and the project currently has a single maintainer.

Pin chart and image versions for real deployments and treat upgrades as
deliberate changes. Release notes are the source of truth for image digests,
chart digests, signatures, attestations, and chart archive checksums.

## Should You Use It?

Use this project when you:

- run Vaultwarden or self-hosted Bitwarden Password Manager and want
  ESO-managed Kubernetes Secrets;
- store source-of-truth values in Bitwarden Cloud Password Manager vault items;
- want ESO to own refresh intervals, target Secret policies, templating, and
  status;
- can dedicate a Vaultwarden or Bitwarden user account to each Kubernetes trust
  boundary;
- want a small webhook service with no Kubernetes API permissions.

Use something else when you need:

- Bitwarden Cloud Secrets Manager (`bws`) instead of Password Manager vault
  items;
- dynamic infrastructure secrets, leases, database credentials, or native cloud
  identity;
- shared organization vault-item decryption or attachment extraction today;
- built-in TLS/mTLS on the ESO-to-provider hop without adding a mesh, ingress,
  or gateway.

## Install In Short

Start with the full [ESO webhook install guide](docs/install/eso-webhook.md)
before using this in a real cluster. The short version below shows the shape of
a Vaultwarden install.

Prerequisites:

- Kubernetes cluster.
- [External Secrets Operator](https://external-secrets.io/latest/) installed.
- Helm 3.8+ or Helm 4 for OCI chart support.
- Dedicated Vaultwarden or Bitwarden user API key.
- That user's master password.

Create the provider namespace and runtime credentials:

```bash
kubectl create namespace bweso-system

kubectl -n bweso-system create secret generic bweso-credentials \
  --from-literal=client-id='user.<uuid>' \
  --from-literal=client-secret='...' \
  --from-literal=master-password='...' \
  --from-literal=webhook-token='generate-a-long-random-token'
```

Install the released chart for a Vaultwarden or single-origin self-hosted
Bitwarden server:

```bash
CHART_VERSION=0.2.1
CHART_REF="oci://ghcr.io/ponchia/charts/vaultwarden-eso-provider"

helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --version "${CHART_VERSION}" \
  --set-string config.singleOriginUrl='https://vaultwarden.example.com' \
  --set-string credentials.existingSecret.name='bweso-credentials' \
  --set-string selectorPolicy.allowedKeys[0]='id:00000000-0000-0000-0000-000000000000'
```

Bitwarden Cloud uses split identity/API endpoints instead. See
[Compatibility](docs/compatibility.md) and the
[install guide](docs/install/eso-webhook.md) for the exact values.

After the provider is installed, create a namespace-local ESO `SecretStore` and
`ExternalSecret`. Examples are in [deploy/eso](deploy/eso).

## How It Works

- ESO calls `/v1/resolve` through its generic webhook provider.
- The provider authenticates the webhook bearer token before parsing the body.
- It logs in with a dedicated Vaultwarden or Bitwarden user API key.
- It unlocks the user vault locally with the configured master password.
- It resolves `id:<item-id>` or `name:<item-name>` selectors to item fields.
- ESO writes the resulting value into a Kubernetes Secret according to the
  `ExternalSecret` target policy.

See [Architecture](docs/architecture.md) for the design and trade-offs.

## Security Defaults To Notice

- The provider has no Kubernetes API RBAC.
- Vault item metadata never decides the Kubernetes namespace or Secret name.
- Public errors, logs, and metrics redact secret values, vault item IDs, item
  names, requested properties, API tokens, master passwords, and derived keys.
- Non-local Vaultwarden/Bitwarden endpoints require TLS verification.
- The chart exposes a cluster-internal HTTP Service by default; add a mesh,
  ingress, or gateway when the pod network is not a trusted boundary.
- Selector policy is item-key scoped, not property scoped. If a namespace can
  request an allowed item, it can request any property on that item.

Read the [Threat Model](docs/threat-model.md) before production use.

## Current Limits

- Shared organization items fail explicitly with `unsupported_shared_item`.
- Attachments fail explicitly with `unsupported_attachment`.
- Interactive two-factor and new-device challenge flows are not supported for
  API-key login.
- Per-source rate limiting is not implemented; the current cap is global
  `/v1/resolve` concurrency.
- The provider does not restart application workloads after Secret changes.
  Use ESO refreshes, Stakater Reloader, checksum annotations, or your GitOps
  rollout mechanism.

## Documentation

Start with [docs/index.md](docs/index.md) for the full documentation map.

| Need | Go to |
| --- | --- |
| Install the provider | [ESO webhook install](docs/install/eso-webhook.md) |
| Choose endpoints and supported surfaces | [Compatibility](docs/compatibility.md) |
| Understand selectors and policy | [Selectors and policy](docs/selectors-and-policy.md) |
| Verify release artifacts | [Release verification](docs/release-verification.md) |
| Operate metrics and alerts | [Observability](docs/operations/observability.md) |
| Plan migrations | [Migration runbook](docs/operations/migration-runbook.md) |
| Review security boundaries | [Threat model](docs/threat-model.md) |
| See examples | [ESO examples](deploy/eso) and [Helm chart](deploy/helm) |

## Development

The project pins common local tools with `mise` and exposes repeatable commands
with `just`:

```bash
mise install
mise run check
mise run ci
```

`mise run check` runs the standard handoff checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contributor workflow, validation
expectations, release-note labels, and security handling.

## Contributing And Security

Contributions are welcome. Keep secrets out of issues and pull requests, and
include relevant validation commands in PRs.

Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not
open public issues for credential leaks, secret-value exposure, auth bypasses,
or selector-redaction failures.

## License

Apache-2.0. See [LICENSE](LICENSE).
