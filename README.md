# Vaultwarden ESO Provider

[![CI](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/ci.yml)
[![Interoperability](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/integration.yml/badge.svg)](https://github.com/Ponchia/vaultwarden-eso-provider/actions/workflows/integration.yml)
[![Release](https://img.shields.io/github/v/release/Ponchia/vaultwarden-eso-provider?include_prereleases&sort=semver)](https://github.com/Ponchia/vaultwarden-eso-provider/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust [External Secrets Operator](https://external-secrets.io/) webhook provider
for **Vaultwarden and Bitwarden Password Manager vault items**. It reads and
decrypts selected item fields; ESO creates and refreshes Kubernetes Secrets.

```text
Vaultwarden / Bitwarden Password Manager
    -> provider: authenticate, unlock, decrypt, enforce selector policy
    -> ESO: refresh, template, own Kubernetes Secret lifecycle
    -> Kubernetes Secret
```

This is not Bitwarden Secrets Manager (`bws`), a separate product that
Vaultwarden does not implement. The project is unofficial and is not affiliated
with Bitwarden, Vaultwarden, or External Secrets Operator.

## Release status

**`v0.4.0` is the published release. `0.5.0-rc.1` is an unpublished candidate.**

See [candidate qualification](docs/release-qualification.md) for the exact-artifact
checks and the separate private Bitwarden Cloud acceptance.

A compatibility review found that the published Argon2id derivation uses the
wrong salt preprocessing. The correction and independent regression vectors
are on `main`, not in the `v0.4.0` image. Do not weaken an account's KDF to work
around this. Argon2 users need a verified build containing the fix or a later
verified release. See [crypto notes](docs/crypto-notes.md).

Unreleased work also includes capability-scoped bearer tokens, bounded
stale-cache fallback, corrected deletion/error semantics, and an operator KDF
memory budget. Read the [changelog](CHANGELOG.md) before upgrading. A newer
source tree does not update an installed image automatically.

This is a pre-1.0, single-maintainer integration. Automated checks and recorded
live smoke tests are not an independent security audit or a production soak
qualification. Pin chart/image versions and review upgrades deliberately.
[Release notes](https://github.com/Ponchia/vaultwarden-eso-provider/releases)
contain the artifact digests, signatures and attestations.

## Where it fits

Use this when you already operate Vaultwarden or Password Manager, use ESO,
and can dedicate a vault account to each infrastructure trust boundary. The
provider needs no Kubernetes API permissions and does not require the `bw` CLI
at runtime. Compared with a CLI-backed webhook, that reduces runtime machinery
but makes this project responsible for protocol compatibility.

Use a different backend for dynamic credentials, leases, native cloud identity,
or Bitwarden Secrets Manager. Shared organization items and attachments are
not supported; a team that depends on those should not assume they will work.
See the [compatibility matrix](docs/compatibility.md).

## Install the published chart

Read the [install guide](docs/install/eso-webhook.md) and
[threat model](docs/threat-model.md) first. This example installs the published
`0.4.0` chart; the release limitation above applies.

Prerequisites: Kubernetes, ESO, Helm with OCI support, a dedicated user API key,
and that user's master password. Prepare `client-id`, `client-secret`,
`master-password`, and a long random `webhook-token` in an operator-controlled
private directory. Do not commit these files or put their values in shell
history or Helm values.

```bash
kubectl create namespace bweso-system
kubectl -n bweso-system create secret generic bweso-credentials \
  --from-file=client-id=/secure/bweso/client-id \
  --from-file=client-secret=/secure/bweso/client-secret \
  --from-file=master-password=/secure/bweso/master-password \
  --from-file=webhook-token=/secure/bweso/webhook-token

kubectl -n bweso-system create configmap bweso-selector-policy \
  --from-literal=allowed-keys='id:00000000-0000-0000-0000-000000000000'

helm upgrade --install bweso \
  oci://ghcr.io/ponchia/charts/vaultwarden-eso-provider \
  --namespace bweso-system --version 0.4.0 \
  --set-string config.singleOriginUrl='https://vaultwarden.example.com' \
  --set-string credentials.existingSecret.name='bweso-credentials' \
  --set-string selectorPolicy.configMap.name='bweso-selector-policy'
```

Replace the example item ID with a reviewed source item. Create a namespace-local
`SecretStore` and `ExternalSecret` using the [ESO examples](deploy/eso).
Bitwarden Cloud uses separate identity/API endpoints; the install guide covers
US and EU endpoint configuration.

## Security boundaries

The provider holds an API key, master password and unlocked user key. A
compromised provider can decrypt everything accessible to that account.
Selector policy restricts callers; it cannot contain a compromised process.
Use separate accounts and deployments where that distinction matters.

Allow only reviewed `id:` selectors. Policy is **item-level**, not field-level:
access to an item allows any supported property on that item. Scoped tokens on
`main` add caller-specific limits, but do not change the upstream account's
privileges. Restrict access to the provider namespace and workload token Secrets.

The default Service is cluster-internal **HTTP**. It carries bearer tokens and
plaintext resolved values. Use a trusted pod network with reviewed NetworkPolicy
rules, or a TLS/mTLS gateway or service mesh. NetworkPolicy is opt-in because
backend and DNS routes are cluster-specific; enabling it with empty rules denies
all ingress and egress. Never expose the default Service to the internet.

Public errors and metrics omit secret values and selectors. Use the
[operations runbook](docs/operations/failure-and-recovery.md) for failed refreshes,
revocations, credential changes and the limits of last-known-good policy reloads.
The provider does not restart consumer workloads or create dynamic secrets.

## Development and validation

`rust-toolchain.toml` pins Rust; `mise.toml` and `justfile` pin and route the
other tools. Start with:

```bash
mise install
mise run check
mise run ci
```

CI enforces formatting, Clippy, tests with an 80% line-coverage floor, Helm
contracts, documentation checks, dependency/security scans and Docker builds.
The separate interoperability workflow creates disposable Vaultwarden accounts
using independent Python cryptography, tests PBKDF2 and Argon2id, and exercises
actual ESO `Delete`/`Retain` behavior in kind. It needs no production credentials.
See [testing](docs/live-testing.md) for coverage boundaries and release smoke tests.

For contribution and security handling, read [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md). Report suspected vulnerabilities privately rather
than including credentials or decrypted values in public issues.

[Documentation index](docs/index.md) · [Roadmap](docs/roadmap.md) ·
[Apache-2.0 license](LICENSE)
