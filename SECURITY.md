# Security Policy

This project handles secret synchronization paths. Treat security issues as
private until maintainers have confirmed impact and prepared a fix.

## Supported Versions

Pre-1.0 releases are supported on a best-effort basis. The public compatibility
contract is intentionally conservative until the first stable release.

## Reporting Vulnerabilities

Use GitHub Security Advisories for vulnerabilities:

[GitHub Security Advisories](https://github.com/Ponchia/vaultwarden-eso-provider/security/advisories/new)

Do not open a public issue for vulnerabilities, credential exposure, auth
bypass, redaction failures, decrypted secret disclosure, path traversal,
server-side request forgery, unsafe TLS behavior, or Kubernetes privilege
escalation.

When reporting, include enough redacted detail to reproduce the issue:

- Provider version or image digest.
- Backend type: Bitwarden Cloud, Vaultwarden, or self-hosted Bitwarden.
- External Secrets Operator and Kubernetes versions.
- Minimal redacted `SecretStore` and `ExternalSecret` manifests.
- Redacted logs, metrics, or HTTP responses.

Never include real credentials, master passwords, API tokens, vault item IDs,
vault item names, Kubernetes Secret values, kubeconfigs, or private hostnames.

## Security Invariants

- Never disable TLS verification by default.
- Never log decrypted secret values, master passwords, access tokens, refresh
  tokens, API keys, or derived keys.
- Never accept namespace targets from Bitwarden/Vaultwarden item metadata as the
  primary authorization model.
- Never require cluster-admin for the default deployment path.
- Never delete Kubernetes Secrets unless Kubernetes ownership policy or an
  explicit user setting says deletion is allowed.

## Threat Model

The initial threat model lives in [docs/threat-model.md](docs/threat-model.md).

## Maintainer Response

Maintainers should acknowledge private reports, reproduce the issue, prepare a
fix and release when needed, then publish a public advisory once users have a
reasonable upgrade path.
