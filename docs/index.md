# Documentation

This repository keeps user-facing documentation in Git so changes go through
pull requests, CI, review, release-note labels, and the same history as the
code.

## Start Here

| Goal | Document |
| --- | --- |
| Understand what the project is | [README](../README.md) |
| Install the provider with ESO | [ESO webhook install](install/eso-webhook.md) |
| Choose Vaultwarden or Bitwarden endpoints | [Compatibility](compatibility.md) |
| Select vault items and fields safely | [Selectors and policy](selectors-and-policy.md) |
| Review security boundaries | [Threat model](threat-model.md) |
| Verify release artifacts | [Release verification](release-verification.md) |

## Operators

| Goal | Document |
| --- | --- |
| Observe health, metrics, and alerts | [Observability](operations/observability.md) |
| Plan Secret migrations | [Migration runbook](operations/migration-runbook.md) |
| Understand restarts and rollouts | [Restart behavior](operations/restarts.md) |
| Use ESO manifests | [ESO examples](../deploy/eso/README.md) |
| Configure the Helm chart | [Helm chart](../deploy/helm/README.md) |

## Maintainers

| Goal | Document |
| --- | --- |
| Run local checks and open PRs | [Contributing](../CONTRIBUTING.md) |
| Prepare a public release | [Public release checklist](public-release-checklist.md) |
| Track user-facing changes | [Changelog](../CHANGELOG.md) |
| Govern repository settings | [Repository governance](repository-governance.md) |
| Decide whether to use GitHub Wiki | [GitHub Wiki strategy](github-wiki.md) |
| Track planned work | [Roadmap](roadmap.md) |
| Review architecture decisions | [Architecture decisions](decisions) |

## Reference

- [Architecture](architecture.md)
- [Crypto notes](crypto-notes.md)
- [Live testing](live-testing.md)
- [Upstream research map](reference-map.md)
- [Support policy](../SUPPORT.md)
- [Security policy](../SECURITY.md)
