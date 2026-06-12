# Upstream Research Map

This page records the public upstream projects used as research inputs for
Vaultwarden ESO Provider. Do not vendor source from these repositories into this
project without an explicit license review.

## Repositories

<!-- markdownlint-disable MD013 -->

| Project | Upstream | Purpose |
| --- | --- | --- |
| `vaultwarden` | `https://github.com/dani-garcia/vaultwarden` | Vaultwarden API compatibility, server behavior, Rust style |
| `bitwarden-clients` | `https://github.com/bitwarden/clients` | Password Manager client-side cipher, key, and field model behavior |
| `bitwarden-sdk` | `https://github.com/bitwarden/sdk` | Bitwarden Rust SDK structure and crypto references |
| `external-secrets` | `https://github.com/external-secrets/external-secrets` | ESO webhook provider contract and controller semantics |
| `onepassword-operator` | `https://github.com/1Password/onepassword-operator` | Mature password-manager Kubernetes operator UX |
| `secrets-store-csi-driver` | `https://github.com/kubernetes-sigs/secrets-store-csi-driver` | CSI mount and sync semantics |
| `secrets-store-sync-controller` | `https://github.com/kubernetes-sigs/secrets-store-sync-controller` | Standalone sync-controller experiment |
| `vaultwarden-kubernetes-secrets` | `https://github.com/antoniolago/vaultwarden-kubernetes-secrets` | Prior art and anti-pattern review |

<!-- markdownlint-enable MD013 -->

## Current Review Snapshot

Last refreshed: 2026-06-12.

<!-- markdownlint-disable MD013 -->

| Project | Ref checked | Notes |
| --- | --- | --- |
| `bitwarden-clients` | `fce61d84d03cecd472498c261c218c74e89e266f` | Current client-side models still treat API-key login as Password Manager auth, with master-password unlock material under `UserDecryptionOptions.MasterPasswordUnlock`. |
| `vaultwarden` | `d6a3d539ed13352085ca7dfa63c49017d86c419b` | API-key login accepts `grant_type=client_credentials`; user API keys use `scope=api`, organization API keys use `scope=api.organization`. Vaultwarden returns both `MasterKeyEncryptedUserKey` and `MasterKeyWrappedUserKey` for compatibility. |
| `external-secrets` | `8cb4c1cd006f7ef103b1219875c5810997cafea8` | The generic webhook provider still templates `remoteRef`, headers, body, and `result.jsonPath`, matching the provider's `/v1/resolve` contract and the example `SecretStore` manifests. |
| `kubernetes` | `687fe1685ad16b2687de873a9bebefffbfa745bc` | The chart defaults continue to align with the Restricted Pod Security direction: non-root user, seccomp `RuntimeDefault`, no privilege escalation, dropped capabilities, read-only root filesystem, and disabled service account token mounting. |

<!-- markdownlint-enable MD013 -->

These refs are research checkpoints only. Do not copy source from upstream
repositories into this project without a separate license review.
