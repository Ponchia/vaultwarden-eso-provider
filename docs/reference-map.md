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
