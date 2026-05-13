# Architecture

## Goal

Provide a serious, public-ready path for syncing **Vaultwarden** and
Bitwarden Password Manager items into Kubernetes without making vault item
metadata the Kubernetes control plane. Vaultwarden is the primary target —
it is free, self-hosted, and has no first-party Kubernetes secret integration
of its own. Bitwarden Cloud Password Manager is supported as a secondary
target for users who do not want to pay for Bitwarden Secrets Manager.

## Initial Shape

The first target is an External Secrets Operator webhook provider:

```text
ExternalSecret
  -> SecretStore(provider.webhook)
  -> vaultwarden-eso-provider
  -> Bitwarden-compatible API
  -> decrypted item fields
  -> ESO-managed Kubernetes Secret
```

This project should own:

- Bitwarden-compatible authentication.
- Local decryption and field extraction.
- Master-password user-key unlock.
- Bitwarden and Vaultwarden API-key login and sync.
- Provider-level caching and rate limiting.
- Provider-side selector policy to constrain which raw ESO `remoteRef.key` or
  `dataFrom.extract.key` values a deployment may resolve. This is an item-key
  boundary, not per-property authorization.
- Redacted JSON logs, Prometheus metrics, Kubernetes health probes, and graceful
  shutdown readiness behavior.
- A small HTTP contract usable by ESO's generic webhook provider.

This project should not own initially:

- Kubernetes Secret ownership.
- Refresh policy.
- Deletion policy.
- Target Secret templating.
- Deployment restarts.

Those are already modeled by External Secrets Operator.

## Why ESO First

External Secrets Operator already provides the API surface Kubernetes users
expect: `SecretStore`, `ExternalSecret`, refresh intervals, creation policies,
deletion policies, status conditions, and templating. Reusing it avoids a
premature CRD and gives the project a narrow, testable first milestone.

An ESO webhook provider is better than a full native operator while the desired
behavior is "read a Password Manager item and materialize a Kubernetes Secret."
It lets ESO own the Kubernetes lifecycle and lets this project own only the
Bitwarden-compatible auth, sync, decrypt, and field extraction boundary. That is
also easier to test because the webhook can be exercised without a Kubernetes
controller-runtime reconcile loop.

A native operator becomes better only if this project needs first-class
Bitwarden-specific Kubernetes APIs. Examples would be custom CRDs for vault
item discovery, project/team mapping, controller-owned rollout policies, or
status that cannot be represented cleanly through ESO `ExternalSecret`
conditions. Until then, a standalone operator would mostly duplicate mature ESO
behavior and require broader RBAC.

The 1Password Operator comparison maps naturally to this split:

- ESO `ExternalSecret` covers the "make/update a Secret" path.
- ESO refresh intervals and force-sync annotations cover periodic and manual
  refresh.
- ESO target policies cover migration semantics. For long-lived migrated
  Kubernetes Secrets, use `creationPolicy: Orphan`, `deletionPolicy: Retain`,
  and template `mergePolicy: Merge`; `creationPolicy: Merge` updates existing
  Secrets but does not recreate a missing target.
- Stakater Reloader, checksum annotations, or GitOps rollout annotations cover
  workload restarts after Secret changes.
- This project covers the missing Bitwarden/Vaultwarden Password Manager
  provider implementation.

## Later Options

- Native External Secrets Operator provider if the webhook API becomes too
  limiting.
- Native Rust controller with `kube-rs` if we need Bitwarden-specific CRDs.
- Secrets Store CSI provider only if file mount semantics become a first-class
  target.
