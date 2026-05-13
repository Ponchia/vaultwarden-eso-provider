# Threat Model

## Context

This provider's primary deployment target is **Vaultwarden** (and self-hosted
Bitwarden Password Manager); Bitwarden Cloud Password Manager is a secondary
target. Bitwarden Secrets Manager — which uses a machine-account model that
does not require storing a master password in the runtime — is **not** an
available alternative for Vaultwarden users; Vaultwarden does not implement
the Secrets Manager API. The realistic alternatives for this audience are
the `bw` CLI in a cron job, a hand-rolled controller, or kubernetes-external-
secrets style scrapers. The threat model below assumes that comparison set,
not BSM.

The trade-off is explicit: this provider keeps a long-lived Vaultwarden /
Bitwarden user master password and API key in the provider runtime memory so
it can perform local vault decryption. Anyone with read access to the
provider pod's memory or filesystem can extract those credentials. The
recommended mitigations — dedicated per-boundary user accounts, exact `id:`
selector allowlists, restricted RBAC on the provider namespace, encryption
at rest for Kubernetes Secrets, NetworkPolicy, and TLS/mTLS in front of the
webhook — are necessary, not optional.

## Assets

- Vaultwarden or Bitwarden user API key client ID and client secret.
- Vaultwarden or Bitwarden user master password.
- Derived vault encryption keys.
- Decrypted item field values.
- Kubernetes Secrets created by External Secrets Operator.
- Provider logs, metrics, and caches.

## Trust Boundaries

- Kubernetes API server to provider pod.
- ESO controller to provider webhook.
- Provider pod to Bitwarden-compatible HTTPS endpoint.
- Provider memory and local cache.
- Kubernetes Secret storage and etcd encryption.
- ESO to provider webhook traffic. The default Helm chart exposes a ClusterIP
  HTTP service for ESO; this hop carries resolved secret values and relies on
  Kubernetes network isolation, bearer-token auth, and optional NetworkPolicy.

## Initial Attacker Capabilities

- Read provider logs.
- Read Kubernetes objects in namespaces where RBAC allows it.
- Compromise an application namespace.
- Intercept network traffic if TLS is misconfigured.
- Submit or modify `ExternalSecret` manifests if GitOps or RBAC allows it.

## Security Requirements

- TLS verification is mandatory by default.
- The provider Service must stay cluster-internal unless it is placed behind a
  TLS or mTLS terminating mesh, ingress, or gateway. Use that protected HTTPS
  endpoint for the ESO webhook URL when pod-network traffic is not trusted.
- The provider must not expose vault item IDs, item names, requested properties,
  secret values, decrypted vault content, API tokens, master passwords, or
  derived keys through logs, metrics, or public error responses.
- Vaultwarden/Bitwarden credentials must come from a Kubernetes Secret or external
  workload identity mechanism, not command-line args.
- The default deployment must not need Kubernetes API RBAC. Namespace access is
  controlled by ESO `SecretStore`/`ClusterSecretStore` placement, Kubernetes
  RBAC, and optional NetworkPolicy.
- A compromised application namespace must not allow arbitrary vault item
  reads unless its `SecretStore` credentials and provider selector policy
  explicitly allow that.
- Deletion must be controlled by ESO policies, not hidden provider behavior.
- Provider-side selector policy must deny by default when configured and must
  return redacted `403` responses for disallowed `remoteRef.key` values.
- The provider must authenticate `/v1/resolve` before parsing the JSON body and
  must keep request body size bounded.

## Recommended Isolation Model

- Use one dedicated Bitwarden/Vaultwarden user API key per namespace or trust
  boundary.
- Use namespace-local `SecretStore` resources by default.
- Put only the webhook bearer token in workload namespaces. Keep client ID,
  client secret, and master password in the provider namespace or an equivalent
  runtime secret boundary.
- Configure `selectorPolicy.allowedKeys` or `selectorPolicy.allowedKeyPrefixes`
  on the provider Deployment when the credential can see more vault items than
  the namespace should consume.
- Treat provider selector policy as item-key scoped. It does not enforce
  per-property authorization inside an allowed item, so use exact `id:`
  allowlists and separate provider credentials when different namespaces should
  see different fields.
- Treat `ClusterSecretStore` as a deliberate shared trust boundary. Kubernetes
  RBAC can control who may reference it, but the Bitwarden/Vaultwarden account
  and selector policy still define the data that can be read.

## Unsupported Surfaces For v0.1.x

- Bitwarden Secrets Manager (`bws`) is a separate paid product surface and is
  not handled by this provider. Vaultwarden does not implement it.
- Shared organization vault items fail explicitly until organization-key
  decryption is implemented and live-tested for Vaultwarden and Bitwarden
  Cloud.
- Attachment extraction fails explicitly. Use notes or custom fields for
  multiline material until attachment download/decryption is implemented.
- Custom CA bundles for Vaultwarden installs on a private CA are not
  configurable. TLS verification uses the system trust store only. Self-
  hosted users on internal PKI must terminate TLS with a publicly-trusted
  certificate (e.g., behind a reverse proxy with cert-manager) until this
  lands.
- `/v1/resolve` has no per-source rate limiting. Bearer-token auth, the
  16 KiB body cap, and single-flight cache refresh are the only mitigations.

## Open Questions

- Whether the Bitwarden Password Manager SDK internals (the open-source Rust
  client crates) can be adopted in place of the hand-rolled protocol code in
  this repo, both legally and practically. The trade-off is one-maintainer
  drift risk against SDK coupling and dependency footprint.
- Whether item revision metadata is sufficient for efficient cache
  invalidation.
