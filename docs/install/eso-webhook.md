# ESO Webhook Install

Install External Secrets Operator first. This project provides the Bitwarden
Password Manager and Vaultwarden resolver behind ESO's generic webhook provider.

Create a namespace and provider runtime credential Secret. For real credentials,
prefer a secret manager or files so values do not land in shell history:

```bash
install -m 0700 -d /tmp/bweso-bootstrap
printf '%s' 'user.<uuid>' > /tmp/bweso-bootstrap/client-id
printf '%s' '...' > /tmp/bweso-bootstrap/client-secret
printf '%s' '...' > /tmp/bweso-bootstrap/master-password
printf '%s' 'generate-a-long-random-token' > /tmp/bweso-bootstrap/webhook-token

kubectl create namespace bweso-system
kubectl -n bweso-system create secret generic bweso-credentials \
  --from-file=client-id=/tmp/bweso-bootstrap/client-id \
  --from-file=client-secret=/tmp/bweso-bootstrap/client-secret \
  --from-file=master-password=/tmp/bweso-bootstrap/master-password \
  --from-file=webhook-token=/tmp/bweso-bootstrap/webhook-token
rm -rf /tmp/bweso-bootstrap
```

For throwaway local clusters, literal placeholders are shorter:

```bash
kubectl create namespace bweso-system
kubectl -n bweso-system create secret generic bweso-credentials \
  --from-literal=client-id='user.<uuid>' \
  --from-literal=client-secret='...' \
  --from-literal=master-password='...' \
  --from-literal=webhook-token='generate-a-long-random-token'
```

The provider rejects `/v1/resolve` calls without `Authorization: Bearer
<webhook-token>` by default.

Choose the provider image reference first. Released OCI charts are published to
GHCR and default to the matching provider image version. The same packaged
chart is also attached to the GitHub Release as a `.tgz` fallback. For
unreleased `main` builds, clone the repository and use
`./deploy/helm/vaultwarden-eso-provider` as the chart reference, omitting
`--version`.

Set the release chart reference:

```bash
CHART_VERSION=0.4.0
CHART_REF="oci://ghcr.io/ponchia/charts/vaultwarden-eso-provider"
```

Create the selector-policy ConfigMap before installing the chart. Use exact
`id:` selectors in production. ConfigMap-backed policy is the recommended
GitOps path because updates are picked up by the provider without a restart:

```bash
kubectl -n bweso-system create configmap bweso-selector-policy \
  --from-literal=allowed-keys='id:00000000-0000-0000-0000-000000000000'
```

Install the webhook for Vaultwarden or single-origin self-hosted Bitwarden:

```bash
helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --version "${CHART_VERSION}" \
  --set-string image.tag="${CHART_VERSION}" \
  --set-string config.singleOriginUrl='https://vaultwarden.example.com' \
  --set-string credentials.existingSecret.name=bweso-credentials \
  --set-string selectorPolicy.configMap.name=bweso-selector-policy
```

Install the webhook for Bitwarden Cloud US:

```bash
helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --version "${CHART_VERSION}" \
  --set-string image.tag="${CHART_VERSION}" \
  --set-string config.identityUrl='https://identity.bitwarden.com' \
  --set-string config.apiUrl='https://api.bitwarden.com' \
  --set-string credentials.existingSecret.name=bweso-credentials \
  --set-string selectorPolicy.configMap.name=bweso-selector-policy
```

Use `https://identity.bitwarden.eu` and `https://api.bitwarden.eu` for
Bitwarden EU.

For environments that cannot pull OCI charts, use the GitHub Release archive
instead and omit `--version`:

```bash
CHART_REF="https://github.com/ponchia/vaultwarden-eso-provider/releases/download/v${CHART_VERSION}/vaultwarden-eso-provider-${CHART_VERSION}.tgz"
```

`networkPolicy.enabled` is false by default. When enabled, the default empty
ingress and egress lists deny all traffic until you add rules for ESO,
Prometheus, DNS, and your Bitwarden/Vaultwarden backend. If the provider must
reach an in-cluster ingress or private address while still using the public
Vaultwarden hostname for TLS and HTTP host routing, configure `hostAliases`.

`selectorPolicy.configMap` is the recommended production allowlist source.
`selectorPolicy.allowedKeys` and `selectorPolicy.allowedKeyPrefixes` are also
available, but inline values are read only at process start. Public installs
should configure at least one allowlist entry or a ConfigMap-backed allowlist.
Running without a selector policy requires the explicit
`selectorPolicy.allowAllSelectors=true` escape hatch and is acceptable only when
the Bitwarden/Vaultwarden account itself is already scoped to the trust
boundary. Every non-matching selector returns `403` without echoing the
requested key.

Selector policy is item-key scoped, not property scoped. If a namespace can
request an allowed `remoteRef.key` or `dataFrom.extract.key`, it can request any
property on that item and can request whole-item extraction unless your ESO
manifests, RBAC, and GitOps review prevent it. Use one dedicated provider
credential per namespace or trust boundary for strict isolation.

See [`../selectors-and-policy.md`](../selectors-and-policy.md) for selector
syntax, property names, policy scope, and ConfigMap-backed hot reload behavior.

## Configure bounded stale cache

This configuration is available on unreleased `main`; the `v0.4.0` release
continues to fail closed on every upstream refresh error.

The provider fails closed on upstream refresh errors by default. You can opt in
to serving a previous successful sync during a temporary Vaultwarden or
Bitwarden outage:

```yaml
config:
  cacheTtlSeconds: 60
  cacheStaleIfErrorSeconds: 600
  cacheRefreshRetryIntervalSeconds: 15
```

With these values, a cached sync is fresh for 60 seconds and may then be served
for up to 600 additional seconds when a refresh fails. The maximum cache age is
the sum: 660 seconds. The provider retries the upstream refresh after 15
seconds instead of retrying once per ESO request.

Stale fallback applies only after at least one successful sync and only for
transport failures, HTTP `408`, HTTP `429`, and HTTP `5xx` responses. It does
not mask authentication or authorization failures, malformed or oversized
responses, invalid KDF data, or decryption failures. The cache is in memory and
is empty after a provider restart.

Set `cacheStaleIfErrorSeconds: 0` to keep the default fail-closed behavior. If
you enable this mode, alert on `bweso_cache_stale_serves_total` and choose a
window that matches how long your workloads may safely keep the previous vault
value. A longer window improves outage tolerance but can delay propagation of a
vault update while the upstream service is unavailable.

## Recommended Production Pattern

For each namespace or trust boundary:

- use a dedicated Bitwarden/Vaultwarden account or API key;
- install the provider with a ConfigMap-backed selector policy containing exact
  `id:<item-id>` entries;
- use a namespace-local `SecretStore`;
- put only the webhook bearer token in workload namespaces;
- keep the Bitwarden/Vaultwarden client secret and master password in the
  provider namespace;
- rotate the Bitwarden/Vaultwarden API key, master password, and webhook token
  like other infrastructure credentials, then restart the provider pods and
  force an ESO reconcile;
- avoid `ClusterSecretStore` unless the store is intentionally shared and every
  namespace that can reference it may read the allowed items.

Create a token-only webhook auth Secret in each namespace that uses a
namespace-local `SecretStore`:

```bash
kubectl create namespace app
kubectl -n app create secret generic bweso-webhook-auth \
  --from-literal=webhook-token='same-webhook-token-as-above'
kubectl -n app label secret bweso-webhook-auth \
  external-secrets.io/type=webhook
```

ESO reads this same-namespace Secret to render the authorization header.
Keeping it token-only avoids copying the Bitwarden/Vaultwarden client secret and
master password into workload namespaces.

Point ESO at the webhook from the workload namespace. The webhook bearer token
is a read capability over every selector allowed by provider policy; restrict
who can read it and who can create or edit `SecretStore` and `ExternalSecret`
resources.

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: bitwarden
  namespace: app
spec:
  provider:
    webhook:
      url: "http://bweso-vaultwarden-eso-provider.bweso-system.svc.cluster.local:8080/v1/resolve"
      method: POST
      headers:
        Content-Type: application/json
        Authorization: 'Bearer {{ index .auth "webhook-token" }}'
      secrets:
        - name: auth
          secretRef:
            name: bweso-webhook-auth
            key: webhook-token
      body: |
        {
          "remoteRef": {
            "key": {{ .remoteRef.key | toJson }},
            "property": {{ .remoteRef.property | toJson }}
          }
        }
      result:
        jsonPath: "$.data.value"
      timeout: 10s
```

The webhook response contains the resolved secret value. The chart exposes the
provider as an in-cluster `ClusterIP` HTTP service, so this hop relies on
Kubernetes network isolation plus the bearer token. Do not expose the provider
Service outside the cluster. For clusters where pod-network traffic is not a
trusted boundary, put this service behind a mesh, ingress, or gateway that
terminates TLS/mTLS, and point the ESO webhook URL at that protected HTTPS
endpoint instead.

Then create `ExternalSecret` resources that select item IDs/names and
properties. Selectors must use `id:<item-id>` or `name:<item-name>`. Prefer
`id:` selectors in production; bare selectors are rejected with `400 validation`
since `v0.2`.

For migrated Kubernetes Secret keys, prefer custom fields and request them with
`field.<key>`. Plain `username` and `password` select Bitwarden login fields;
`field.username` and `field.password` select custom fields named `username` and
`password`.

Use this target policy for migration-style Secrets that should survive
ExternalSecret removal and be recreated if the target Secret is deleted:

```yaml
target:
  name: app-database
  creationPolicy: Orphan
  deletionPolicy: Retain
  template:
    mergePolicy: Merge
```

`creationPolicy: Merge` updates existing Secrets but does not recreate a missing
target Secret. `mergePolicy: Merge` is important whenever `target.template.data`
contains static keys, such as an intentionally empty config file, because it
keeps template data from replacing provider-sourced data.

Single-property responses always expose the selected value at `$.data.value`, so
the `SecretStore` does not need JSONPath templating for field names. See
[`../../deploy/eso`](../../deploy/eso) for Secret type, Reloader,
`ClusterSecretStore`, and NetworkPolicy examples.

For production installs, pin and verify release artifacts before rollout.
Releases produced by the current release workflow include the image digest,
chart digest, chart archive checksum, Sigstore signing evidence, and GitHub
artifact-attestation evidence in the GitHub Release notes. Older tags may have
less evidence; see [`../release-verification.md`](../release-verification.md).

Whole-item `dataFrom.extract` uses a separate webhook `SecretStore` shape with
`result.jsonPath: "$.data"` and a request body that omits
`remoteRef.property`; see
[`../../deploy/eso/secretstore-webhook-map.example.yaml`](../../deploy/eso/secretstore-webhook-map.example.yaml)
and [`../../deploy/eso/whole-item.example.yaml`](../../deploy/eso/whole-item.example.yaml).
Whole-item extraction exposes every extractable conventional field and custom
field on the selected item, so prefer one-field `data` entries when you need a
narrower target Secret. If a custom field has the same output name as a
conventional login, notes, or SSH-key field, whole-item extraction fails closed
with `409 ambiguous_document` instead of choosing one value silently.

The chart configures startup, liveness, and readiness probes by default:

```yaml
probes:
  startup:
    httpGet:
      path: /livez
      port: http
  liveness:
    httpGet:
      path: /livez
      port: http
  readiness:
    httpGet:
      path: /readyz
      port: http
```

The provider always serves Prometheus-format metrics at `/metrics`. If the
Prometheus Operator CRDs are installed, enable a `ServiceMonitor`:

```bash
helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --version "${CHART_VERSION}" \
  --reuse-values \
  --set metrics.serviceMonitor.enabled=true
```

See [`../operations/observability.md`](../operations/observability.md) for the
full metric list and operational notes.

## Verify Without Printing Secret Values

After install, wait for the provider and ESO resources without dumping Secret
data:

```bash
kubectl -n bweso-system rollout status deployment/bweso-vaultwarden-eso-provider
kubectl -n app wait externalsecret/app-database --for=condition=Ready --timeout=120s
kubectl -n app get secret app-database -o jsonpath='{.metadata.name}{"\n"}'
kubectl -n app get secret app-database -o json | jq '.data | keys'
```

Common redacted error classes:

| Error class | Likely fix |
| --- | --- |
| `auth` | Check the token-only auth Secret and header template. |
| `validation` | Check `id:`/`name:` selector prefixes and JSON syntax. |
| `policy_denied` | Add the selector or use the correct provider instance. |
| `item_not_found` | Check the item ID/name without posting values. |
| `property_not_found` | Check the requested property without posting values. |
| `ambiguous_document` | Remove duplicate output keys or select one property. |
| `upstream_*` | Check reachability, TLS trust, and credentials. |
| `request_timeout` | Check for a slow or stalled client request body. |

## Resource Sizing

The default chart resources are intentionally small and are suitable for
PBKDF2-backed accounts plus low-throughput sync. Bitwarden Argon2id accounts
can require substantially more memory during unlock. If the provider exits
during unlock or Kubernetes reports OOM kills, raise `resources.requests.memory`
and `resources.limits.memory` to match the account's configured Argon2 memory
cost with operational headroom.
