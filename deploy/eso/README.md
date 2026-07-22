# ESO Examples

These examples use placeholders only. Replace item IDs, namespaces, service
names, and image names before applying them.

Recommended order:

- `secretstore-webhook.example.yaml`: namespace-local `SecretStore`.
- `externalsecret.example.yaml`: single-field sync using `id:<item-id>`.
- `secretstore-webhook-map.example.yaml`: namespace-local `SecretStore` for
  whole-item `dataFrom.extract` sync.
- `whole-item.example.yaml`: whole-item extraction into a target Secret.
- `secret-types.example.yaml`: docker config JSON, basic auth, SSH auth, and
  multiline files.
- `selector-policy-configmap.example.yaml`: hot-reloadable selector policy
  sourced from a ConfigMap (onboard items with no provider restart).
- `scoped-auth-policy-secret.example.yaml`: provider-side Secret containing
  multiple bearer-token capabilities with independent selector allowlists
  (unreleased `main`; not available in `v0.4.0`).
- `reloader.example.yaml`: Stakater Reloader annotation pattern.
- `clustersecretstore.warning.example.yaml`: shared store pattern with the
  security warning that should accompany it.
- `networkpolicy-eso-ingress.example.yaml`: provider ingress from the ESO
  controller namespace, with optional Prometheus scrape ingress.
- `networkpolicy-vaultwarden-in-cluster.example.yaml`: narrow in-cluster
  Vaultwarden egress starting point.
- `networkpolicy-bitwarden-cloud.example.yaml`: Bitwarden Cloud egress starting
  point. It is port-only for HTTPS because native Kubernetes NetworkPolicy
  cannot restrict by DNS name; use a CNI or egress gateway with FQDN policy if
  strict hostname enforcement is required.

The Helm chart leaves NetworkPolicy disabled by default. Enable
`networkPolicy.enabled` only after adapting these examples to the exact DNS,
ingress, Vaultwarden, ESO, and Prometheus paths in your cluster. With
`networkPolicy.enabled=true`, the chart's default empty ingress/egress lists are
deny-all until you add rules.

ESO receives resolved secret values from the provider webhook. The default
examples use the provider's in-cluster HTTP `ClusterIP` Service plus a bearer
token. Keep that Service private to the cluster. Use RBAC to restrict who can
read webhook tokens or create stores, and use NetworkPolicy, mesh, ingress, or
gateway policy to restrict network reachability. If pod-network traffic is not a
trusted boundary, front the provider with TLS/mTLS and use that HTTPS URL in the
`SecretStore`.

Prefer one dedicated Bitwarden/Vaultwarden user and one namespace-local
`SecretStore` per trust boundary. Namespace-local `SecretStore` resources read
webhook auth from a same-namespace token Secret such as `bweso-webhook-auth`.
In legacy mode, that bearer token is a read capability over every selector
allowed by the global provider policy. For a shared provider, use
`auth.scopedPolicy` and give each trust boundary a different token whose
capability contains only its item IDs. Restrict who can read each token and who
can create or edit `SecretStore` / `ExternalSecret` resources. The provider
runtime credentials in `bweso-system` should not be reused across namespaces as
the ESO auth Secret.
Prefer the Helm chart's ConfigMap-backed selector policy whenever the provider
credentials can see more vault items than the namespace should read. Inline
`selectorPolicy.allowedKeys` / `selectorPolicy.allowedKeyPrefixes` remain
available for static policy that can wait for a provider rollout.
For rendered GitOps output, run `scripts/eso-policy-coverage.rb` against the
provider Deployment, selector-policy ConfigMap, and `ExternalSecret` resources
before applying them. It fails if any selector is missing from policy and
redacts selector values in findings by default. It accepts `-` for stdin and
Kubernetes `List` output, so raw `kubectl get ... -o yaml` audits are valid
inputs. Include `SecretStore` and `ClusterSecretStore` resources in live audits
so the checker can ignore ExternalSecrets that use other providers. If the
render contains multiple secret backends, scope the check with
`--store <namespace>/<name>` or `--cluster-store <name>`. Empty selections fail
unless you pass `--allow-empty` for an intentional policy-only lint.

Selector policy matches only the raw ESO `remoteRef.key` or `dataFrom.extract.key`.
It does not restrict individual properties on an allowed item. Treat each
allowed item as fully readable by every namespace that can use the matching
`SecretStore`, and use dedicated provider credentials for stronger isolation.
See [`../../docs/selectors-and-policy.md`](../../docs/selectors-and-policy.md)
for the full selector and property reference.

The ExternalSecret examples use `creationPolicy: Orphan`,
`deletionPolicy: Retain`, and template `mergePolicy: Merge`. That combination
lets ESO recreate a missing target Secret, avoids deleting target Secrets when
an ExternalSecret is removed, and prevents template-only keys from replacing
provider-sourced keys.

For migrated Kubernetes Secret keys, prefer `field.<key>` properties. Bare
`username` and `password` mean Bitwarden login fields, while `field.username`
and `field.password` mean custom fields with those names.

Whole-item extraction maps the selected item's conventional fields and custom
field names directly to Kubernetes Secret keys. Use one-field `data` entries
instead when an item has custom field names that are not valid Kubernetes
Secret keys or when only a subset of the item should be exposed.
