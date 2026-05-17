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
That bearer token is a read capability over every selector allowed by the
provider policy, so restrict who can read it and who can create or edit
`SecretStore` / `ExternalSecret` resources. The provider runtime credentials in
`bweso-system` should not be reused across namespaces as the ESO auth Secret.
Configure the Helm chart's
`selectorPolicy.allowedKeys` or `selectorPolicy.allowedKeyPrefixes` whenever
the provider credentials can see more vault items than the namespace should
read.

Selector policy matches only the raw ESO `remoteRef.key` or `dataFrom.extract.key`.
It does not restrict individual properties on an allowed item. Treat each
allowed item as fully readable by every namespace that can use the matching
`SecretStore`, and use dedicated provider credentials for stronger isolation.

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
