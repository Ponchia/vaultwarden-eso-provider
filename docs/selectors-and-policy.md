# Selectors And Policy

Selectors are the values ESO sends as `remoteRef.key` or
`dataFrom.extract.key`. They choose a vault item. Properties choose a field
inside that item.

## Item Selectors

Selectors must use an explicit prefix:

| Selector | Meaning |
| --- | --- |
| `id:<item-id>` | Select a vault item by stable Bitwarden item ID. |
| `name:<item-name>` | Select a vault item by name. Duplicate names fail. |

Use `id:` selectors in production. Item IDs survive renames and avoid
ambiguity. `name:` selectors are useful while testing or onboarding, but two
matching item names return `ambiguous_selector`.

Unprefixed keys are rejected with `400 validation` since `v0.2`.

## Properties

Common properties:

| Property | Meaning |
| --- | --- |
| `username` or `login.username` | Login username field. |
| `password` or `login.password` | Login password field. |
| `totp` or `login.totp` | Login TOTP field. |
| `notes` | Item notes or secure-note content. |
| `field.<name>` | Custom field with the exact name. |
| `custom.<name>` | Custom field alias. |
| `<name>` | Custom field fallback when no conventional property matches. |
| `sshKey.privateKey` | SSH private key field. |
| `sshKey.publicKey` | SSH public key field. |
| `sshKey.keyFingerprint` | SSH key fingerprint field. |

Prefer `field.<key>` for migrated Kubernetes Secret keys. Plain `username` and
`password` select Bitwarden login fields; `field.username` and
`field.password` select custom fields with those names.

Whole-item extraction rejects duplicate output keys with
`409 ambiguous_document`. For example, an item cannot expose both a login
`password` and a custom field named `password` in the same whole-item document.
Single-property selectors remain unambiguous: use `password` for the login
field or `field.password` for the custom field.

Attachment properties fail with `unsupported_attachment`. Shared organization
items fail with `unsupported_shared_item` until organization-key decryption is
implemented and live-tested.

## Selector Policy

Provider-side selector policy gates item keys before the provider resolves a
vault item. It supports exact keys and key prefixes:

```bash
--set-string selectorPolicy.allowedKeys[0]='id:00000000-0000-0000-0000-000000000000'
--set-string selectorPolicy.allowedKeyPrefixes[0]='id:11111111-'
```

The policy is item-key scoped, not property scoped. If a namespace can request
an allowed `remoteRef.key` or `dataFrom.extract.key`, it can request any
property on that item and can request whole-item extraction unless your ESO
manifests, RBAC, and GitOps review prevent it.

For strict isolation, prefer:

- one dedicated provider account per namespace or trust boundary;
- exact `id:` entries in the selector policy, with a ConfigMap-backed policy
  preferred for GitOps-managed installs and inline `selectorPolicy.allowedKeys`
  only for static policy;
- namespace-local `SecretStore` resources;
- token-only webhook auth Secrets in workload namespaces;
- capability-scoped authentication when one provider serves several namespace
  trust boundaries;
- no shared `ClusterSecretStore` unless every namespace that can reference it
  may read the allowed items.

Running without any selector policy requires the explicit
`selectorPolicy.allowAllSelectors=true` Helm value or
`BWESO_ALLOW_ALL_SELECTORS=true`. Use that only when the provider account is
already scoped to the same trust boundary.

## Capability-scoped authentication

This feature is available on unreleased `main`. The `v0.4.0` release supports
the legacy single-token mode only.

Legacy authentication gives one bearer token every selector admitted by the
global provider policy. Capability-scoped authentication instead loads a JSON
policy from a Kubernetes Secret. Each capability has its own token set and
item-key allowlist:

```json
{
  "version": 1,
  "capabilities": [
    {
      "name": "app-a",
      "tokens": [
        "replace-with-random-token-for-app-a-00000001"
      ],
      "allowedKeys": [
        "id:00000000-0000-0000-0000-000000000001"
      ],
      "allowedKeyPrefixes": []
    }
  ]
}
```

The effective permission is the intersection of two policies:

```text
request allowed = global selector policy AND matching bearer capability
```

A capability cannot widen the global policy. A global policy change also cannot
grant an item to a capability that does not list it. Both layers remain
item-key scoped; a caller that can select an item can request any property or
whole-item extraction from it.

Create the auth policy as a Secret, never a ConfigMap. See
[`../deploy/eso/scoped-auth-policy-secret.example.yaml`](../deploy/eso/scoped-auth-policy-secret.example.yaml)
for a synthetic example. Configure the chart:

```yaml
auth:
  enabled: true
  scopedPolicy:
    existingSecret:
      name: bweso-auth-policy
      key: auth-policy.json
    reloadIntervalSeconds: 30
```

Do not configure the legacy `webhook-token` at the same time. Each workload
namespace receives only the token for its capability and uses the normal
namespace-local `SecretStore` example.

Policy rules:

- `version` must be `1`.
- Capability names and token values must be unique.
- Each capability needs at least one token and at least one exact key or prefix.
- Tokens must contain 32–4096 printable ASCII, non-whitespace bytes. Generate random
  values; do not derive them from capability or namespace names.
- Multiple tokens in one capability have identical scope. Use this overlap to
  rotate a token without downtime.
- The file is limited to 1 MiB, 1,024 capabilities, and 4,096 total tokens.
- Unknown JSON fields and invalid or empty policy documents are rejected.

The provider hashes tokens during loading, zeroizes the parsed token strings,
and retains only SHA-256 digests. Each request hashes the supplied token and
compares it with every configured digest in constant time. Authentication
failures return a redacted `401`; selector denials return a redacted `403`.

The Secret-mounted file reloads every `reloadIntervalSeconds`. Valid changes
swap atomically. Invalid updates keep the last known-good policy and increment
the failure metric. Set the interval to `0` to read only at startup and require
a provider rollout for changes.

Alert on:

- `sum(rate(bweso_auth_policy_reloads_total{outcome="failure"}[5m])) > 0`
- `bweso_auth_policy_last_reload_success_age_seconds > 600`

See [ADR 0006](decisions/0006-capability-scoped-auth.md) for the security and
operational rationale. Tooling can validate policy structure against
[`auth-policy.schema.json`](auth-policy.schema.json); runtime validation remains
authoritative for cross-capability uniqueness.

## Hot Reload

Inline policy values are read once at process start:

- `selectorPolicy.allowedKeys`
- `selectorPolicy.allowedKeyPrefixes`
- `BWESO_ALLOWED_KEYS`
- `BWESO_ALLOWED_KEY_PREFIXES`

To onboard items without restarting the provider, source the allow-list from a
ConfigMap instead:

```bash
helm upgrade --install bweso "${CHART_REF}" \
  --namespace bweso-system \
  --set-string config.singleOriginUrl='https://vaultwarden.example.com' \
  --set-string credentials.existingSecret.name='bweso-credentials' \
  --set-string selectorPolicy.configMap.name='bweso-selector-policy' \
  --set selectorPolicy.reloadIntervalSeconds=30
```

The ConfigMap is mounted read-only at `/etc/bweso/policy` and wired through:

- `BWESO_ALLOWED_KEYS_FILE`
- `BWESO_ALLOWED_KEY_PREFIXES_FILE`
- `BWESO_POLICY_RELOAD_INTERVAL_SECONDS`

Each policy file holds one entry per line. Commas also split entries. Blank
lines and `#` comment lines are ignored. File entries are unioned with inline
lists.

The provider re-reads files every `reloadIntervalSeconds` seconds. The default
is `30`; `0` reads once and never starts a reload task. Mounted ConfigMap
volumes update in place, so changing the ConfigMap updates the allow-list within
one interval with no provider restart.

## Failure Behavior

The effective policy is the union of inline entries and every configured file.
If that effective policy evaluates to zero entries, startup fails and reloads
keep the last known-good policy. An empty or comment-only file never widens to
allow-all.

On reload errors, the provider keeps serving the last known-good policy. This
avoids cluster-wide secret-sync outages caused by transient ConfigMap
projection issues.

High-assurance trust boundaries that need coordinated, audited policy changes
should set `reloadIntervalSeconds: 0` and change policy through a normal
provider rollout. A bad config then fails the pod at startup instead of being
handled by the reload loop.

Alert on:

- `sum(rate(bweso_policy_reloads_total{outcome="failure"}[5m])) > 0`
- `bweso_policy_last_reload_success_age_seconds > 600`

## Static Coverage Check

For GitOps repositories, render the provider Deployment, selector-policy
ConfigMap, and `ExternalSecret` resources together and run:

```bash
scripts/eso-policy-coverage.rb rendered-manifests/
```

The checker parses local YAML only and never reads Kubernetes Secret data. It
also accepts `-` for stdin and expands Kubernetes `List` documents, so raw
audit output works:

```bash
kubectl get deployment,configmap,externalsecret,secretstore,clustersecretstore \
  -A --show-managed-fields=false -o yaml |
  scripts/eso-policy-coverage.rb -
```

It verifies that every `remoteRef.key` and `dataFrom.extract.key` is covered by
the exact keys or prefixes visible in the rendered provider policy. Findings
redact selector values by default; use `--show-keys` only in a trusted local
terminal.

When the rendered set includes `SecretStore` / `ClusterSecretStore` resources,
the checker ignores ExternalSecrets that reference a rendered non-webhook store.
For mixed webhook providers or partial render sets, scope explicitly with
`--store app/bitwarden-vault` or `--cluster-store shared-bitwarden-vault`.

If one rendered output contains multiple provider Deployments, run the checker
once per trust boundary with `--provider bweso-system/bweso`. Pair that with
`--store` or `--cluster-store` whenever the same rendered bundle contains
multiple SecretStores or shared trust boundaries.

By default, the checker fails when it finds no selected ExternalSecret keys or
no provider Deployment / explicit offline policy. This catches broken filters
and incomplete `kubectl` output. Pass `--allow-empty` only for deliberate
policy-only linting.

See [Observability](operations/observability.md) for the full metric list and
[ADR 0004](decisions/0004-hot-reloadable-selector-policy.md) for the design
rationale.
