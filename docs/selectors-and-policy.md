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
- exact `id:` entries in `selectorPolicy.allowedKeys`;
- namespace-local `SecretStore` resources;
- token-only webhook auth Secrets in workload namespaces;
- no shared `ClusterSecretStore` unless every namespace that can reference it
  may read the allowed items.

Running without any selector policy requires the explicit
`selectorPolicy.allowAllSelectors=true` Helm value or
`BWESO_ALLOW_ALL_SELECTORS=true`. Use that only when the provider account is
already scoped to the same trust boundary.

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

See [Observability](operations/observability.md) for the full metric list and
[ADR 0004](decisions/0004-hot-reloadable-selector-policy.md) for the design
rationale.
