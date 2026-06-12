# Kubernetes Secret Migration Runbook

This runbook is for migrating existing long-lived Kubernetes `Secret` objects to
Bitwarden Password Manager or Vaultwarden vault items through this provider and
External Secrets Operator.

It is intentionally conservative. Do not start with controller-generated or
bootstrap credentials.

## Scope

Good first candidates:

- application environment Secrets;
- registry pull Secrets;
- static database credentials;
- static webhook/API tokens;
- certificates, kubeconfigs, SSH keys, and multiline config stored in notes or
  custom fields.

Leave these with their existing owners unless you have a separate design:

- service-account tokens;
- Helm release records;
- cert-manager or other controller-generated TLS Secrets;
- database operator generated Secrets;
- Flux or Argo CD bootstrap credentials;
- the Bitwarden/Vaultwarden credentials used to start this provider;
- Vaultwarden's own bootstrap Secret when Vaultwarden is the backend.

## Procedure

1. Back up existing Secret objects with your normal cluster backup tool.

2. Inventory candidates without printing values:

   ```bash
   kubectl get secrets -A \
     -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type
   ```

3. Create one Bitwarden/Vaultwarden item per Kubernetes Secret. Prefer item IDs
   in manifests. Store Kubernetes keys as custom fields and use the exact key
   names.

4. Install the provider with a dedicated Bitwarden/Vaultwarden user. Configure
   a ConfigMap-backed selector policy with exact `id:` entries for the migrated
   items if the account can see more items than a namespace should read. Use
   inline `selectorPolicy.allowedKeys` / `selectorPolicy.allowedKeyPrefixes`
   only for static policy that can wait for a provider rollout.

5. For each namespace using a namespace-local `SecretStore`, create a
   token-only Secret containing the provider webhook token:

   ```bash
   kubectl -n app create secret generic bweso-webhook-auth \
     --from-literal=webhook-token='same-provider-webhook-token'
   kubectl -n app label secret bweso-webhook-auth \
     external-secrets.io/type=webhook
   ```

6. Create namespace-local `SecretStore` resources that use
   `bweso-webhook-auth`.

7. Create `ExternalSecret` resources with:

   ```yaml
   target:
     name: existing-secret-name
     creationPolicy: Orphan
     deletionPolicy: Retain
     template:
       mergePolicy: Merge
   data:
     - secretKey: password
       remoteRef:
         key: id:00000000-0000-0000-0000-000000000000
         property: field.password
   ```

8. Force a reconcile and wait for `Ready=True`:

   ```bash
   kubectl -n app annotate externalsecret app-secret \
     force-sync="$(date +%s)" --overwrite
   kubectl -n app wait externalsecret/app-secret \
     --for=condition=Ready --timeout=180s
   ```

9. Verify target Secret key sets and application health without printing values.

10. Recreate-test at least one low-risk target Secret:

    - capture a local hash of the existing Secret data;
    - delete the target Secret;
    - force-sync the `ExternalSecret`;
    - confirm the Secret is recreated with the same data hash.

## Important Behaviors

- `creationPolicy: Merge` updates an existing Secret but does not create a
  missing target Secret. Use `Orphan` for migration-style Secrets that must be
  recreated after accidental deletion.
- `deletionPolicy: Retain` keeps the target Secret if the ExternalSecret is
  removed.
- `template.mergePolicy: Merge` keeps template-only data from replacing
  provider-sourced data.
- Plain `username` and `password` properties select Bitwarden login fields.
  Use `field.username` and `field.password` for custom fields with those names.
- Bitwarden custom fields may not preserve empty strings through all clients.
  For intentional empty keys, use `target.template.data` together with
  `mergePolicy: Merge`.
- Do not store Secret values in `kubectl.kubernetes.io/last-applied-configuration`
  annotations. Prefer create/update commands that avoid client-side apply for
  raw Secret manifests, or remove that annotation after bootstrap operations.

## Rollback

Because target Secrets are retained, the simplest rollback is usually:

1. stop reconciling the affected `ExternalSecret`;
2. delete or pause the `ExternalSecret`;
3. restore the original Secret from backup if ESO has already changed it;
4. restart workloads only if they read the Secret at process startup.
