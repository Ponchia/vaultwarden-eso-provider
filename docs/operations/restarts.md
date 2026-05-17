# Restart Behavior

This project does not restart workloads by itself. The webhook resolves values;
External Secrets Operator writes Kubernetes Secrets; restart behavior should be
chosen explicitly per workload.

Recommended options:

- Use applications that reload mounted Secret files or environment-derived
  config themselves when possible.
- Use Stakater Reloader for annotation-driven Deployment restarts after Secret
  changes. See
  [`../../deploy/eso/reloader.example.yaml`](../../deploy/eso/reloader.example.yaml).
- Use a chart checksum annotation when the Secret is rendered by the same Helm
  release as the workload. This chart adds checksum annotations for chart-created
  provider credentials and inline CA bundles.
- Use GitOps-controlled force-sync annotations on `ExternalSecret` resources
  for manual refreshes.

Provider runtime credentials are read once during process startup. When rotating
an externally managed Bitwarden/Vaultwarden API key, master password, or webhook
bearer token, update the provider credential Secret, restart the provider pods so
the mounted files are re-read, then force ESO to reconcile affected
`ExternalSecret` resources. Existing Secret references are intentionally not
checksummed by this chart because their contents are not visible to Helm; use a
restart controller or an explicit rollout restart for those rotations.

The live smoke script verifies that after the webhook Deployment restarts, ESO
can force-refresh and keep the target Secret valid. That proves provider
statelessness, but it does not imply every consuming workload will observe the
new Secret without its own reload or restart mechanism.
