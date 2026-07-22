# Helm Chart

The installable chart lives in
[`vaultwarden-eso-provider`](vaultwarden-eso-provider).

The default chart shape is intentionally small:

- Namespace-scoped deployment.
- No Kubernetes API RBAC; the webhook does not watch or write Kubernetes
  objects.
- No dashboard by default; optional Grafana and PrometheusRule examples live in
  [`../../examples`](../../examples).
- Existing Kubernetes Secret for credentials by default.
- Startup, liveness, and readiness probes enabled by default.
- Prometheus metrics exposed by the pod, with optional `ServiceMonitor`
  rendering when Prometheus Operator CRDs are installed.
- Webhook bearer-token authentication enabled by default. The legacy mode uses
  one token for the global selector-policy scope. Shared deployments can use
  `auth.scopedPolicy` to mount multiple independently scoped capabilities from
  a Kubernetes Secret.
- Provider-side selector policy with exact `remoteRef.key` allowlists and prefix
  allowlists. Production GitOps installs should source policy from a
  hot-reloadable ConfigMap (`selectorPolicy.configMap`) so onboarding needs no
  provider restart; inline lists are still available for static installs.
  Running without a selector policy requires
  `selectorPolicy.allowAllSelectors=true`.
- Fail-closed cache refreshes by default, with optional bounded stale reads and
  refresh retry throttling through `config.cacheStaleIfErrorSeconds` and
  `config.cacheRefreshRetryIntervalSeconds`.
- Baseline resource requests/limits and seccomp by default.
- Optional NetworkPolicy rendering. When enabled, default empty rules deny all
  traffic until you adapt ingress and egress rules to your ESO, DNS, Bitwarden
  Cloud, or Vaultwarden path.
- Optional `hostAliases` rendering for private DNS, split-horizon DNS, or
  in-cluster ingress paths that must preserve the Bitwarden/Vaultwarden
  hostname for TLS and HTTP host routing.

Capability-scoped authentication is available on unreleased `main`. The
`v0.4.0` chart supports the legacy single-token mode only.

Render it locally with non-secret lint values:

```bash
helm lint deploy/helm/vaultwarden-eso-provider -f deploy/helm/lint-values.yaml
helm template bweso deploy/helm/vaultwarden-eso-provider \
  -f deploy/helm/lint-values.yaml \
  --namespace bweso-system \
  --set-string 'selectorPolicy.allowedKeys[0]=id:00000000-0000-0000-0000-000000000000'
```
