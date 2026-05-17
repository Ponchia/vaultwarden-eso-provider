# Roadmap

This roadmap separates what shipped in the `v0.1.x` release line from
follow-up work.

## v0.2.1

Released after `v0.2.0`:

- **Hot-reloadable selector policy**: `BWESO_ALLOWED_KEYS_FILE` /
  `BWESO_ALLOWED_KEY_PREFIXES_FILE` plus `BWESO_POLICY_RELOAD_INTERVAL_SECONDS`
  and the `selectorPolicy.configMap` Helm values. A ConfigMap-sourced
  allow-list is re-read on an interval and hot-swapped, so onboarding an item
  no longer requires a provider restart. No file configured ⇒ behavior is
  unchanged; a configured file that evaluates to zero entries is an error
  (no fail-open); reload outcomes are exported as metrics. See
  [`decisions/0004-hot-reloadable-selector-policy.md`](decisions/0004-hot-reloadable-selector-policy.md).

## v0.1.x

The first public release includes:

- Bitwarden Password Manager and Vaultwarden vault-item sync through External
  Secrets Operator's generic webhook provider.
- Bitwarden-compatible user API-key login, master-password unlock, vault sync,
  and local item decryption.
- PBKDF2-SHA256 and Argon2id account KDF support.
- Vaultwarden/single-origin endpoints and Bitwarden Cloud split endpoints.
- Single-field `remoteRef` resolution and whole-item `dataFrom.extract`
  resolution.
- `id:<item-id>` and `name:<item-name>` selectors; unprefixed bare keys
  rejected with `400 validation`.
- Provider-side selector allowlists for exact keys and key prefixes.
- Explicit hard failures for unsupported shared organization items and
  attachments.
- Redacted logs, public error bodies, and low-cardinality Prometheus metrics.
- Health probes, graceful shutdown readiness behavior, and cache metrics.
- Helm chart, ESO examples, NetworkPolicy examples, Reloader example,
  PrometheusRule example, Grafana dashboard, threat model, release checklist,
  and live smoke-test script.
- Multi-arch release workflow with GHCR image publishing, SBOM/provenance,
  release image scanning, GHCR OCI Helm chart publishing, and Helm chart
  attachment to GitHub Releases.
- Live smoke verification against Vaultwarden and Bitwarden Cloud using the
  exact release chart and image.

## v0.2 (Rename + Vaultwarden-First Repositioning)

`v0.2` is the rename and repositioning boundary. `v0.1.x` had no real users,
so this is a hard rename: the old GHCR image package and OCI chart are
deleted, old tags are yanked, no compatibility shim is kept. Targeted scope:

- Renamed the GitHub repository, binary crate, container image, and Helm
  chart to `vaultwarden-eso-provider`. The crate prefix `bweso-` (which
  refers to the Bitwarden-compatible API surface) stays; only the binary
  crate, the chart, and the image moved.
- Added **custom CA bundle support**: `BWESO_CA_BUNDLE_FILE` env / CLI arg
  plus `caBundle.pem` and `caBundle.existingSecret` Helm values. The bundle
  supplements the bundled WebPKI trust roots and is the path for Vaultwarden
  installs on a private CA.
- Added a **concurrency cap on `/v1/resolve`** via a tokio Semaphore in the
  handler. Excess concurrent requests are shed with `503 overloaded`.
  Configurable via `BWESO_RESOLVE_CONCURRENCY_LIMIT` (default 16) and the
  `config.resolveConcurrencyLimit` Helm value. Per-source rate limiting
  remains a follow-up item.
- Collapse the six `BitwardenApiClient` constructors into a single
  `with_options(BitwardenApiClientOptions)` form.
- Replace the hand-rolled `constant_time_eq` with the `subtle` crate (or the
  `constant_time_eq` crate) so the project does not ship its own
  constant-time comparison.
- Replace the hand-rolled Prometheus emitter with `metrics-exporter-prometheus`:
  **no** (see [`decisions/0003-keep-handrolled-prometheus-emitter.md`](decisions/0003-keep-handrolled-prometheus-emitter.md)).
- Added cargo-fuzz target on `EncryptedString::from_str` at
  `crates/bweso-bitwarden/fuzz/`. The target asserts that no input panics;
  malformed bytes must surface as typed errors. Run weekly + on-demand via
  `.github/workflows/fuzz.yml`. Seeded corpus covers valid type-2 strings,
  legacy type-0 (rejected), and empty input.
- Adopt the Bitwarden Password Manager SDK Rust crates: **no** (see
  [`decisions/0002-do-not-adopt-bitwarden-sdk.md`](decisions/0002-do-not-adopt-bitwarden-sdk.md)).

## After v0.2

Higher-effort follow-up work:

- Finish the Vaultwarden-in-kind integration test. Scaffolding is in
  `.github/workflows/kind-integration.yml` (workflow_dispatch only) and
  `scripts/kind-vaultwarden-bootstrap.sh`. The blocker is the
  user-registration crypto step: Vaultwarden's `/api/accounts/register`
  expects a real Bitwarden registration payload (PBKDF2 master key,
  stretched user key, RSA keypair) that is impractical to assemble in
  shell. The recommended fix is a tiny `vaultwarden-test-bootstrap`
  binary inside the workspace that uses the `bweso-bitwarden` crypto
  primitives to register the user and plant an item, then the workflow
  shells out to it.
- Add **organization / shared item decryption** after fixture coverage,
  key-handling review, and live verification against both Vaultwarden and
  Bitwarden Cloud. This is the gap that excludes most team-scale users today.
- Add attachment metadata lookup, download, decryption, and Kubernetes
  mapping only after the UX and security model are clear.
- Assess whether a native ESO provider would remove webhook operational
  friction without duplicating ESO's lifecycle semantics.
- Evaluate stale-cache-on-upstream-outage behavior. The first release keeps
  upstream failures explicit.
- Decide whether a GitHub Pages chart repository is worth the extra release
  surface for users who cannot consume OCI charts.
- Revisit a native Kubernetes controller only if ESO cannot cover important
  workflows cleanly.
- Expand fuzzing beyond the encrypted-string parser and add property tests on
  URL/path construction.
- Consolidate the governance / readiness / release-checklist documents,
  which currently overlap.

## Not Planned For v0.1.x

- Bitwarden Secrets Manager (`bws`) support. Use Bitwarden's official Secrets
  Manager integrations for that product surface.
- Built-in application workload restarts. Use ESO refreshes, Reloader, checksum
  annotations, or GitOps rollout mechanisms.
- Property-level selector policy. The current selector policy gates item keys;
  isolate stricter trust boundaries with dedicated provider credentials and
  exact `id:` allowlists.
