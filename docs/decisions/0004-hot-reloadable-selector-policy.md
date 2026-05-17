# 0004 — Hot-Reloadable Selector Policy

## Status

Accepted, 2026-05-17.

## Context

The selector allow-list (`BWESO_ALLOWED_KEYS` /
`BWESO_ALLOWED_KEY_PREFIXES`) was parsed once in `main()` via
`SelectorPolicy::from_args` and stored in the cloned `AppState`. There was
no runtime reload path.

Operators driving the allow-list from a Kubernetes ConfigMap (the natural
GitOps pattern: regenerate the policy, commit, let the cluster apply it)
hit a sharp edge. Mounting the ConfigMap value as the `BWESO_ALLOWED_KEYS`
env var via `configMapKeyRef` snapshots it at pod start. Changing the
ConfigMap does not change the Deployment pod spec, so the pod is never
rolled and the in-memory policy keeps denying the new key. The provider
correctly answers `403 policy_denied`, but ESO's webhook provider masks it
as a generic `SecretSyncedError`, so the root cause (a stale in-memory
policy that needed a manual `kubectl rollout restart`) is non-obvious.
This was reported from production use as
[issue #3](https://github.com/Ponchia/vaultwarden-eso-provider/issues/3).

Existing mitigations were insufficient: prefix entries reduce churn but
weaken per-item scoping; the Reloader example reloads consumer workloads,
not the provider's own policy; Reloader on the provider Deployment still
means a pod restart per onboarding and pushes a provider-specific
operational concern onto every adopter.

## Decision

Add **optional file-backed policy sources that are re-read at runtime**:

- New args `BWESO_ALLOWED_KEYS_FILE` / `BWESO_ALLOWED_KEY_PREFIXES_FILE`
  (consistent with the existing `*_FILE` credential pattern) and
  `BWESO_POLICY_RELOAD_INTERVAL_SECONDS` (default `30`, `0` disables
  reloading).
- File entries are unioned with the inline flag/env entries. File format:
  one entry per line, commas also split, surrounding whitespace trimmed,
  blank lines and `#` comment lines ignored, remaining entries validated
  non-empty.
- `SelectorPolicy` becomes a hot-swappable holder
  (`RwLock<Arc<PolicyRules>>`, no new dependency). A background task
  re-evaluates the file sources on the interval and atomically swaps the
  active rules only when they change.
- The task is spawned only when a file source is configured; otherwise
  behavior is byte-for-byte unchanged (single startup evaluation). The
  task exits promptly on shutdown via a `Lifecycle` notification
  (`tokio::select!` on the tick vs. a shutdown signal), not only on its
  next tick.
- Configured-but-unreadable/invalid files fail fast at startup; a
  transient failure during a later reload is logged and the last
  known-good policy keeps serving (fail to last-good, not open/closed).
- **Configured-empty is not allow-all.** The legacy "empty rule set ⇒
  allow all" applies only when *no* policy source is configured. When a
  file source is configured and the **effective** policy (inline entries
  plus every file) yields zero entries — empty/comment-only file, or a
  ConfigMap emptied by a bad GitOps render — it is an error: fail fast at
  startup, fail to last-good on reload, never silently widen to allow-all
  on the no-restart path. If inline entries are also configured, an
  emptied file narrows to the inline baseline (still never wider) instead
  of erroring; this is the safe direction and is the documented contract.
- **Policy metrics are seeded at startup**, so a file-backed policy is
  observable from `t0` — including `reloadIntervalSeconds: 0` (no reload
  task) and the warm-up window before the first tick. The reload counter
  family stays zero until an actual reload cycle; the baseline only sets
  the active-count gauges and the initial last-success timestamp.
- Helm chart gains `selectorPolicy.configMap` (mounted read-only at
  `/etc/bweso/policy`) and `selectorPolicy.reloadIntervalSeconds`.

## Rationale

- Removes the missed-restart failure mode: ConfigMap-driven onboarding
  becomes pure GitOps, applied within one interval with no restart.
- Conservative by default: no file ⇒ no task ⇒ identical behavior, so
  existing deployments are unaffected and the security posture is unchanged.
- No new dependency. The read path stays a cheap uncontended `Arc` clone;
  swaps are rare (reload interval).
- Redaction preserved: reload logs counts only, never selector keys, and
  errors carry file paths, not vault keys.

## Consequences

- A file-backed policy widens/narrows access on the reload interval
  without an audited pod rollout. `reloadIntervalSeconds: 0` (or omitting
  the ConfigMap entirely) keeps the stricter rollout-gated behavior for
  high-assurance boundaries.
- Mounted-ConfigMap propagation latency (kubelet sync) adds to the
  configured interval before a change takes effect.
- With multiple replicas, propagation + per-pod reload intervals mean
  replicas can briefly serve different policies during a change window.
  Bounded by the interval; `reloadIntervalSeconds: 0` + a rollout gives
  strictly coordinated changes.
- A configured file is read in full on every interval. A defensive size
  cap (4 MiB, well above the ~1 MiB ConfigMap limit) rejects an
  unexpectedly large file instead of slurping it each reload. The
  `metadata()`-then-`read` is a benign TOCTOU: a ConfigMap projection is
  an atomic `..data` symlink swap, so no torn read, and every generation
  is bounded by the Kubernetes ConfigMap limit far under the cap.
- The reload task is a single dedicated consumer of the `Lifecycle`
  shutdown latch (`notify_one` + an `is_ready()` fast-path and a
  post-select backstop). It is intentionally not a broadcast primitive;
  adding more consumers would need `notify_waiters` plus its own
  ordering handling.
- Reload is observable: `bweso_policy_reloads_total` by outcome, active
  key/prefix counts, and last-success timestamp/age — counts only, never
  the selector keys, preserving redaction.

## Alternatives considered

- **An opt-in fail-closed mode** (deny-all on a reload *error* instead of
  retaining the last known-good policy): **rejected.** It is the wrong
  default — a transient ConfigMap/filesystem error would cause a
  cluster-wide secret-sync outage from a non-security event. The only
  security-relevant failure direction (widening to allow-all) is already
  impossible, and high-assurance deployments already have a complete,
  simpler answer that needs no new code: `reloadIntervalSeconds: 0` plus
  rollout-gated policy changes — a bad config then fails the pod at
  startup (fail-closed on bad config) and every change is audited.
  Revocation is normally driven by rotating/removing the secret in the
  vault, not by the allow-list. Operators who need to detect a wedged
  policy should alert on `bweso_policy_reloads_total{outcome="failure"}`
  and a growing last-success age. Revisit only if a concrete requirement
  appears; it is ~30 lines plus tests to add later.

## High-assurance posture (recommended)

For trust boundaries that require coordinated, audited policy changes:
set `reloadIntervalSeconds: 0` (or omit the ConfigMap) and change the
policy via a normal rollout. Alert on a rising
`bweso_policy_reloads_total{outcome="failure"}` rate and a growing
`bweso_policy_last_reload_success_age_seconds` to catch a stale or
wedged policy. The hot-reload path is for low-friction onboarding, not
for security-critical revocation timing.
