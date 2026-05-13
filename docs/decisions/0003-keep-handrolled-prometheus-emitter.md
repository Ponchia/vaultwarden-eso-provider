# 0003 — Keep the Hand-Rolled Prometheus Text Emitter

## Status

Accepted, 2026-05-13.

## Context

The `metrics.rs` module in the binary crate is a hand-rolled Prometheus
text-format emitter (~515 lines including tests). The earlier project
review queued its replacement with the `metrics` facade plus
`metrics-exporter-prometheus` as a v0.2 refactor on the grounds that
adopting a well-trodden library would reduce maintenance surface and
remove the need to hand-maintain label escaping.

## Decision

**Keep the hand-rolled emitter.** Do not adopt `metrics` /
`metrics-exporter-prometheus` for v0.2.

## Rationale

After working through what the migration would actually look like, the
trade-off is less favorable than I initially framed it:

- **The `metrics` facade uses a global recorder.** A single
  `PrometheusBuilder::install_recorder()` call sets the process-wide
  recorder and panics on the second install. This collides with the
  existing test pattern, which constructs an `AppMetrics` per `AppState`
  per test case. Working around it means either threading
  `metrics::with_local_recorder` through every recording callsite or
  building one global recorder lazily and accepting that tests share
  state. Both are worse than what we have.

- **Mixed render-time and event-time metrics still need a custom path.**
  `bweso_uptime_seconds`, `bweso_ready`, the build info gauge, and the
  cache snapshot metrics are all computed at render time from non-metric
  sources (the lifecycle state, the cache metric state read off the
  provider trait object). The recorder gives us request counters and
  histograms, but the rest still has to be appended manually. We don't
  remove the hand-rolled emitter; we just split it.

- **The redaction tests are the actual value.** The tests in `metrics.rs`
  and `main.rs` assert that vault keys and properties do not leak into
  `/metrics`. Any replacement would need exactly the same tests, and the
  replacement's correctness would still be conditional on us getting the
  label-set right. The library does not add safety against the failure
  mode we actually care about.

- **The emitter is isolated and bounded.** It is one file, well-tested,
  with no `unsafe`, no untrusted-input parsing, and a stable API surface.
  It is not the largest or most complex part of the codebase. The
  argument that hand-rolled code is per se a maintenance burden does not
  weigh much when the code is small, isolated, and exercised on every CI
  run.

- **Dependency footprint.** The workspace currently has ~24 deps and a
  tight graph. `metrics-exporter-prometheus` pulls in `mio`, `quanta`,
  `parking_lot`, and friends. Worth it when the win is large; not here.

## Consequences

- `crates/vaultwarden-eso-provider/src/metrics.rs` stays as it is.
- The earlier roadmap entry queuing the replacement is removed.
- If the metric surface grows significantly (e.g., we add many histograms
  or per-cipher metrics), revisit this decision.

## When to revisit

- If adopting Tokio Console, OpenTelemetry, or another `metrics`-using
  observability stack becomes a real requirement.
- If the metric surface grows past roughly a dozen series.
- If the redaction-test pattern stops being sufficient.
