# Reproducible performance evidence

Issue #76 requires measured, repeatable operating evidence for this provider.
The Rust example below is a **synthetic KDF-only probe**, intended to make
later experiments reproducible. It never contacts a vault, reads a credential,
downloads a secret, or starts an ESO webhook. It does not measure cold account
login, HTTP latency, full-vault refresh, cache hits, or restarts.

## Run a bounded synthetic baseline

Build from the checked-out, reviewed source with the locked dependency graph.
Use a release build so measurements do not primarily reflect debug overhead.

~~~sh
cargo build --release --locked -p bweso-bitwarden --example kdf-cost
./target/release/examples/kdf-cost --help
./target/release/examples/kdf-cost --mode both --rounds 5 \
  --pbkdf2-iterations 600000 \
  --argon2-memory-mib 64 --argon2-iterations 3 --argon2-parallelism 2 \
  > kdf-evidence.json
~~~

The tool uses one constant, non-secret password and a synthetic account email
through the **same in-repository key-derivation implementation** as the provider.
It caps a single probe to 20 iterations and Argon2 memory to 64 MiB; the
application still supports larger server KDF costs through its separately
controlled runtime budget. Do not edit the probe to use actual account details.

Output is structured JSON. Each algorithm reports wall-clock samples, median,
a nearest-rank p95 estimate, and (on Linux) the process high-water resident
memory. The output also records OS, architecture, visible CPU parallelism and
available cgroup v2 CPU/memory ceilings. A missing memory field is null rather
than an invented measurement. Small samples do **not** provide reliable tail
latency confidence and the process RSS includes dependencies and process state,
not only the allocation of one derivation. The probe is single-process and does
not simulate concurrent HTTP requests.

## Compare under explicit CPU/memory limits

Use the same revision, source package, architecture, optimized binary and
inputs for each environment. In an isolated disposable container, an example
Linux Docker invocation after compiling a binary compatible with Ubuntu 24.04
and the target CPU architecture is:

~~~sh
docker run --rm --network none --read-only --cpus=1 --memory=256m \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$PWD/target/release/examples/kdf-cost:/kdf-cost:ro" \
  ubuntu:24.04 /kdf-cost \
  --mode both --rounds 5 --pbkdf2-iterations 600000 \
  --argon2-memory-mib 64 --argon2-iterations 3 --argon2-parallelism 2
~~~

The binary must match the container's CPU architecture and runtime libraries.
Record the container image digest, exact CPU quota, memory limit, source
revision, test parameters, raw samples, and any contention. If real pod limits
or production settings differ, repeat on a disposable matching pod: running
unlimited on the devbox does not establish Kubernetes latency.

Avoid treating elapsed time, JSON output or a simulated key as a real vault
secret. No production credential is needed.

## Remaining operating measurements

The synthetic results are **not** sufficient to close issue #76. Evidence still
needed from disposable Vaultwarden/ESO fixtures includes:

- Exact-ID fresh-cache lookups, cold full login/unlock, cache misses and full
  refresh, using explicitly sized small and large synthetic vaults.
- Repeated measurements of successful and failed paths with CPU-throttled pods
  and memory pressure, including the selected KDF configurations.
- Concurrent upstream outages, cancellation during unlock, rotation/revocation,
  provider restart, source trash and ESO target Secret recreation.
- A defined soak interval and version/image digests, plus visible per-replica
  outcomes and failure rates, without vault names, item IDs or secret values.

The [live testing guide](live-testing.md) describes disposable CI fixtures; the
[failure and recovery runbook](operations/failure-and-recovery.md) defines what
must fail closed. Preserve current security boundaries. Independent protocol
review and backend qualification remain separate from internal benchmarks.
