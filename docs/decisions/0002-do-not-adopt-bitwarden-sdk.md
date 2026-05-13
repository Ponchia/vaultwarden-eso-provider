# 0002 — Do Not Adopt the Bitwarden SDK as a Dependency

## Status

Accepted, 2026-05-13.

## Context

The provider currently hand-rolls the Bitwarden-compatible protocol layer in
`crates/bweso-bitwarden`: AES-256-CBC + HMAC-SHA256 encrypted-string parsing
and decryption, PBKDF2-SHA256 / Argon2id master-key derivation, HKDF
stretching, master-key-wrapped user-key unwrap, the cipher model, and the
prelogin / API-key login / sync HTTP calls. The earlier project review raised
this as a one-maintainer drift risk: the protocol surface tracks an external
project (Bitwarden, with Vaultwarden following), and the audit baseline of
hand-rolled crypto is weaker than the baseline of Bitwarden's own audited
client crates.

The natural alternative is the open-source Bitwarden SDK at
[`bitwarden/sdk-internal`](https://github.com/bitwarden/sdk-internal),
specifically the `bitwarden-crypto` and `bitwarden-core` crates plus the
`bitwarden-api-api` / `bitwarden-api-identity` HTTP clients.

## Decision

**Do not link the Bitwarden SDK crates as dependencies.** Use the SDK only
as a *reference implementation* — read the code, port the protocol behavior
into our own crate, and import test vectors as fixture data — but keep this
project's Bitwarden-compatible logic in `crates/bweso-bitwarden`, under
Apache-2.0.

## Rationale

### License is the first blocker, and it is decisive

The root `LICENSE` file at `bitwarden/sdk-internal` (verified 2026-05-13)
states:

> Source code in this repository is covered by one of two licenses:
> (i) the GNU General Public License (GPL) v3.0
> (ii) the BITWARDEN SOFTWARE DEVELOPMENT KIT LICENSE v2.0.

Both `crates/bitwarden-crypto/Cargo.toml` and `crates/bitwarden-core/Cargo.toml`
declare `license-file.workspace = true`, which resolves to this dual-license.

For a third-party project, the effective license is GPL-3.0 — the Bitwarden
SDK License v2.0 is a vendor-favoring license intended for Bitwarden's own
products and is not a general-purpose open-source license.

This project is Apache-2.0. Rust links statically, so taking a GPL-3.0
dependency forces the entire binary to be GPL-3.0. That is a hard relicense
of the project, of the container image, and of the Helm chart artifacts.

License compatibility alone closes the question. Everything below is
additional reasoning that would still apply if the license were permissive.

### The SDK is explicitly internal

The repository is named `sdk-internal`. Bitwarden has been explicit that the
SDK is for their own first-party clients and that API stability for
third-party consumers is not promised. Adopting it trades one drift risk
(the Bitwarden server protocol, which is a wire format that moves slowly and
is equally tracked by Vaultwarden) for another (the SDK's Rust API surface,
which Bitwarden actively reshapes). For a webhook this small, the server
protocol is the easier moving target.

### The code being replaced is small

Stripping tests and workspace plumbing, the hand-rolled protocol logic in
`crates/bweso-bitwarden` is roughly 1500 LOC. The hardest parts — KDF
parameter bounds, HKDF expand to a 64-byte split key, MAC-then-decrypt,
authenticated-encryption framing — are already implemented correctly with
deterministic fixture vectors. The savings from adoption are not large
enough on their own to justify the license and stability costs.

### Dependency footprint cost

The current workspace has ~24 direct dependencies and a tight, audit-friendly
graph: `forbid(unsafe_code)`, pedantic clippy, deny `unwrap`/`expect`/`panic`.
Pulling in `bitwarden-core` drags chrono, schemars, uuid, several wrapper
crates, and the rest of the SDK tree. Dependency count roughly triples for
code that already works.

### What the SDK would actually help with

The one place adoption would genuinely help is **organization-item
decryption**. Organization key unwrap is more involved than user key unwrap
(user-key-encrypted organization keys, RSA-wrapped collection keys,
per-collection vs per-organization splits). It is the part where rolling our
own carries the most correctness and drift risk. Even there, the license
issue blocks direct adoption, so the realistic path is to port the logic
from the SDK and Vaultwarden's server code into `crates/bweso-bitwarden`
with our own fixture tests.

## Consequences

- The hand-rolled Bitwarden-compatible protocol code stays in
  `crates/bweso-bitwarden` under Apache-2.0.
- Organization-item decryption work in v0.2+ will be implemented by reading
  the open-source SDK and Vaultwarden server code as a reference, porting
  the protocol behavior, and validating against fixture vectors lifted from
  the SDK's test data (test vectors are facts about the protocol, not
  copyrighted expression).
- Drift risk against the Bitwarden server protocol is acknowledged and
  mitigated by: (1) fake-server fixture tests in `crates/bweso-bitwarden`,
  (2) the `scripts/live-eso-smoke.sh` live smoke against Vaultwarden and
  Bitwarden Cloud on every release, and (3) the roadmap item to add a
  Vaultwarden-in-kind integration target so the protocol is exercised
  against the actual primary backend on every CI run.
- The "one maintainer's hand-rolled crypto" concern remains a real concern
  and is queued as a v0.2+ item to address through a focused external audit
  of `crates/bweso-bitwarden`, not through SDK adoption.

## When to revisit

Revisit this decision if any of the following changes:

- Bitwarden relicenses `bitwarden-crypto` (or a relevant subset) under a
  permissive license compatible with Apache-2.0.
- Bitwarden publishes a stable, externally-supported SDK with API-stability
  guarantees for third-party consumers.
- This project relicenses to GPL-3.0 for unrelated reasons.
