# 0002 — Keep the Bitwarden protocol boundary independent

## Status

Accepted 2026-05-13; rationale corrected during the 2026-10-13 review.

## Decision

Do not introduce a Bitwarden SDK dependency in this change. Keep the limited
Password Manager protocol implementation in `bweso-bitwarden`, using established
Rust cryptographic primitives and independently produced interoperability
fixtures. Do not copy or translate upstream implementation code into this
Apache-2.0 repository without a separate license review.

## Rationale

An SDK could reduce duplicated protocol work, especially organization-key
handling. It also adds dependency, API-stability and licensing questions. Those
need evaluation against exact crate versions and licenses, not assumptions from
a repository name or a historical snapshot.

Earlier wording categorically described relicensing every artifact and treated
all upstream test vectors as automatically reusable. Those statements were too
broad. This decision records an engineering boundary, not legal advice or a
license clearance. Evaluate the selected components and intended distribution
before adopting dependencies or reusing source/test material.

Keeping protocol code small does not prove it correct. The Argon2 salt bug
found in October 2026 passed earlier self-generated fixtures. That is direct
evidence for independent implementations and actual backend tests, rather than
claims that the existing code already works or has an audited baseline.

## Consequences

The project owns compatibility drift and maintenance of API-key login, user-key
unwrap, encrypted strings and item extraction. CI must exercise independent
fixtures and a real Vaultwarden backend. Cloud-specific behavior still needs
explicit Cloud verification. Document limitations instead of swallowing
unsupported data into apparent success or source deletion.

An independent protocol/security review remains valuable. Do not implement
organization-key decryption merely by porting upstream code during cleanup.

## Revisit when

Reassess adoption when a suitable stable SDK surface is available, the exact
license/dependency implications have been reviewed, or maintaining protocol
compatibility is more costly than accepting the SDK coupling. Compare actual
alternatives and measured maintenance cost; dependency count alone is not a
security or correctness argument.
