# Crypto Notes

## Supported Format

The first implementation supports authenticated Bitwarden encrypted strings:

```text
2.<base64 iv>|<base64 ciphertext>|<base64 hmac>
```

The symmetric key is the standard 64-byte Bitwarden form:

- bytes `0..32`: AES-256-CBC encryption key
- bytes `32..64`: HMAC-SHA256 authentication key

The HMAC input is `iv || ciphertext`. Decryption verifies the MAC before
attempting AES-CBC decryption.

## Explicitly Disabled

Legacy AES-CBC encrypted strings without a MAC, including type `0` and untyped
`iv|ciphertext` strings, are rejected. This matches the current Bitwarden client
direction and avoids accepting tamperable ciphertext in a Kubernetes secret
sync path.

## Master Password Unlock

The Bitwarden client crate derives master keys from the normalized account email
(`trim` + lowercase) and the server prelogin KDF config:

- PBKDF2-HMAC-SHA256 (`KdfType = 0`)
- Argon2id (`KdfType = 1`, memory converted from MiB to KiB)

It rejects prelogin KDF parameters below Bitwarden's current downgrade
minimums, and also caps them at Bitwarden's current setting maximums so a
controller process cannot be asked to perform unbounded key derivation. The
derived 32-byte master key is stretched with HKDF-SHA256 using `enc` and `mac`
info labels to decrypt the master-key-wrapped 64-byte user key.

## Current Scope

This code covers master-password user-key unlock and field-level cipher
decryption once the correct user, organization, or item key is available. User
API-key login and per-cipher key handling are implemented. Organization key
unwrap is separate work and must receive fixture tests plus live Vaultwarden and
Bitwarden Cloud verification before support is advertised. Selected shared
organization items fail explicitly in the current release line.

## Argon2 interoperability regression (fixed in 0.5.0-rc.1)

The `v0.4.0` Argon2 path incorrectly uses the normalized email directly as the
Argon2 salt. Bitwarden Password Manager instead uses the SHA-256 digest of that
normalized email. PBKDF2 still uses the normalized email directly. This was a
compatibility failure, not evidence that the Argon2 primitive itself was weak.
`0.5.0-rc.1` corrects the derivation. Use the exact release verification evidence
before installing an image; current Bitwarden Cloud qualification remains open.

Regression vectors use synthetic inputs and were independently generated with
`argon2-cffi` 25.1.0 / libargon2, not with this repository's Rust code. Reproduce
the original account fixture with:

```python
import base64
import hashlib
from argon2.low_level import Type, hash_secret_raw

salt = hashlib.sha256(" User@Example.COM ".strip().lower().encode()).digest()
key = hash_secret_raw(
    b"correct horse battery staple", salt,
    time_cost=2, memory_cost=16 * 1024, parallelism=1,
    hash_len=32, type=Type.ID, version=19,
)
assert base64.b64encode(key).decode() == (
    "aEgjyL6m4hJR5qk6Qow5zqboJtfdI2zu3lSqNkgDE7A="
)
```

Additional fixtures cover independent inputs, multiple lanes, a 64 MiB cost,
and a Unicode password. The protocol behavior was checked against
[Bitwarden's KDF implementation at an immutable revision](https://github.com/bitwarden/sdk-internal/blob/229c5b9a897b670ca988b6c03ee8a3c5e90128a6/crates/bitwarden-crypto/src/keys/kdf.rs).
No upstream implementation was vendored or linked.

The provider's Argon2 allocation budget defaults to 64 MiB and is checked before
key derivation. `BWESO_ARGON2_MEMORY_LIMIT_MIB` and Helm
`config.argon2MemoryLimitMiB` accept 16–1024 MiB. Increase the pod memory limit
as well as this budget for accounts with larger costs. Leave headroom for the
HTTP response, encrypted cache, decrypted fields and allocator overhead; a KDF
budget is not a whole-process memory limit. The chart defaults to 256 MiB.

KDF work runs on a blocking worker rather than a Tokio async worker. A permit
limits each client to one active unlock and stays inside the blocking task if
the caller is cancelled. Plaintext cipher fields, temporary unwrapped cipher
keys and the collected token-response buffer are wiped on drop where owned by
this implementation. HTTP/framework buffers and process memory are not an
independent security boundary. This project has not received an independent
cryptographic audit.
