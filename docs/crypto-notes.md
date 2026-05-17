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
