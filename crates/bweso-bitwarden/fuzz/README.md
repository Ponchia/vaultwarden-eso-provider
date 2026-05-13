# Fuzz targets for bweso-bitwarden

These targets exercise parsers and primitives that eat untrusted bytes from
the Bitwarden-compatible upstream. They are not built by the normal
workspace; cargo-fuzz uses libFuzzer which requires a nightly toolchain.

## Targets

- `encrypted_string_from_str` — fuzzes the `2.iv|data|mac` parser. Property:
  no input must panic; every malformed input must surface as a typed
  `CryptoError`.

## Run locally

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cd crates/bweso-bitwarden/fuzz
cargo +nightly fuzz run encrypted_string_from_str -- -max_total_time=60
```

The seeded corpus in `corpus/encrypted_string_from_str/` includes the
valid AES-CBC/HMAC fixture, a legacy type-0 (no-MAC) string that must be
rejected, and an empty input.

Crashes are written to `artifacts/encrypted_string_from_str/`. Reproduce
with `cargo +nightly fuzz run encrypted_string_from_str <artifact-path>`.
