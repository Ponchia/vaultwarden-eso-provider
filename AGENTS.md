# Bitwarden ESO Provider Instructions

This is a standalone Rust repository. Keep commits and generated artifacts local
to this repository.

## Boundaries

- Reference repositories, when checked out locally, belong outside this repo.
  Keep public source URLs and durable review notes in `docs/`.
- Do not vendor or copy implementation code from reference repositories.
- Treat Bitwarden and Vaultwarden source as reference material only unless a
  license review explicitly approves reuse.
- Do not put real Bitwarden/Vaultwarden credentials, master passwords, API
  tokens, or Kubernetes kubeconfigs in this repository.
- Do not create release tags or run release publishing unless the maintainer
  explicitly asks for a release. Normal cleanup and implementation work should
  land on `main` first; release only after the maintainer decides the current
  state is ready.

## Checks

Before handing off code changes, run:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

If dependencies change, also run:

```bash
cargo generate-lockfile
cargo tree
```

## Security Defaults

- `unsafe` is forbidden.
- TLS verification is mandatory by default.
- Secret values must use redacting or zeroizing wrappers where practical.
- Logs, metrics, and public error responses must not include vault item IDs,
  item names, requested property names, secret values, API tokens, master
  passwords, or derived keys.
- Deletion, rollout, and namespace-scoped behavior must be explicit in the
  Kubernetes-facing API.

## House check

Run `repo-instruction-audit --repo .` after changing agent instructions or
documentation routing.
