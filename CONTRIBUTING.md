# Contributing

Thanks for helping improve Vaultwarden ESO Provider. This project sits between a
password manager, External Secrets Operator, and Kubernetes Secrets, so changes
must keep security, compatibility, and operational behavior clear.

## Ground Rules

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Do not include real secrets, master passwords, API tokens, vault item IDs,
  vault item names, Kubernetes Secret values, kubeconfigs, or private
  infrastructure details in issues, pull requests, tests, examples, screenshots,
  logs, or commit history.
- Keep reference code out of the source tree. Public source links and durable
  review notes belong in `docs/`.
- Prefer small pull requests with a focused behavior change.
- Add tests for behavior that touches auth, decryption, sync semantics,
  redaction, metrics, Helm rendering, or Kubernetes-facing contracts.
- Update docs, examples, chart values, and schema when user-facing behavior
  changes.
- Update `docs/decisions` when architecture changes.
- Keep defaults conservative, especially around deletion, TLS, logging, auth,
  NetworkPolicy, and RBAC.

## Development

Install a stable Rust toolchain and Helm. The fastest path is to use
[mise](https://mise.jdx.dev/) and [just](https://just.systems/man/en/):

```bash
mise install
mise run check
```

`mise.toml` pins the local tool versions used by the project, and `justfile`
keeps the common commands discoverable with `mise run default` or `just --list`.
Without mise/just, run the underlying commands directly:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo llvm-cov --locked --workspace --all-targets \
  --fail-under-lines 80 --summary-only
helm lint deploy/helm/vaultwarden-eso-provider -f deploy/helm/lint-values.yaml
helm template bweso deploy/helm/vaultwarden-eso-provider \
  -f deploy/helm/lint-values.yaml --namespace bweso-system
```

For a broader local CI mirror, run:

```bash
mise run ci
```

`cargo llvm-cov` is the public CI coverage gate. The threshold is intentionally
conservative; review should focus on meaningful tests for auth, selector policy,
decryption, redaction, cache behavior, and Kubernetes-facing contracts.

If dependencies change, also run:

```bash
cargo generate-lockfile
cargo tree
```

## Pull Requests

Pull requests should explain:

- What changed and why.
- Which backend was affected: Bitwarden Cloud, Vaultwarden, self-hosted
  Bitwarden, ESO, Helm, or packaging.
- How the change was validated.
- Whether there are compatibility or security implications.

The default merge path is expected to be squash merge after required checks and
review pass.
