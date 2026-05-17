# Pull Request

## Summary

-

## Release Notes

- [ ] Label this PR for generated release notes (`feature`, `bug`, `security`,
      `devops`, `ci`, `release`, `documentation`, `dependencies`, or
      `breaking-change`).
- [ ] Add `skip-changelog` only when the change should not appear in release
      notes.
- [ ] Update `CHANGELOG.md` when the change is notable to operators or users.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --workspace --all-targets -- -D warnings`
- [ ] `cargo test --locked --workspace --all-targets`
- [ ] `cargo llvm-cov --locked --workspace --all-targets --fail-under-lines 80 --summary-only`
- [ ] `helm lint deploy/helm/vaultwarden-eso-provider -f deploy/helm/lint-values.yaml`
- [ ] `helm template bweso deploy/helm/vaultwarden-eso-provider \
      -f deploy/helm/lint-values.yaml --namespace bweso-system`

## Security And Compatibility

- [ ] No secrets, vault item names, vault item IDs, requested properties,
      API tokens, master passwords, or derived keys are logged or exposed in
      metrics/errors.
- [ ] TLS, authentication, RBAC, NetworkPolicy, and deletion defaults stay
      conservative.
- [ ] Bitwarden Cloud and Vaultwarden compatibility is unchanged or documented.
- [ ] User-facing docs, chart values, examples, and schema were updated when
      behavior changed.
