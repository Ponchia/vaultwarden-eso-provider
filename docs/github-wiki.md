# GitHub Wiki Strategy

GitHub Wiki can be enabled for this repository, but it should not become the
source of truth for documentation.

At the time this note was added, the repository wiki was disabled. Verify the
current setting with:

```bash
gh repo view Ponchia/vaultwarden-eso-provider --json hasWikiEnabled
```

Enable it with:

```bash
gh repo edit Ponchia/vaultwarden-eso-provider --enable-wiki
```

## Recommendation

Keep canonical documentation in this repository under `README.md`, `docs/`,
`deploy/eso`, and `deploy/helm`.

Use the GitHub Wiki only as a convenience front door or curated mirror. Wiki
pages live in a separate Git repository and do not naturally pass through the
same pull-request review, CI checks, release-note labels, branch protection, or
security review workflow as normal docs changes.

## Good Wiki Pages

If the wiki is enabled, keep it small:

- `Home`: short project summary and links back to `README.md` and
  `docs/index.md`.
- `Install`: link to `docs/install/eso-webhook.md`.
- `Selectors and Policy`: link to `docs/selectors-and-policy.md`.
- `Operations`: link to observability, restarts, and migration docs.
- `Release Verification`: link to `docs/release-verification.md`.

Do not duplicate long install commands or security guidance by hand unless
there is a deliberate sync process. Stale wiki security guidance is worse than
no wiki.

## Future Sync Option

A later workflow can publish selected Markdown files into the wiki repository
after docs checks pass on `main`. That should be treated as a publishing step,
not as the authoring workflow. The source files should stay in this repository.
