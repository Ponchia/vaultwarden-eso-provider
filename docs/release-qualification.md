# Candidate qualification

`0.5.0-rc.2` is a **prerelease candidate** for the Vaultwarden release line.
GitHub Releases records publication and exact artifact evidence. Candidate
checks alone neither publish artifacts nor establish that released bytes passed.
The `0.5.0` release line is scoped to Vaultwarden only. Bitwarden Cloud
acceptance is deferred in #75, remains unverified, and does not block that release.

## Public, disposable checks

The Artifact qualification workflow builds the exact source revision for native
AMD64 and ARM64, packages the chart once per job, and deploys that archive with
the exact locally loaded image into an isolated kind cluster. No public registry
push occurs. Fixtures create independent PBKDF2 and Argon2 accounts on a pinned
Vaultwarden service; they never use real accounts or a user's email.
The fixture increases only its disposable backend's login burst limit because
it compresses many restart/rollback unlocks into minutes. Production limits
are unchanged. The separate normal interoperability workflow retains the
backend defaults; this qualification is not a rate-limit/load test (#76).
The exact loaded container is scanned for high/critical fixed vulnerabilities
and embedded secrets before testing or retaining its archive.

The checks exercise private-CA TLS, file-mounted credentials, item and field
reads, policy enforcement, source rotation, missing fields versus deletion,
ESO Delete/Retain, provider restart, target recreation, and a configuration
upgrade/rollback. A separate cross-version test loads the released v0.4.0 image
by its immutable digest and chart archive by checksum. PBKDF2 must remain
readable through rollback; the known v0.4.0 Argon2 incompatibility must fail
without deleting targets, followed by recovery onto the candidate. These are
fixture acceptance tests, not a promise that every production migration works.

Only an explicit artifact allowlist is uploaded: container archive, extracted
binary, packaged chart, checksums and a count/status-only qualification record.
Kubeconfigs, fixture directories, logs, browser profiles and account credentials
are excluded. Successful main builds additionally attest artifact provenance.
The record deliberately says `cloudTested: false`; a disposable Vaultwarden pass
must not be presented as Bitwarden Cloud verification.

## Verify published artifacts without rebuilding

Select the release tag as both the workflow ref and the validated input:

```bash
gh workflow run qualification.yml --ref v0.5.0-rc.2 \
  -f release_tag=v0.5.0-rc.2
```

This mode downloads the signed release archive, checks its checksum against
release evidence, verifies the chart and image signatures and provenance with
the exact tag/source/workflow, and confirms the OCI chart has identical bytes.
It then pulls the image by digest and runs the same native packaged lifecycle
tests. It does not rebuild the image or chart. The qualification record names
the release tag and image digest and records `published: true`; `cloudTested`
remains false. Use this run before promoting the package into a live deployment.

## Deferred private Cloud checks

Do not run this work as part of the Vaultwarden release. When the maintainer
resumes #75, use a separate Bitwarden Cloud test account with synthetic secrets,
never the operator's personal password vault. The user's Gmail may receive verification
mail, but Gmail/Google credentials and cookies are not provider inputs. Do not
store the account email, master password, personal API key or session in GitHub
variables, secrets, Actions inputs, logs or build contexts for this qualification.

Run only the reviewed artifact, verify its checksum/provenance first, and retain
only a redacted result and artifact identity in the public issue. Keep temporary
credentials outside every repository with restrictive permissions; revoke test
access and remove temporary state when the qualification is complete. A browser
may retain its normal private session; closing a tab is not credential erasure.

Issue #75 remains open as non-blocking follow-up until a separate live Bitwarden
Cloud pass has actual evidence. Its deferral does not remove any Vaultwarden
artifact gate. Independent external review is separate (#76).
