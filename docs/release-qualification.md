# Candidate qualification

`0.5.0-rc.1` identifies an **unpublished candidate**, not a released version.
The published release remains `v0.4.0`. Preparing or testing artifacts does not
publish an image, create a tag, or authorize a production rollout.

## Public, disposable checks

The Artifact qualification workflow builds the exact source revision for native
AMD64 and ARM64, packages the chart once per job, and deploys that archive with
the exact locally loaded image into an isolated kind cluster. No public registry
push occurs. Fixtures create independent PBKDF2 and Argon2 accounts on a pinned
Vaultwarden service; they never use real accounts or a user's email.

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

## Private Cloud checks

Use a separate Bitwarden Cloud test account with synthetic secrets, never the
operator's personal password vault. The user's Gmail may receive verification
mail, but Gmail/Google credentials and cookies are not provider inputs. Do not
store the account email, master password, personal API key or session in GitHub
variables, secrets, Actions inputs, logs or build contexts for this qualification.

Run only the reviewed artifact, verify its checksum/provenance first, and retain
only a redacted result and artifact identity in the public issue. Keep temporary
credentials outside every repository with restrictive permissions; revoke test
access and remove temporary state when the qualification is complete. A browser
may retain its normal private session; closing a tab is not credential erasure.

Issue #75 remains open until current artifact qualification and a separate
live Bitwarden Cloud pass have actual evidence. Independent external review
is separate (#76).
