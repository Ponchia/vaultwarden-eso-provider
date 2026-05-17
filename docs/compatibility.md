# Compatibility

This project targets the Bitwarden Password Manager vault protocol. The
primary target is **Vaultwarden** (and self-hosted Bitwarden Password Manager
exposed through a single origin); **Bitwarden Cloud Password Manager** is a
supported second target through the split-endpoint mode. Bitwarden Secrets
Manager (`bws`) is not in scope and is not implemented by Vaultwarden in any
case.

## Endpoint Modes

Two endpoint layouts are supported.

Single-origin servers use one URL and derive the API roots from it. This is
the Vaultwarden layout and also matches self-hosted Bitwarden when exposed
through one origin:

```bash
BWESO_SINGLE_ORIGIN_URL="https://vaultwarden.example.com"
```

Requests are built as:

- Identity: `https://vaultwarden.example.com/identity/...`
- API: `https://vaultwarden.example.com/api/...`

Split endpoint servers use explicit identity and API URLs. This is the
Bitwarden Cloud layout:

```bash
BWESO_IDENTITY_URL="https://identity.bitwarden.com"
BWESO_API_URL="https://api.bitwarden.com"
```

For Bitwarden EU, use:

```bash
BWESO_IDENTITY_URL="https://identity.bitwarden.eu"
BWESO_API_URL="https://api.bitwarden.eu"
```

The provider appends only the endpoint-specific paths in split mode:

- Prelogin: `{identity_url}/accounts/prelogin/password`
- Token: `{identity_url}/connect/token`
- Sync: `{api_url}/sync?excludeDomains=true`

## Verified Contract

The automated suite has fake-server coverage for both endpoint layouts:

- Vaultwarden/self-hosted single-origin routes under `/identity` and `/api`.
- Bitwarden-style split identity and API servers with root-relative
  `/connect/token`, `/accounts/prelogin/password`, and `/sync` routes.
- Token form fields use Bitwarden client casing for device metadata:
  `deviceIdentifier`, `deviceName`, and `deviceType`.

The live smoke test can be aimed at either layout:

- `BWESO_TEST_SINGLE_ORIGIN_URL` for single-origin servers.
- `BWESO_TEST_IDENTITY_URL` plus `BWESO_TEST_API_URL` for Bitwarden Cloud or
  explicit split deployments.

Live verification status. These are smoke tests run by the maintainer on a
personal k3s cluster on the dates listed; treat them as "the release path
worked end-to-end on this date," not as production soak time:

- Vaultwarden single-origin: smoke-tested against the exact `v0.1.3` OCI
  release chart and image on a real k3s cluster on 2026-05-11, including
  selector policy, single-field and whole-item sync, target Secret recreation,
  webhook restart, negative cases, and redacted metrics. This is historical
  backend evidence reused by `v0.2.x` only for the unchanged login/sync protocol
  path.
- Bitwarden Cloud US split endpoints: smoke-tested against a dedicated live
  account and the exact `v0.1.1` release chart and image on a real k3s
  cluster on 2026-05-11, including selector policy, single-field and
  whole-item sync, target Secret recreation, webhook restart, negative cases,
  and redacted metrics. The current `v0.2.1` release keeps the same
  split-endpoint provider protocol implementation covered by fake-server tests.

The latest Vaultwarden live verification environment used:

- k3s server `v1.34.5+k3s1`.
- External Secrets Operator `v2.4.1`.
- Helm `v4.1.4`.
- Vaultwarden `1.35.4`.

## Current Scope

Implemented:

- User API-key login with master-password unlock data.
- PBKDF2-SHA256 and Argon2id account KDFs.
- Authenticated Bitwarden encrypted strings.
- Login, secure-note notes, custom fields, TOTP fields, and SSH key fields.
- Individual vault item sync against single-origin and split endpoint layouts.
- Single-field ESO sync through `remoteRef` and whole-item ESO sync through
  `dataFrom.extract`.
- `id:<item-id>` and `name:<item-name>` selectors. Explicit prefix required;
  unprefixed bare keys are rejected with `400 validation`.
- Provider-side selector policy based on exact raw keys and raw key prefixes.
  This policy gates item keys, not individual item properties.
- Optional ConfigMap-backed selector policy hot reload.
- Custom CA bundle support for private Vaultwarden CAs. Extra roots supplement
  the bundled WebPKI trust roots.
- Global `/v1/resolve` concurrency cap with `503 overloaded` load shedding.

Not yet implemented:

- Bitwarden Secrets Manager (`bws`) machine-account/project secret APIs.
  Out of scope by design; not implemented by Vaultwarden in any case.
- Shared organization item decryption that requires organization key handling.
  Selected shared items fail explicitly instead of silently returning partial
  results. For many teams this is the largest gap — pure-personal vaults or
  dedicated per-user-key deployments are the realistic current use cases.
- Attachment metadata lookup, download, decryption, and mapping. Properties
  beginning with `attachment.` or `attachments.` fail explicitly.
- Interactive two-factor or new-device challenge handling for API-key login.
- Per-source rate limiting. The current concurrency cap is global, not per
  namespace, token, or selector.
