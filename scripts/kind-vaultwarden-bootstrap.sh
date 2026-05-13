#!/usr/bin/env bash
#
# Bootstrap a Vaultwarden instance inside a kind cluster, register a user via
# Vaultwarden's open-signup endpoint, mint a personal API key, plant a vault
# item, and emit the values the integration test needs as environment-style
# output on stdout.
#
# Designed to run inside .github/workflows/kind-integration.yml. The cluster
# and Vaultwarden Deployment must already be applied (see the workflow);
# this script handles the user/API key/item flow that does not lend itself
# to YAML.
#
# Usage:
#   ./scripts/kind-vaultwarden-bootstrap.sh <vaultwarden_url> <email> <password>
#
# On success, prints lines suitable for >> "$GITHUB_OUTPUT":
#   client_id=...
#   client_secret=...
#   item_id=...
#   item_name=...
#
# Anything written to stderr is diagnostic and not consumed by the workflow.

set -euo pipefail

VW_URL="${1:?vaultwarden base URL required}"
EMAIL="${2:?email required}"
PASSWORD="${3:?master password required}"

echo "::group::wait for vaultwarden /alive" >&2
for _ in $(seq 1 60); do
  if curl -sf "${VW_URL}/alive" >/dev/null; then break; fi
  sleep 2
done
echo "::endgroup::" >&2

echo "::group::register user via /api/accounts/register" >&2
# Vaultwarden allows public signup when SIGNUPS_ALLOWED=true. We send the
# Bitwarden-style registration payload with PBKDF2 KDF.
# The master_password_hash is the base64 PBKDF2(masterKey, password, 1).
# For bootstrap we lean on /tools/registration_token if SIGNUPS_DOMAINS_WHITELIST
# is empty; otherwise the request below works directly.
register_payload=$(jq -nc \
  --arg email "$EMAIL" \
  --arg name "kind-test" \
  --arg hint "kind-bootstrap" \
  '{
    email: $email,
    name: $name,
    masterPasswordHash: "BOOTSTRAP_REPLACED_BY_NEXT_STEP",
    masterPasswordHint: $hint,
    kdf: 0,
    kdfIterations: 600000,
    key: "BOOTSTRAP_REPLACED",
    keys: { publicKey: "BOOTSTRAP_REPLACED", encryptedPrivateKey: "BOOTSTRAP_REPLACED" }
  }')
echo "WARNING: Direct registration with proper key material is not implemented" >&2
echo "in this scaffold script. See the README for the bw CLI approach." >&2
echo "::endgroup::" >&2

# Producing a real registration payload requires running the Bitwarden
# crypto stack (PBKDF2 -> stretch -> generate AES key -> RSA keypair -> wrap).
# Doing that in pure bash is impractical. Two options for completing this:
#
#   1. Run the upstream `bw` CLI against the Vaultwarden instance to register
#      a user, then mint an API key from the admin panel using ADMIN_TOKEN.
#   2. Use the bweso-bitwarden crate to write a tiny `cargo run --bin
#      vaultwarden-test-bootstrap` helper that performs the registration +
#      item creation flow with real crypto.
#
# Option 2 is the recommended path. Tracked in the roadmap.

echo "client_id=user.PLACEHOLDER"
echo "client_secret=PLACEHOLDER"
echo "item_id=PLACEHOLDER"
echo "item_name=PLACEHOLDER"
exit 1  # Hard-fail until the bootstrap helper is wired up.
