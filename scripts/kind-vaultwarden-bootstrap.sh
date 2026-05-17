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
# On success, prints lines suitable for appending to "$GITHUB_OUTPUT":
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
# Validate these inputs without logging them; the bootstrap flow below is still
# intentionally unimplemented.
: "${EMAIL}" "${PASSWORD}"

echo "::group::wait for vaultwarden /alive" >&2
for _ in $(seq 1 60); do
  if curl -sf "${VW_URL}/alive" >/dev/null; then break; fi
  sleep 2
done
echo "::endgroup::" >&2

cat >&2 <<'EOF'
::error::Vaultwarden kind bootstrap is not implemented yet.

Producing a real registration payload requires running the Bitwarden crypto
stack: PBKDF2, stretch, generate an AES key, generate an RSA keypair, and wrap
the private key. Doing that in pure bash is impractical. Two options for
completing this:

1. Run the upstream `bw` CLI against the Vaultwarden instance to register a
   user, then mint an API key from the admin panel using ADMIN_TOKEN.
2. Use the bweso-bitwarden crate to write a tiny `cargo run --bin
   vaultwarden-test-bootstrap` helper that performs the registration and item
   creation flow with real crypto.

Option 2 is the recommended path. It is tracked in docs/roadmap.md.
EOF
exit 1
