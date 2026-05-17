#!/usr/bin/env bash
set -euo pipefail

chart="${1:-deploy/helm/vaultwarden-eso-provider}"
values="${2:-deploy/helm/lint-values.yaml}"
namespace="${3:-bweso-system}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

cat >"${tmpdir}/no-selector-policy.yaml" <<'YAML'
selectorPolicy:
  allowedKeys: []
  allowedKeyPrefixes: []
  allowAllSelectors: false
  configMap:
    name: ""
    keys:
      allowedKeys: ""
      allowedKeyPrefixes: ""
YAML

cat >"${tmpdir}/allow-all.yaml" <<'YAML'
selectorPolicy:
  allowedKeys: []
  allowedKeyPrefixes: []
  allowAllSelectors: true
  configMap:
    name: ""
    keys:
      allowedKeys: ""
      allowedKeyPrefixes: ""
YAML

cat >"${tmpdir}/configmap-exact-only.yaml" <<'YAML'
selectorPolicy:
  allowedKeys: []
  allowedKeyPrefixes: []
  allowAllSelectors: false
  configMap:
    name: bweso-selector-policy
    keys:
      allowedKeys: allowed-keys
      allowedKeyPrefixes: ""
YAML

cat >"${tmpdir}/configmap-prefix-only.yaml" <<'YAML'
selectorPolicy:
  allowedKeys: []
  allowedKeyPrefixes: []
  allowAllSelectors: false
  configMap:
    name: bweso-selector-policy
    keys:
      allowedKeys: ""
      allowedKeyPrefixes: allowed-key-prefixes
YAML

expect_render_contains() {
  local expected="$1"
  shift
  helm template bweso "${chart}" -f "${values}" --namespace "${namespace}" "$@" |
    grep -q "${expected}"
}

expect_render_fails() {
  if helm template bweso "${chart}" -f "${values}" --namespace "${namespace}" "$@" >/dev/null 2>&1; then
    echo "expected helm render to fail: $*" >&2
    exit 1
  fi
}

expect_render_fails -f "${tmpdir}/no-selector-policy.yaml"
expect_render_fails --set selectorPolicy.allowAllSelectors=true

expect_render_contains 'BWESO_ALLOW_ALL_SELECTORS' -f "${tmpdir}/allow-all.yaml"
expect_render_contains 'BWESO_ALLOWED_KEYS_FILE' -f "${tmpdir}/configmap-exact-only.yaml"
expect_render_contains 'BWESO_ALLOWED_KEY_PREFIXES_FILE' -f "${tmpdir}/configmap-prefix-only.yaml"
