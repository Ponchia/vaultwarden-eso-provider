#!/usr/bin/env bash
set -euo pipefail

chart="${1:-deploy/helm/vaultwarden-eso-provider}"
values="${2:-deploy/helm/lint-values.yaml}"
namespace="${3:-bweso-system}"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

helm template bweso "${chart}" \
  -f "${values}" \
  --namespace "${namespace}" \
  --set config.cacheStaleIfErrorSeconds=600 \
  --set config.cacheRefreshRetryIntervalSeconds=20 \
  >"${rendered}"

expect_env_value() {
  local name="$1"
  local value="$2"

  awk -v name="${name}" -v value="${value}" '
    $0 ~ "name: " name "$" {
      getline
      if ($0 ~ "value: \"" value "\"$") {
        found = 1
      }
    }
    END { exit found ? 0 : 1 }
  ' "${rendered}"
}

expect_env_value BWESO_CACHE_TTL_SECONDS 60
expect_env_value BWESO_CACHE_STALE_IF_ERROR_SECONDS 600
expect_env_value BWESO_CACHE_REFRESH_RETRY_INTERVAL_SECONDS 20

if helm template bweso "${chart}" -f "${values}" --namespace "${namespace}" \
  --set config.cacheStaleIfErrorSeconds=-1 >/dev/null 2>&1; then
  echo "expected a negative stale-cache window to fail schema validation" >&2
  exit 1
fi
