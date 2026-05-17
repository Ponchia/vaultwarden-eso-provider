#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${ROOT_DIR}/deploy/helm/vaultwarden-eso-provider"

log() {
  printf '[bweso-smoke] %s\n' "$*"
}

fail() {
  printf '[bweso-smoke] error: %s\n' "$*" >&2
  exit 1
}

truthy() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | y | Y | on | ON) return 0 ;;
    *) return 1 ;;
  esac
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

force_sync_value() {
  printf '%s-%s' "$(date +%s)" "${RANDOM}"
}

env_or_empty() {
  local name="$1"
  printf '%s' "${!name:-}"
}

first_env() {
  local name value
  for name in "$@"; do
    value="$(env_or_empty "${name}")"
    if [[ -n "${value}" ]]; then
      printf '%s' "${value}"
      return 0
    fi
  done
  return 1
}

url_host() {
  local raw="$1"
  raw="${raw#*://}"
  raw="${raw%%/*}"
  raw="${raw%%:*}"
  printf '%s' "${raw}"
}

kubectl_cmd=(kubectl)
helm_cmd=(helm)
kube_context="$(first_env BWESO_E2E_KUBE_CONTEXT KUBE_CONTEXT || true)"
if [[ -n "${kube_context}" ]]; then
  kubectl_cmd+=(--context "${kube_context}")
  helm_cmd+=(--kube-context "${kube_context}")
fi

require_cmd kubectl
require_cmd helm
require_cmd jq
require_cmd cargo
require_cmd curl
require_cmd openssl

namespace="$(first_env BWESO_E2E_NAMESPACE || true)"
namespace="${namespace:-bweso-live-smoke}"
release="$(first_env BWESO_E2E_RELEASE || true)"
release="${release:-bweso}"
image_repository="$(first_env BWESO_E2E_IMAGE_REPOSITORY || true)"
image_repository="${image_repository:-ghcr.io/ponchia/vaultwarden-eso-provider}"
image_tag="$(first_env BWESO_E2E_IMAGE_TAG || true)"
chart_ref="$(first_env BWESO_E2E_CHART_REF || true)"
chart_ref="${chart_ref:-${CHART_DIR}}"
chart_version="$(first_env BWESO_E2E_CHART_VERSION || true)"
credentials_secret="$(first_env BWESO_E2E_CREDENTIALS_SECRET || true)"
credentials_secret="${credentials_secret:-bweso-live-credentials}"
pull_secret="$(first_env BWESO_E2E_IMAGE_PULL_SECRET || true)"
target_secret="bweso-smoke-secret"
whole_target_secret="bweso-whole-item-secret"
selector_file="$(first_env BWESO_E2E_SELECTOR_FILE || true)"
cleanup_namespace=true
if truthy "$(first_env BWESO_E2E_KEEP_NAMESPACE || true)"; then
  cleanup_namespace=false
fi

[[ -n "${image_tag}" ]] || fail "set BWESO_E2E_IMAGE_TAG to the image tag to test"

single_origin_url="$(
  first_env \
    BWESO_TEST_SINGLE_ORIGIN_URL BWESO_SINGLE_ORIGIN_URL || true
)"
identity_url="$(
  first_env \
    BWESO_TEST_IDENTITY_URL BWESO_IDENTITY_URL || true
)"
api_url="$(first_env BWESO_TEST_API_URL BWESO_API_URL || true)"
client_id="$(first_env BWESO_TEST_CLIENT_ID BWESO_CLIENT_ID || true)"
client_secret="$(first_env BWESO_TEST_CLIENT_SECRET BWESO_CLIENT_SECRET || true)"
master_password="$(first_env BWESO_TEST_MASTER_PASSWORD BWESO_MASTER_PASSWORD || true)"
network_policy_enabled="$(first_env BWESO_E2E_NETWORK_POLICY_ENABLED || true)"
host_alias_ip="$(first_env BWESO_E2E_HOST_ALIAS_IP || true)"
host_alias_hostname="$(first_env BWESO_E2E_HOST_ALIAS_HOSTNAME || true)"

if [[ -n "${single_origin_url}" && ( -n "${identity_url}" || -n "${api_url}" ) ]]; then
  fail "use either BWESO_TEST_SINGLE_ORIGIN_URL/BWESO_SINGLE_ORIGIN_URL or split identity/api URLs, not both"
fi
if [[ -z "${single_origin_url}" && ( -z "${identity_url}" || -z "${api_url}" ) ]]; then
  fail "set a single-origin URL or both split endpoint URLs"
fi
[[ -n "${client_id}" ]] || fail "set BWESO_TEST_CLIENT_ID or BWESO_CLIENT_ID"
[[ -n "${client_secret}" ]] || fail "set BWESO_TEST_CLIENT_SECRET or BWESO_CLIENT_SECRET"
[[ -n "${master_password}" ]] || fail "set BWESO_TEST_MASTER_PASSWORD or BWESO_MASTER_PASSWORD"
if [[ -n "${network_policy_enabled}" ]]; then
  case "${network_policy_enabled}" in
    true | false) ;;
    *) fail "BWESO_E2E_NETWORK_POLICY_ENABLED must be true or false" ;;
  esac
fi
if [[ -n "${host_alias_ip}" && -z "${host_alias_hostname}" ]]; then
  [[ -n "${single_origin_url}" ]] || fail "set BWESO_E2E_HOST_ALIAS_HOSTNAME when using split endpoints"
  host_alias_hostname="$(url_host "${single_origin_url}")"
fi
if [[ -z "${host_alias_ip}" && -n "${host_alias_hostname}" ]]; then
  fail "set BWESO_E2E_HOST_ALIAS_IP when BWESO_E2E_HOST_ALIAS_HOSTNAME is set"
fi

tmp_dir="$(mktemp -d)"
port_forward_pid=""
local_port=""
stop_port_forward() {
  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
    port_forward_pid=""
  fi
}

cleanup() {
  stop_port_forward
  rm -rf "${tmp_dir}"
  if [[ "${cleanup_namespace}" == true ]]; then
    log "cleaning namespace ${namespace}"
    "${kubectl_cmd[@]}" delete namespace "${namespace}" --ignore-not-found=true --wait=false >/dev/null
    local deadline=$((SECONDS + 120))
    while (( SECONDS < deadline )); do
      if ! "${kubectl_cmd[@]}" get namespace "${namespace}" >/dev/null 2>&1; then
        return 0
      fi
      sleep 2
    done
    log "namespace ${namespace} is still terminating; inspect it manually if it does not disappear"
  else
    log "leaving namespace ${namespace} because BWESO_E2E_KEEP_NAMESPACE is set"
  fi
}
trap cleanup EXIT

selector_from_env() {
  local key property
  key="$(first_env BWESO_TEST_ITEM_KEY || true)"
  property="$(first_env BWESO_TEST_PROPERTY || true)"
  [[ -n "${key}" && -n "${property}" ]] || return 1
  jq -n --arg key "${key}" --arg property "${property}" \
    '{key: $key, property: $property}' >"${tmp_dir}/selector.json"
  selector_file="${tmp_dir}/selector.json"
}

selector_from_live_test() {
  export BWESO_TEST_CLIENT_ID="${client_id}"
  export BWESO_TEST_CLIENT_SECRET="${client_secret}"
  export BWESO_TEST_MASTER_PASSWORD="${master_password}"
  export BWESO_TEST_LIVE=true
  export BWESO_TEST_SELECTOR_OUTPUT="${tmp_dir}/selector.json"
  if [[ -n "${single_origin_url}" ]]; then
    export BWESO_TEST_SINGLE_ORIGIN_URL="${single_origin_url}"
    unset BWESO_TEST_IDENTITY_URL BWESO_TEST_API_URL
  else
    export BWESO_TEST_IDENTITY_URL="${identity_url}"
    export BWESO_TEST_API_URL="${api_url}"
    unset BWESO_TEST_SINGLE_ORIGIN_URL
  fi

  if [[ -z "$(first_env BWESO_TEST_ITEM_KEY || true)" ]]; then
    export BWESO_TEST_ALLOW_ANY_ITEM="${BWESO_TEST_ALLOW_ANY_ITEM:-true}"
  fi

  log "selecting a live vault item without printing values"
  (cd "${ROOT_DIR}" && cargo test -p bweso-bitwarden --test live_bitwarden -- --nocapture)
  selector_file="${tmp_dir}/selector.json"
}

if [[ -n "${selector_file}" ]]; then
  [[ -f "${selector_file}" ]] || fail "selector file does not exist: ${selector_file}"
elif ! selector_from_env; then
  selector_from_live_test
fi

item_key="$(jq -r '.key // empty' "${selector_file}")"
property="$(jq -r '.property // empty' "${selector_file}")"
[[ -n "${item_key}" ]] || fail "selector must contain .key"
[[ -n "${property}" ]] || fail "selector must contain .property for ESO value extraction"
missing_property="__bweso_missing_property_$(date +%s)"
missing_item="__bweso_missing_item_$(date +%s)"
denied_item="__bweso_policy_denied_item_$(date +%s)"

log "creating namespace ${namespace}"
"${kubectl_cmd[@]}" create namespace "${namespace}" --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f - >/dev/null

ghcr_token="$(first_env BWESO_E2E_GHCR_TOKEN || true)"
if [[ -n "${ghcr_token}" ]]; then
  pull_secret="${pull_secret:-ghcr-pull}"
  ghcr_user="$(first_env BWESO_E2E_GHCR_USER GITHUB_ACTOR || true)"
  ghcr_user="${ghcr_user:-bweso-smoke}"
  auth="$(printf '%s:%s' "${ghcr_user}" "${ghcr_token}" | base64 | tr -d '\n')"
  cat >"${tmp_dir}/dockerconfigjson" <<EOF
{"auths":{"ghcr.io":{"username":"${ghcr_user}","password":"${ghcr_token}","auth":"${auth}"}}}
EOF
  "${kubectl_cmd[@]}" -n "${namespace}" create secret generic "${pull_secret}" \
    --type=kubernetes.io/dockerconfigjson \
    --from-file=.dockerconfigjson="${tmp_dir}/dockerconfigjson" \
    --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f - >/dev/null
fi

printf '%s' "${client_id}" >"${tmp_dir}/client-id"
printf '%s' "${client_secret}" >"${tmp_dir}/client-secret"
printf '%s' "${master_password}" >"${tmp_dir}/master-password"
webhook_token="$(openssl rand -base64 48 | tr -d '\n')"
printf '%s' "${webhook_token}" >"${tmp_dir}/webhook-token"
chmod 0600 "${tmp_dir}/client-id" "${tmp_dir}/client-secret" "${tmp_dir}/master-password" "${tmp_dir}/webhook-token"

log "creating webhook credential Secret"
"${kubectl_cmd[@]}" -n "${namespace}" create secret generic "${credentials_secret}" \
  --from-file=client-id="${tmp_dir}/client-id" \
  --from-file=client-secret="${tmp_dir}/client-secret" \
  --from-file=master-password="${tmp_dir}/master-password" \
  --from-file=webhook-token="${tmp_dir}/webhook-token" \
  --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f - >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" label secret "${credentials_secret}" \
  external-secrets.io/type=webhook --overwrite >/dev/null

helm_args=(
  upgrade --install "${release}" "${chart_ref}"
  --namespace "${namespace}"
  --set-string "image.repository=${image_repository}"
  --set-string "image.tag=${image_tag}"
  --set-string "credentials.existingSecret.name=${credentials_secret}"
  --set-string "config.cacheTtlSeconds=2"
  --set-string "selectorPolicy.allowedKeys[0]=${item_key}"
  --set-string "selectorPolicy.allowedKeys[1]=${missing_item}"
)
if [[ -n "${chart_version}" ]]; then
  helm_args+=(--version "${chart_version}")
fi
if [[ -n "${single_origin_url}" ]]; then
  helm_args+=(--set-string "config.singleOriginUrl=${single_origin_url}")
else
  helm_args+=(--set-string "config.identityUrl=${identity_url}")
  helm_args+=(--set-string "config.apiUrl=${api_url}")
fi
if [[ -n "${network_policy_enabled}" ]]; then
  helm_args+=(--set "networkPolicy.enabled=${network_policy_enabled}")
fi
if [[ -n "${host_alias_ip}" ]]; then
  log "using host alias ${host_alias_hostname} -> ${host_alias_ip}"
  helm_args+=(
    --set-string "hostAliases[0].ip=${host_alias_ip}"
    --set-string "hostAliases[0].hostnames[0]=${host_alias_hostname}"
  )
fi
if [[ -n "${pull_secret}" ]]; then
  helm_args+=(--set-string "imagePullSecrets[0].name=${pull_secret}")
fi

log "installing webhook chart ${chart_ref} with image ${image_repository}:${image_tag}"
"${helm_cmd[@]}" "${helm_args[@]}" >/dev/null

selector="app.kubernetes.io/instance=${release},app.kubernetes.io/name=vaultwarden-eso-provider"
log "waiting for webhook rollout"
"${kubectl_cmd[@]}" -n "${namespace}" rollout status deployment -l "${selector}" --timeout=180s >/dev/null

service_name="$("${kubectl_cmd[@]}" -n "${namespace}" get svc -l "${selector}" -o jsonpath='{.items[0].metadata.name}')"
[[ -n "${service_name}" ]] || fail "could not find webhook Service"

start_port_forward() {
  stop_port_forward
  local_port=$((18080 + RANDOM % 1000))
  port_forward_log="${tmp_dir}/port-forward-${local_port}.log"
  "${kubectl_cmd[@]}" -n "${namespace}" port-forward --address 127.0.0.1 "svc/${service_name}" \
    "${local_port}:8080" >"${port_forward_log}" 2>&1 &
  port_forward_pid="$!"
}

wait_for_probe() {
  local path="$1"
  local expected="$2"
  local deadline=$((SECONDS + 60))
  local status
  while (( SECONDS < deadline )); do
    status="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${local_port}${path}" || true)"
    if [[ "${status}" == "${expected}" ]]; then
      return 0
    fi
    if ! kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
      fail "port-forward to webhook Service exited before ${path} became reachable"
    fi
    sleep 1
  done
  fail "webhook probe ${path} did not return HTTP ${expected}"
}

fetch_metrics() {
  local output_file="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if curl -fsS "http://127.0.0.1:${local_port}/metrics" >"${output_file}"; then
      return 0
    fi
    if ! kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
      start_port_forward
    fi
    sleep 1
  done
  fail "metrics endpoint did not return a successful response"
}

record_direct_metric_observations() {
  local success_body="${tmp_dir}/resolve-success-request.json"
  local success_response="${tmp_dir}/resolve-success-response.json"
  local error_body="${tmp_dir}/resolve-error-request.json"
  local denied_body="${tmp_dir}/resolve-denied-request.json"
  local status

  jq -n --arg key "${item_key}" --arg property "${property}" \
    '{remoteRef: {key: $key, property: $property}}' >"${success_body}"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${webhook_token}" \
    -o "${success_response}" \
    -d @"${success_body}" \
    "http://127.0.0.1:${local_port}/v1/resolve" >/dev/null

  jq -n --arg key "${item_key}" --arg property "${missing_property}" \
    '{remoteRef: {key: $key, property: $property}}' >"${error_body}"
  status="$(curl -sS \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${webhook_token}" \
    -o /dev/null \
    -w '%{http_code}' \
    -d @"${error_body}" \
    "http://127.0.0.1:${local_port}/v1/resolve" || true)"
  [[ "${status}" == "404" ]] || fail "direct missing-property resolve returned HTTP ${status}, expected 404"

  jq -n --arg key "${denied_item}" --arg property "${property}" \
    '{remoteRef: {key: $key, property: $property}}' >"${denied_body}"
  status="$(curl -sS \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${webhook_token}" \
    -o /dev/null \
    -w '%{http_code}' \
    -d @"${denied_body}" \
    "http://127.0.0.1:${local_port}/v1/resolve" || true)"
  [[ "${status}" == "403" ]] || fail "direct policy-denied resolve returned HTTP ${status}, expected 403"
}

start_port_forward
log "checking webhook probes"
wait_for_probe /livez 204
wait_for_probe /readyz 204

cat >"${tmp_dir}/eso.yaml" <<EOF
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: bitwarden-live
  namespace: ${namespace}
spec:
  provider:
    webhook:
      url: "http://${service_name}.${namespace}.svc.cluster.local:8080/v1/resolve"
      method: POST
      headers:
        Content-Type: application/json
        Authorization: 'Bearer {{ index .auth "webhook-token" }}'
      secrets:
        - name: auth
          secretRef:
            name: ${credentials_secret}
            key: webhook-token
      body: |
        {
          "remoteRef": {
            "key": {{ .remoteRef.key | toJson }},
            "property": {{ .remoteRef.property | toJson }}
          }
        }
      result:
        jsonPath: "$.data.value"
      timeout: 10s
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: bitwarden-live-map
  namespace: ${namespace}
spec:
  provider:
    webhook:
      url: "http://${service_name}.${namespace}.svc.cluster.local:8080/v1/resolve"
      method: POST
      headers:
        Content-Type: application/json
        Authorization: 'Bearer {{ index .auth "webhook-token" }}'
      secrets:
        - name: auth
          secretRef:
            name: ${credentials_secret}
            key: webhook-token
      body: |
        {
          "remoteRef": {
            "key": {{ .remoteRef.key | toJson }}
          }
        }
      result:
        jsonPath: "$.data"
      timeout: 10s
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bweso-smoke
  namespace: ${namespace}
spec:
  refreshPolicy: Periodic
  refreshInterval: 10s
  secretStoreRef:
    name: bitwarden-live
    kind: SecretStore
  target:
    name: ${target_secret}
    creationPolicy: Orphan
    deletionPolicy: Retain
    template:
      mergePolicy: Merge
  data:
    - secretKey: resolved
      remoteRef:
        key: "${item_key}"
        property: "${property}"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bweso-whole-item
  namespace: ${namespace}
spec:
  refreshPolicy: Periodic
  refreshInterval: 10s
  secretStoreRef:
    name: bitwarden-live-map
    kind: SecretStore
  target:
    name: ${whole_target_secret}
    creationPolicy: Orphan
    deletionPolicy: Retain
    template:
      mergePolicy: Merge
  dataFrom:
    - extract:
        key: "${item_key}"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bweso-missing-property
  namespace: ${namespace}
spec:
  refreshPolicy: Periodic
  refreshInterval: 10s
  secretStoreRef:
    name: bitwarden-live
    kind: SecretStore
  target:
    name: bweso-missing-property-secret
    creationPolicy: Orphan
    deletionPolicy: Retain
    template:
      mergePolicy: Merge
  data:
    - secretKey: resolved
      remoteRef:
        key: "${item_key}"
        property: "${missing_property}"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bweso-missing-item
  namespace: ${namespace}
spec:
  refreshPolicy: Periodic
  refreshInterval: 10s
  secretStoreRef:
    name: bitwarden-live
    kind: SecretStore
  target:
    name: bweso-missing-item-secret
    creationPolicy: Orphan
    deletionPolicy: Retain
    template:
      mergePolicy: Merge
  data:
    - secretKey: resolved
      remoteRef:
        key: "${missing_item}"
        property: "${property}"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bweso-policy-denied
  namespace: ${namespace}
spec:
  refreshPolicy: Periodic
  refreshInterval: 10s
  secretStoreRef:
    name: bitwarden-live
    kind: SecretStore
  target:
    name: bweso-policy-denied-secret
    creationPolicy: Orphan
    deletionPolicy: Retain
    template:
      mergePolicy: Merge
  data:
    - secretKey: resolved
      remoteRef:
        key: "${denied_item}"
        property: "${property}"
EOF

log "applying ESO smoke resources"
"${kubectl_cmd[@]}" apply -f "${tmp_dir}/eso.yaml" >/dev/null

log "waiting for successful sync"
"${kubectl_cmd[@]}" -n "${namespace}" wait externalsecret/bweso-smoke \
  --for=condition=Ready --timeout=180s >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" wait externalsecret/bweso-whole-item \
  --for=condition=Ready --timeout=180s >/dev/null

wait_secret_nonempty() {
  local name="$1"
  local key="$2"
  local deadline=$((SECONDS + 120))
  local encoded_value_len
  while (( SECONDS < deadline )); do
    encoded_value_len="$("${kubectl_cmd[@]}" -n "${namespace}" get secret "${name}" \
      -o "jsonpath={.data.${key}}" 2>/dev/null | wc -c | tr -d ' ')"
    if [[ "${encoded_value_len}" -gt 0 ]]; then
      return 0
    fi
    sleep 2
  done
  fail "Secret ${name} did not contain non-empty key ${key}"
}

wait_secret_has_data() {
  local name="$1"
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if "${kubectl_cmd[@]}" -n "${namespace}" get secret "${name}" -o json 2>/dev/null \
      | jq -e '.data | length > 0' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  fail "Secret ${name} did not contain any data keys"
}

wait_secret_nonempty "${target_secret}" resolved
wait_secret_has_data "${whole_target_secret}"
original_resolved="$("${kubectl_cmd[@]}" -n "${namespace}" get secret "${target_secret}" \
  -o jsonpath='{.data.resolved}')"
[[ -n "${original_resolved}" ]] || fail "Secret ${target_secret} had an empty resolved value before recreation"

log "checking Secret recreation"
"${kubectl_cmd[@]}" -n "${namespace}" delete secret "${target_secret}" >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" annotate externalsecret/bweso-smoke \
  "force-sync=$(force_sync_value)" --overwrite >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" wait externalsecret/bweso-smoke \
  --for=condition=Ready --timeout=180s >/dev/null
wait_secret_nonempty "${target_secret}" resolved
recreated_resolved="$("${kubectl_cmd[@]}" -n "${namespace}" get secret "${target_secret}" \
  -o jsonpath='{.data.resolved}')"
[[ "${recreated_resolved}" == "${original_resolved}" ]] || fail "recreated Secret data differed from the initial sync"

log "checking webhook restart plus resync"
"${kubectl_cmd[@]}" -n "${namespace}" rollout restart deployment -l "${selector}" >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" rollout status deployment -l "${selector}" --timeout=180s >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" annotate externalsecret/bweso-smoke \
  "force-sync=$(force_sync_value)" --overwrite >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" wait externalsecret/bweso-smoke \
  --for=condition=Ready --timeout=180s >/dev/null
wait_secret_nonempty "${target_secret}" resolved

wait_negative_absent() {
  local name="$1"
  local deadline=$((SECONDS + 120))
  local status
  while (( SECONDS < deadline )); do
    status="$("${kubectl_cmd[@]}" -n "${namespace}" get externalsecret "${name}" -o json \
      | jq -r '.status.conditions[]? | select(.type == "Ready") | "\(.status) \(.reason)"' \
      | tail -n 1)"
    if [[ "${status}" == "False SecretSyncedError" || "${status}" == "True SecretDeleted" ]]; then
      return 0
    fi
    sleep 2
  done
  fail "${name} did not reach a negative no-target state"
}

log "checking expected negative cases"
wait_negative_absent bweso-missing-property
wait_negative_absent bweso-missing-item
wait_negative_absent bweso-policy-denied
if "${kubectl_cmd[@]}" -n "${namespace}" get secret bweso-missing-property-secret >/dev/null 2>&1; then
  fail "missing-property ExternalSecret unexpectedly created a target Secret"
fi
if "${kubectl_cmd[@]}" -n "${namespace}" get secret bweso-missing-item-secret >/dev/null 2>&1; then
  fail "missing-item ExternalSecret unexpectedly created a target Secret"
fi
if "${kubectl_cmd[@]}" -n "${namespace}" get secret bweso-policy-denied-secret >/dev/null 2>&1; then
  fail "policy-denied ExternalSecret unexpectedly created a target Secret"
fi

log "checking redacted metrics endpoint"
start_port_forward
wait_for_probe /livez 204
wait_for_probe /readyz 204
record_direct_metric_observations
metrics_file="${tmp_dir}/metrics.txt"
fetch_metrics "${metrics_file}"
grep -Fq 'bweso_ready 1' "${metrics_file}" || fail "metrics did not report ready state"
grep -Fq 'bweso_http_requests_total' "${metrics_file}" || fail "metrics did not include HTTP counters"
grep -Fq 'bweso_resolve_requests_total' "${metrics_file}" || fail "metrics did not include resolution counters"
grep -Fq 'outcome="success"' "${metrics_file}" || fail "metrics did not include successful resolution outcomes"
grep -Fq 'outcome="error"' "${metrics_file}" || fail "metrics did not include expected error outcomes"
grep -Fq 'error_kind="policy_denied"' "${metrics_file}" || fail "metrics did not include policy-denied outcomes"
grep -Fq 'bweso_cache_refreshes_total' "${metrics_file}" || fail "metrics did not include cache refresh counters"
if [[ "${#item_key}" -ge 8 ]] && grep -Fq "${item_key}" "${metrics_file}"; then
  fail "metrics leaked selected vault item key"
fi
if grep -Fq "${missing_property}" "${metrics_file}"; then
  fail "metrics leaked missing-property selector"
fi
if grep -Fq "${missing_item}" "${metrics_file}"; then
  fail "metrics leaked missing-item selector"
fi
if grep -Fq "${denied_item}" "${metrics_file}"; then
  fail "metrics leaked policy-denied selector"
fi

log "live ESO smoke test passed"
