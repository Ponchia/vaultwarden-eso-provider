#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" || "${tag}" != v* ]]; then
  echo "usage: $0 v<version>" >&2
  exit 2
fi

version="${tag#v}"
chart_file="deploy/helm/vaultwarden-eso-provider/Chart.yaml"

chart_version="$(
  awk -F': *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' "${chart_file}"
)"
app_version="$(
  awk -F': *' '$1 == "appVersion" { gsub(/"/, "", $2); print $2; exit }' "${chart_file}"
)"

package_version() {
  local manifest="$1"
  awk -F'= *' '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && $1 ~ /^version[[:space:]]*$/ {
      gsub(/[ "]/, "", $2)
      print $2
      exit
    }
  ' "${manifest}"
}

if [[ "${chart_version}" != "${version}" ]]; then
  echo "Chart.yaml version ${chart_version} does not match tag ${tag}" >&2
  exit 1
fi

if [[ "${app_version}" != "${version}" ]]; then
  echo "Chart.yaml appVersion ${app_version} does not match tag ${tag}" >&2
  exit 1
fi

if ! grep -Eq "^## v?${version}([[:space:]-]|$)" CHANGELOG.md; then
  echo "CHANGELOG.md does not contain an entry for ${tag}" >&2
  exit 1
fi

for manifest in \
  crates/bweso-core/Cargo.toml \
  crates/bweso-bitwarden/Cargo.toml \
  crates/vaultwarden-eso-provider/Cargo.toml; do
  actual="$(package_version "${manifest}")"
  if [[ "${actual}" != "${version}" ]]; then
    echo "${manifest}: package.version ${actual} != ${version}" >&2
    exit 1
  fi
done

echo "release version gate passed for ${tag}"
