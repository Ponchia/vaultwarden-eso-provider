#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(mktemp)"
trap 'rm -f "${output}"' EXIT
if env -i PATH="${PATH}" bash "${root}/scripts/live-eso-smoke.sh" >"${output}" 2>&1; then
  echo "live smoke must require explicit opt-in" >&2
  exit 1
fi
grep -q 'set BWESO_TEST_LIVE=true' "${output}"
if env -i PATH="${PATH}" BWESO_TEST_LIVE=true bash "${root}/scripts/live-eso-smoke.sh" >"${output}" 2>&1; then
  echo "live smoke must require an explicit context" >&2
  exit 1
fi
grep -q 'set BWESO_E2E_KUBE_CONTEXT explicitly' "${output}"
echo "Live smoke requires explicit account opt-in and cluster context."
