#!/usr/bin/env bash
# CI-only validation against the immutable upstream SPDX 2.3 JSON schema.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP must name the current CI job temporary directory}"
if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo 'usage: validate-spdx.sh <sbom.spdx.json>' >&2
  exit 2
fi
schema="${RUNNER_TEMP}/bweso-spdx-2.3.schema.json"
validator="${RUNNER_TEMP}/bweso-spdx-validator"
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/spdx/spdx-spec/aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json \
  -o "$schema"
printf '%s  %s\n' 239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b "$schema" | sha256sum --check
python3 -m venv "$validator"
"${validator}/bin/pip" install --disable-pip-version-check jsonschema==4.25.1
"${validator}/bin/python" - "$schema" "$1" <<'PY'
import json
from pathlib import Path
import sys
from jsonschema import Draft7Validator
schema = json.loads(Path(sys.argv[1]).read_text())
report = json.loads(Path(sys.argv[2]).read_text())
errors = list(Draft7Validator(schema).iter_errors(report))
if errors:
    print(f'SPDX schema validation failed: {len(errors)} structural errors.', file=sys.stderr)
    raise SystemExit(1)
print('Official SPDX 2.3 schema validation passed.')
PY
