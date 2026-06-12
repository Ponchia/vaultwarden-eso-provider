#!/usr/bin/env bash
set -euo pipefail

checker="${1:-scripts/eso-policy-coverage.rb}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

cat >"${tmpdir}/covered.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: bweso-selector-policy
  namespace: bweso-system
data:
  allowed-keys: |
    id:11111111-1111-4111-8111-111111111111
  allowed-key-prefixes: |
    name:team-a/
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
  namespace: bweso-system
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS_FILE
              value: /etc/bweso/policy/allowed-keys
            - name: BWESO_ALLOWED_KEY_PREFIXES_FILE
              value: /etc/bweso/policy/allowed-key-prefixes
          volumeMounts:
            - name: selector-policy
              mountPath: /etc/bweso/policy
      volumes:
        - name: selector-policy
          configMap:
            name: bweso-selector-policy
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: exact
  namespace: app
spec:
  secretStoreRef:
    name: bitwarden-vault
    kind: SecretStore
  target:
    name: exact-target
  data:
    - secretKey: password
      remoteRef:
        key: id:11111111-1111-4111-8111-111111111111
        property: field.password
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: prefix
  namespace: app
spec:
  secretStoreRef:
    name: bitwarden-vault
    kind: SecretStore
  dataFrom:
    - extract:
        key: name:team-a/database
YAML

cat >"${tmpdir}/uncovered.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: bweso-selector-policy
data:
  allowed-keys: |
    id:11111111-1111-4111-8111-111111111111
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS
              valueFrom:
                configMapKeyRef:
                  name: bweso-selector-policy
                  key: allowed-keys
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: missing-policy
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:22222222-2222-4222-8222-222222222222
        property: field.password
YAML

cat >"${tmpdir}/ambiguous-providers.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso-a
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS
              value: id:11111111-1111-4111-8111-111111111111
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso-b
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS
              value: id:33333333-3333-4333-8333-333333333333
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: exact
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:11111111-1111-4111-8111-111111111111
        property: field.password
YAML

cat >"${tmpdir}/custom-policy-key-names.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-policy
data:
  prefix-looking-items: |
    id:44444444-4444-4444-8444-444444444444
  teams: |
    name:platform/
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS_FILE
              value: /etc/bweso/policy/prefix-looking-items
            - name: BWESO_ALLOWED_KEY_PREFIXES_FILE
              value: /etc/bweso/policy/teams
          volumeMounts:
            - name: selector-policy
              mountPath: /etc/bweso/policy
      volumes:
        - name: selector-policy
          configMap:
            name: custom-policy
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: custom-prefix
spec:
  dataFrom:
    - extract:
        key: name:platform/database
YAML

cat >"${tmpdir}/subpath-policy.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: subpath-policy
data:
  exact-items: |
    id:55555555-5555-4555-8555-555555555555
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS_FILE
              value: /etc/bweso/allowed-keys
          volumeMounts:
            - name: selector-policy
              mountPath: /etc/bweso/allowed-keys
              subPath: exact-items
      volumes:
        - name: selector-policy
          configMap:
            name: subpath-policy
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: subpath
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:55555555-5555-4555-8555-555555555555
        property: field.password
YAML

cat >"${tmpdir}/mapped-items-policy.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: mapped-policy
data:
  source-key: |
    id:66666666-6666-4666-8666-666666666666
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS_FILE
              value: /etc/bweso/policy/mapped-key
          volumeMounts:
            - name: selector-policy
              mountPath: /etc/bweso/policy
      volumes:
        - name: selector-policy
          configMap:
            name: mapped-policy
            items:
              - key: source-key
                path: mapped-key
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: mapped
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:66666666-6666-4666-8666-666666666666
        property: field.password
YAML

cat >"${tmpdir}/allow-all.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOW_ALL_SELECTORS
              value: "true"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: allow-all
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:77777777-7777-4777-8777-777777777777
        property: field.password
YAML

cat >"${tmpdir}/mixed-stores.yaml" <<'YAML'
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: bitwarden-vault
  namespace: app
spec:
  provider:
    webhook:
      url: http://bweso.bweso-system.svc/v1/resolve
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: other-provider
  namespace: app
spec:
  provider:
    fake: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS
              value: id:88888888-8888-4888-8888-888888888888
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: bitwarden-secret
  namespace: app
spec:
  secretStoreRef:
    name: bitwarden-vault
    kind: SecretStore
  data:
    - secretKey: password
      remoteRef:
        key: id:88888888-8888-4888-8888-888888888888
        property: field.password
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ignored-other-provider
  namespace: app
spec:
  secretStoreRef:
    name: other-provider
    kind: SecretStore
  data:
    - secretKey: password
      remoteRef:
        key: id:99999999-9999-4999-8999-999999999999
        property: field.password
YAML

cat >"${tmpdir}/sidecar-only-mount.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: sidecar-policy
data:
  allowed-keys: |
    id:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS_FILE
              value: /etc/bweso/policy/allowed-keys
        - name: sidecar
          image: busybox:latest
          volumeMounts:
            - name: selector-policy
              mountPath: /etc/bweso/policy
      volumes:
        - name: selector-policy
          configMap:
            name: sidecar-policy
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: sidecar
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
        property: field.password
YAML

cat >"${tmpdir}/kubectl-list.yaml" <<'YAML'
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: list-policy
      namespace: bweso-system
    data:
      allowed-keys: |
        id:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: bweso
      namespace: bweso-system
    spec:
      template:
        spec:
          containers:
            - name: provider
              image: ghcr.io/ponchia/vaultwarden-eso-provider:test
              env:
                - name: BWESO_ALLOWED_KEYS_FILE
                  value: /etc/bweso/policy/allowed-keys
              volumeMounts:
                - name: selector-policy
                  mountPath: /etc/bweso/policy
          volumes:
            - name: selector-policy
              configMap:
                name: list-policy
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: unrelated-app
      namespace: app
    spec:
      template:
        spec:
          containers:
            - name: app
              image: busybox:latest
              env:
                - name: LISTEN_ADDRESS
                  value: :8000
  - apiVersion: external-secrets.io/v1
    kind: ExternalSecret
    metadata:
      name: list-secret
      namespace: app
    spec:
      data:
        - secretKey: password
          remoteRef:
            key: id:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
            property: field.password
YAML

cat >"${tmpdir}/no-provider.yaml" <<'YAML'
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: no-provider
spec:
  data:
    - secretKey: password
      remoteRef:
        key: id:cccccccc-cccc-4ccc-8ccc-cccccccccccc
        property: field.password
YAML

cat >"${tmpdir}/empty-policy-only.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bweso
spec:
  template:
    spec:
      containers:
        - name: provider
          image: ghcr.io/ponchia/vaultwarden-eso-provider:test
          env:
            - name: BWESO_ALLOWED_KEYS
              value: id:dddddddd-dddd-4ddd-8ddd-dddddddddddd
YAML

"${checker}" "${tmpdir}/covered.yaml" >/dev/null
"${checker}" - <"${tmpdir}/covered.yaml" >/dev/null
"${checker}" "${tmpdir}/custom-policy-key-names.yaml" >/dev/null
"${checker}" "${tmpdir}/subpath-policy.yaml" >/dev/null
"${checker}" "${tmpdir}/mapped-items-policy.yaml" >/dev/null
"${checker}" "${tmpdir}/allow-all.yaml" >/dev/null
"${checker}" "${tmpdir}/mixed-stores.yaml" >/dev/null
"${checker}" "${tmpdir}/kubectl-list.yaml" >/dev/null
"${checker}" - <"${tmpdir}/kubectl-list.yaml" >/dev/null
uncovered_output="${tmpdir}/uncovered.out"
if "${checker}" "${tmpdir}/uncovered.yaml" >"${uncovered_output}" 2>&1; then
  echo "expected uncovered selector policy check to fail" >&2
  exit 1
fi
if grep -Fq 'id:22222222-2222-4222-8222-222222222222' "${uncovered_output}"; then
  echo "expected uncovered selector output to redact raw selector keys" >&2
  exit 1
fi
if "${checker}" "${tmpdir}/ambiguous-providers.yaml" >/dev/null 2>&1; then
  echo "expected multiple provider deployments to require --provider" >&2
  exit 1
fi
"${checker}" --provider default/bweso-a "${tmpdir}/ambiguous-providers.yaml" >/dev/null
if "${checker}" "${tmpdir}/sidecar-only-mount.yaml" >/dev/null 2>&1; then
  echo "expected sidecar-only policy mount to fail coverage" >&2
  exit 1
fi
if "${checker}" "${tmpdir}/no-provider.yaml" >/dev/null 2>&1; then
  echo "expected missing provider deployment to fail coverage" >&2
  exit 1
fi
if "${checker}" "${tmpdir}/empty-policy-only.yaml" >/dev/null 2>&1; then
  echo "expected policy-only render to require --allow-empty" >&2
  exit 1
fi
"${checker}" --allow-empty "${tmpdir}/empty-policy-only.yaml" >/dev/null
if "${checker}" "${tmpdir}/does-not-exist.yaml" >/dev/null 2>&1; then
  echo "expected missing input path to fail" >&2
  exit 1
fi
