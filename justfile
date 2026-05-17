set dotenv-load := false
set shell := ["bash", "-euo", "pipefail", "-c"]

chart := "deploy/helm/vaultwarden-eso-provider"
lint_values := "deploy/helm/lint-values.yaml"
namespace := "bweso-system"
checkov_image := "bridgecrew/checkov:3.2.526@sha256:93a910a5854dce9b9935c18e96574162dec7ef2f07b819fd6af19f2e16ea306c"

# List available recipes.
default:
  @just --list

# Run the standard handoff checks from AGENTS.md.
check: fmt clippy test

# Run the broader local CI/release-readiness mirror.
ci: check coverage helm docs workflows security docker-check

# Check Rust formatting.
fmt:
  cargo fmt --all -- --check

# Run clippy with repository warning policy.
clippy:
  cargo clippy --locked --workspace --all-targets -- -D warnings

# Run all workspace tests.
test:
  cargo test --locked --workspace --all-targets

# Run the coverage gate used by CI.
coverage:
  cargo llvm-cov --locked --workspace --all-targets --fail-under-lines 80 --summary-only

# Validate Helm chart rendering and policy contracts.
helm:
  helm lint {{chart}} -f {{lint_values}}
  helm template bweso {{chart}} -f {{lint_values}} --namespace {{namespace}} >/dev/null
  bash scripts/helm-policy-contracts.sh

# Validate Markdown and static YAML/JSON examples.
docs:
  markdownlint-cli2 '**/*.md'
  jq -e . examples/grafana/*.json >/dev/null
  ruby -e 'require "yaml"; ARGV.each { |path| YAML.safe_load(File.read(path), aliases: true) }' examples/prometheus/*.yaml deploy/eso/*.yaml

# Validate GitHub Actions and issue-template YAML.
workflows:
  actionlint .github/workflows/*.yml
  ruby -e 'require "yaml"; ARGV.each { |path| YAML.safe_load(File.read(path), aliases: true) }' .github/workflows/*.yml .github/ISSUE_TEMPLATE/*.yml .github/dependabot.yml

# Run local security scanners that do not need secrets.
security:
  gitleaks detect --source . --redact --exit-code 1
  trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed .
  cargo deny --locked check advisories licenses bans sources
  just checkov

# Run Checkov through the same digest-pinned image used by CI.
checkov:
  docker run --rm -v "$PWD:/repo" --workdir /repo {{checkov_image}} -d {{chart}} --framework helm --var-file {{lint_values}} --skip-check CKV_K8S_21 --quiet

# Validate the Dockerfile and build context without publishing an image.
docker-check:
  docker buildx build --check .

# Build the local image.
docker-build tag="vaultwarden-eso-provider:local":
  docker buildx build --load -t "{{tag}}" .

# Verify release metadata matches a version, e.g. `just release-check 0.3.0`.
release-check version:
  bash scripts/verify-release-version.sh "v{{version}}"

# Run the release workflow verify job locally as closely as practical.
release-verify version:
  just release-check "{{version}}"
  just ci

# Run dependency-maintenance commands after dependency changes.
deps:
  cargo generate-lockfile
  cargo tree

# Check shell scripts without promoting shell style to a release gate.
shellcheck:
  shellcheck scripts/*.sh

# Show shell formatting drift using the repository's current two-space style.
shfmt-check:
  shfmt -d -i 2 scripts/*.sh

# Spell-check prose while excluding encoded cryptographic fixtures.
typos:
  typos --hidden --exclude target --exclude .git --exclude Cargo.lock \
    --exclude crates/bweso-bitwarden/fuzz/corpus \
    --exclude crates/bweso-bitwarden/src/crypto.rs \
    --exclude crates/bweso-bitwarden/src/api.rs \
    --exclude crates/bweso-bitwarden/src/cipher.rs \
    --exclude crates/vaultwarden-eso-provider/src/main.rs .

# Run unused-dependency detection.
machete:
  cargo machete

# Run mutation testing. This is intentionally separate from `ci`.
mutants:
  cargo mutants --locked

# Run the live ESO smoke test with caller-provided BWESO_E2E_* env.
live-smoke:
  bash scripts/live-eso-smoke.sh
