use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context};
use http::{header, HeaderMap};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::PolicyRules;

/// Kubernetes Secrets are limited to roughly 1 MiB. Keep the generic file
/// input bounded too, so authorization cannot turn into an unbounded parse or
/// per-request comparison workload when the file comes from another source.
pub(super) const MAX_AUTH_POLICY_FILE_BYTES: u64 = 1024 * 1024;
const MAX_AUTH_CAPABILITIES: usize = 1024;
const MAX_AUTH_TOKENS: usize = 4096;
const MIN_SCOPED_TOKEN_BYTES: usize = 32;
const MAX_SCOPED_TOKEN_BYTES: usize = 4096;
const AUTH_POLICY_VERSION: u32 = 1;

#[derive(Clone)]
pub(super) enum WebhookAuth {
    Legacy(TokenDigest),
    Scoped(ScopedAuthPolicy),
    DisabledInsecure,
}

impl WebhookAuth {
    pub(super) fn from_config(
        token: Option<&str>,
        token_file: Option<&Path>,
        scoped_policy_file: Option<&Path>,
        insecure_allow_unauthenticated: bool,
    ) -> anyhow::Result<Self> {
        let token = read_optional_secret(token, token_file, "webhook_auth_token")?;
        let configured_modes = usize::from(token.is_some())
            + usize::from(scoped_policy_file.is_some())
            + usize::from(insecure_allow_unauthenticated);

        if configured_modes > 1 {
            bail!(
                "configure exactly one of BWESO_WEBHOOK_AUTH_TOKEN, \
                 BWESO_AUTH_POLICY_FILE, or \
                 BWESO_INSECURE_ALLOW_UNAUTHENTICATED=true"
            );
        }

        if let Some(token) = token {
            return Ok(Self::Legacy(TokenDigest::new(&token)));
        }
        if let Some(path) = scoped_policy_file {
            return Ok(Self::Scoped(ScopedAuthPolicy::from_file(path)?));
        }
        if insecure_allow_unauthenticated {
            tracing::warn!(
                "webhook authentication is disabled; use only for local or isolated tests"
            );
            return Ok(Self::DisabledInsecure);
        }

        bail!(
            "configure BWESO_WEBHOOK_AUTH_TOKEN or BWESO_AUTH_POLICY_FILE, or explicitly set \
             BWESO_INSECURE_ALLOW_UNAUTHENTICATED=true for local tests"
        )
    }

    /// Authenticate one request and return its selector scope. The legacy and
    /// explicitly-insecure modes are still bounded by the provider's global
    /// selector policy. Scoped mode adds a second, capability-specific bound.
    pub(super) fn authorize(&self, headers: &HeaderMap) -> Option<AuthorizedScope> {
        match self {
            Self::DisabledInsecure => Some(AuthorizedScope::Global),
            Self::Legacy(expected) => {
                let supplied = bearer_token(headers)?;
                expected
                    .matches(supplied)
                    .then_some(AuthorizedScope::Global)
            }
            Self::Scoped(policy) => {
                let supplied = bearer_token(headers)?;
                policy.authorize(supplied)
            }
        }
    }

    pub(super) fn scoped_policy(&self) -> Option<ScopedAuthPolicy> {
        match self {
            Self::Scoped(policy) => Some(policy.clone()),
            Self::Legacy(_) | Self::DisabledInsecure => None,
        }
    }
}

#[derive(Clone)]
pub(super) enum AuthorizedScope {
    Global,
    Scoped(Arc<PolicyRules>),
}

impl AuthorizedScope {
    pub(super) fn allows(&self, key: &str) -> bool {
        match self {
            Self::Global => true,
            Self::Scoped(rules) => rules.allows(key),
        }
    }
}

#[derive(Clone)]
pub(super) struct ScopedAuthPolicy {
    rules: Arc<std::sync::RwLock<Arc<ScopedAuthRules>>>,
    path: Arc<PathBuf>,
}

impl ScopedAuthPolicy {
    fn from_file(path: &Path) -> anyhow::Result<Self> {
        let rules = ScopedAuthRules::read(path)?;
        Ok(Self {
            rules: Arc::new(std::sync::RwLock::new(Arc::new(rules))),
            path: Arc::new(path.to_path_buf()),
        })
    }

    fn authorize(&self, supplied: &str) -> Option<AuthorizedScope> {
        if !(MIN_SCOPED_TOKEN_BYTES..=MAX_SCOPED_TOKEN_BYTES).contains(&supplied.len()) {
            return None;
        }
        self.snapshot().authorize(supplied)
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        self.snapshot().counts()
    }

    pub(super) fn reload(&self) -> anyhow::Result<bool> {
        let next = ScopedAuthRules::read(&self.path)?;
        let current = self.snapshot();
        if *current == next {
            return Ok(false);
        }

        let mut guard = self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Arc::new(next);
        Ok(true)
    }

    fn snapshot(&self) -> Arc<ScopedAuthRules> {
        let guard = self
            .rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ScopedAuthRules {
    capabilities: Vec<ScopedCapability>,
}

impl ScopedAuthRules {
    fn read(path: &Path) -> anyhow::Result<Self> {
        let contents = read_bounded_secret_file(path)?;
        let raw: RawAuthPolicy = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse auth policy file {}", path.display()))?;
        Self::try_from(raw).with_context(|| format!("invalid auth policy file {}", path.display()))
    }

    fn authorize(&self, supplied: &str) -> Option<AuthorizedScope> {
        let supplied = TokenDigest::new(supplied);
        let mut matched_capability = None;

        // Always compare against every configured token. Avoid returning as
        // soon as one token matches, which would expose its position through a
        // coarse timing side channel.
        for (capability_index, capability) in self.capabilities.iter().enumerate() {
            for expected in &capability.tokens {
                if expected.ct_matches(&supplied) {
                    matched_capability = Some(capability_index);
                }
            }
        }

        matched_capability.map(|index| {
            AuthorizedScope::Scoped(Arc::clone(&self.capabilities[index].selector_rules))
        })
    }

    fn counts(&self) -> (usize, usize) {
        let tokens = self
            .capabilities
            .iter()
            .map(|capability| capability.tokens.len())
            .sum();
        (self.capabilities.len(), tokens)
    }
}

impl TryFrom<RawAuthPolicy> for ScopedAuthRules {
    type Error = anyhow::Error;

    fn try_from(raw: RawAuthPolicy) -> Result<Self, Self::Error> {
        if raw.version != AUTH_POLICY_VERSION {
            bail!(
                "unsupported auth policy version {}; expected {AUTH_POLICY_VERSION}",
                raw.version
            );
        }
        if raw.capabilities.is_empty() {
            bail!("auth policy must define at least one capability");
        }
        if raw.capabilities.len() > MAX_AUTH_CAPABILITIES {
            bail!("auth policy defines more than the {MAX_AUTH_CAPABILITIES} capability limit");
        }

        let mut names = HashSet::with_capacity(raw.capabilities.len());
        let mut token_digests = HashSet::new();
        let mut capabilities = Vec::with_capacity(raw.capabilities.len());
        let mut total_tokens = 0usize;

        for (index, capability) in raw.capabilities.iter().enumerate() {
            if capability.name.trim().is_empty() {
                bail!("capabilities[{index}].name must not be empty");
            }
            if capability.name.trim() != capability.name {
                bail!("capabilities[{index}].name must not have surrounding whitespace");
            }
            if !names.insert(capability.name.as_str()) {
                bail!("auth policy capability names must be unique");
            }
            if capability.tokens.is_empty() {
                bail!("capabilities[{index}].tokens must not be empty");
            }

            total_tokens = total_tokens.saturating_add(capability.tokens.len());
            if total_tokens > MAX_AUTH_TOKENS {
                bail!("auth policy defines more than the {MAX_AUTH_TOKENS} token limit");
            }

            let mut tokens = Vec::with_capacity(capability.tokens.len());
            for token in &capability.tokens {
                validate_scoped_token(&token.0, index)?;
                let digest = TokenDigest::new(&token.0);
                if !token_digests.insert(digest) {
                    bail!("auth policy tokens must be unique across capabilities");
                }
                tokens.push(digest);
            }

            let allowed_keys = normalize_entries(&capability.allowed_keys, index, "allowedKeys")?;
            let allowed_key_prefixes = normalize_entries(
                &capability.allowed_key_prefixes,
                index,
                "allowedKeyPrefixes",
            )?;
            if allowed_keys.is_empty() && allowed_key_prefixes.is_empty() {
                bail!("capabilities[{index}] must define allowedKeys or allowedKeyPrefixes");
            }

            capabilities.push(ScopedCapability {
                tokens,
                selector_rules: Arc::new(PolicyRules::AllowList {
                    allowed_keys,
                    allowed_key_prefixes,
                }),
            });
        }

        Ok(Self { capabilities })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ScopedCapability {
    tokens: Vec<TokenDigest>,
    selector_rules: Arc<PolicyRules>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) struct TokenDigest([u8; 32]);

impl TokenDigest {
    fn new(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    fn matches(&self, token: &str) -> bool {
        self.ct_matches(&Self::new(token))
    }

    fn ct_matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAuthPolicy {
    version: u32,
    capabilities: Vec<RawCapability>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCapability {
    name: String,
    tokens: Vec<RawToken>,
    #[serde(default)]
    allowed_keys: Vec<String>,
    #[serde(default)]
    allowed_key_prefixes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct RawToken(String);

impl Drop for RawToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn normalize_entries(
    entries: &[String],
    capability_index: usize,
    field: &str,
) -> anyhow::Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            bail!("capabilities[{capability_index}].{field} entries must not be empty");
        }
        normalized.push(trimmed.to_string());
    }
    Ok(normalized)
}

fn validate_scoped_token(token: &str, capability_index: usize) -> anyhow::Result<()> {
    let length = token.len();
    if !(MIN_SCOPED_TOKEN_BYTES..=MAX_SCOPED_TOKEN_BYTES).contains(&length) {
        bail!(
            "capabilities[{capability_index}].tokens entries must be between \
             {MIN_SCOPED_TOKEN_BYTES} and {MAX_SCOPED_TOKEN_BYTES} bytes"
        );
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!(
            "capabilities[{capability_index}].tokens entries must contain only printable, \
             non-whitespace ASCII bytes"
        );
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut authorization_values = headers.get_all(header::AUTHORIZATION).iter();
    let raw = authorization_values.next()?.to_str().ok()?;
    if authorization_values.next().is_some() {
        return None;
    }
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(token)
}

fn read_optional_secret(
    value: Option<&str>,
    file: Option<&Path>,
    name: &'static str,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    match (value, file) {
        (Some(_), Some(_)) => bail!("configure either {name} or {name}_file, not both"),
        (Some(value), None) => {
            if value.trim().is_empty() {
                bail!("{name} must not be empty");
            }
            Ok(Some(Zeroizing::new(value.to_string())))
        }
        (None, Some(path)) => {
            let mut resolved = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {name}_file"))?,
            );
            let trimmed_length = resolved.trim_end_matches(['\r', '\n']).len();
            resolved.truncate(trimmed_length);
            if resolved.trim().is_empty() {
                bail!("{name} must not be empty");
            }
            Ok(Some(resolved))
        }
        (None, None) => Ok(None),
    }
}

fn read_bounded_secret_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open auth policy file {}", path.display()))?;
    let mut contents = Zeroizing::new(String::new());
    file.take(MAX_AUTH_POLICY_FILE_BYTES + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("failed to read auth policy file {}", path.display()))?;

    if contents.len() as u64 > MAX_AUTH_POLICY_FILE_BYTES {
        bail!(
            "auth policy file {} exceeds the {} byte limit",
            path.display(),
            MAX_AUTH_POLICY_FILE_BYTES
        );
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const TOKEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN_A_NEXT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
    const TOKEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn scoped_policy_json(token_a: &str, token_b: &str) -> String {
        format!(
            r#"{{
  "version": 1,
  "capabilities": [
    {{
      "name": "app-a",
      "tokens": ["{token_a}", "{TOKEN_A_NEXT}"],
      "allowedKeys": ["id:item-a"],
      "allowedKeyPrefixes": ["id:app-a/"]
    }},
    {{
      "name": "app-b",
      "tokens": ["{token_b}"],
      "allowedKeys": ["id:item-b"]
    }}
  ]
}}"#
        )
    }

    struct TempAuthPolicyFile {
        path: PathBuf,
    }

    impl TempAuthPolicyFile {
        fn new(contents: &str) -> TestResult<Self> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/bweso-test-tmp")
                .join(format!("auth-policy-{}-{unique}.json", std::process::id()));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, contents)?;
            Ok(Self { path })
        }

        fn write(&self, contents: &str) -> std::io::Result<()> {
            std::fs::write(&self.path, contents)
        }
    }

    impl Drop for TempAuthPolicyFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).ok();
        }
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = format!("Bearer {token}").parse();
        let Ok(value) = value else {
            unreachable!("test token must form a valid header value");
        };
        headers.insert(header::AUTHORIZATION, value);
        headers
    }

    #[test]
    fn legacy_token_authorizes_global_scope() -> TestResult {
        let auth = WebhookAuth::from_config(Some(TOKEN_A), None, None, false)?;

        let Some(scope) = auth.authorize(&bearer_headers(TOKEN_A)) else {
            unreachable!("matching legacy token should authorize");
        };
        assert!(scope.allows("id:any-global-selector"));
        assert!(auth.authorize(&bearer_headers(TOKEN_B)).is_none());
        Ok(())
    }

    #[test]
    fn scoped_tokens_receive_only_their_capability() -> TestResult {
        let file = TempAuthPolicyFile::new(&scoped_policy_json(TOKEN_A, TOKEN_B))?;
        let auth = WebhookAuth::from_config(None, None, Some(&file.path), false)?;

        let Some(app_a) = auth.authorize(&bearer_headers(TOKEN_A)) else {
            unreachable!("app-a token should authorize");
        };
        assert!(app_a.allows("id:item-a"));
        assert!(app_a.allows("id:app-a/database"));
        assert!(!app_a.allows("id:item-b"));

        let Some(rotated_app_a) = auth.authorize(&bearer_headers(TOKEN_A_NEXT)) else {
            unreachable!("rotation token should share app-a scope");
        };
        assert!(rotated_app_a.allows("id:item-a"));
        assert!(!rotated_app_a.allows("id:item-b"));

        let Some(app_b) = auth.authorize(&bearer_headers(TOKEN_B)) else {
            unreachable!("app-b token should authorize");
        };
        assert!(app_b.allows("id:item-b"));
        assert!(!app_b.allows("id:item-a"));
        Ok(())
    }

    #[test]
    fn scoped_policy_reload_swaps_atomically_and_rejects_invalid_update() -> TestResult {
        let file = TempAuthPolicyFile::new(&scoped_policy_json(TOKEN_A, TOKEN_B))?;
        let auth = WebhookAuth::from_config(None, None, Some(&file.path), false)?;
        let Some(policy) = auth.scoped_policy() else {
            unreachable!("scoped auth should expose its reloadable policy");
        };

        file.write(&scoped_policy_json(TOKEN_B, TOKEN_A))?;
        assert!(policy.reload()?);
        let Some(app_a) = auth.authorize(&bearer_headers(TOKEN_B)) else {
            unreachable!("updated app-a token should authorize");
        };
        assert!(app_a.allows("id:item-a"));

        file.write(r#"{"version":1,"capabilities":[]}"#)?;
        assert!(policy.reload().is_err());
        let Some(last_good) = auth.authorize(&bearer_headers(TOKEN_B)) else {
            unreachable!("invalid reload must retain the last known-good policy");
        };
        assert!(last_good.allows("id:item-a"));
        Ok(())
    }

    #[test]
    fn scoped_policy_rejects_duplicates_short_tokens_and_empty_scopes() -> TestResult {
        let duplicate = TempAuthPolicyFile::new(&scoped_policy_json(TOKEN_A, TOKEN_A))?;
        let duplicate_error = WebhookAuth::from_config(None, None, Some(&duplicate.path), false)
            .err()
            .ok_or("duplicate token policy unexpectedly succeeded")?;
        assert!(format!("{duplicate_error:#}").contains("tokens must be unique"));
        assert!(!format!("{duplicate_error:#}").contains(TOKEN_A));

        let short = TempAuthPolicyFile::new(
            r#"{"version":1,"capabilities":[{"name":"app","tokens":["short"],"allowedKeys":["id:item"]}]}"#,
        )?;
        let short_error = WebhookAuth::from_config(None, None, Some(&short.path), false)
            .err()
            .ok_or("short token policy unexpectedly succeeded")?;
        assert!(format!("{short_error:#}").contains("between 32 and 4096"));

        let empty_scope = TempAuthPolicyFile::new(&format!(
            r#"{{"version":1,"capabilities":[{{"name":"app","tokens":["{TOKEN_A}"]}}]}}"#
        ))?;
        let empty_scope_error =
            WebhookAuth::from_config(None, None, Some(&empty_scope.path), false)
                .err()
                .ok_or("empty capability scope unexpectedly succeeded")?;
        assert!(format!("{empty_scope_error:#}")
            .contains("must define allowedKeys or allowedKeyPrefixes"));
        assert!(!format!("{empty_scope_error:#}").contains(TOKEN_A));
        Ok(())
    }

    #[test]
    fn scoped_policy_rejects_unknown_fields_and_versions() -> TestResult {
        let unknown_field = TempAuthPolicyFile::new(&format!(
            r#"{{"version":1,"unexpected":true,"capabilities":[{{"name":"app","tokens":["{TOKEN_A}"],"allowedKeys":["id:item"]}}]}}"#
        ))?;
        let unknown_error = WebhookAuth::from_config(None, None, Some(&unknown_field.path), false)
            .err()
            .ok_or("unknown auth-policy field unexpectedly succeeded")?;
        assert!(format!("{unknown_error:#}").contains("unknown field"));
        assert!(!format!("{unknown_error:#}").contains(TOKEN_A));

        let unsupported_version = TempAuthPolicyFile::new(&format!(
            r#"{{"version":2,"capabilities":[{{"name":"app","tokens":["{TOKEN_A}"],"allowedKeys":["id:item"]}}]}}"#
        ))?;
        let version_error =
            WebhookAuth::from_config(None, None, Some(&unsupported_version.path), false)
                .err()
                .ok_or("unsupported auth-policy version unexpectedly succeeded")?;
        assert!(format!("{version_error:#}").contains("unsupported auth policy version 2"));
        assert!(!format!("{version_error:#}").contains(TOKEN_A));
        Ok(())
    }

    #[test]
    fn auth_modes_are_mutually_exclusive_and_required() {
        let missing = WebhookAuth::from_config(None, None, None, false);
        assert!(missing.is_err());

        let file = Path::new("unused.json");
        let conflicting = WebhookAuth::from_config(Some(TOKEN_A), None, Some(file), false);
        assert!(conflicting.is_err());

        let insecure_conflict = WebhookAuth::from_config(Some(TOKEN_A), None, None, true);
        assert!(insecure_conflict.is_err());
    }

    #[test]
    fn bearer_parser_rejects_duplicate_or_malformed_headers() {
        let mut duplicate = bearer_headers(TOKEN_A);
        let second = format!("Bearer {TOKEN_B}").parse();
        let Ok(second) = second else {
            unreachable!("test token must form a valid header value");
        };
        duplicate.append(header::AUTHORIZATION, second);
        assert!(bearer_token(&duplicate).is_none());

        let mut malformed = HeaderMap::new();
        let malformed_value = "Bearer token with-spaces".parse();
        let Ok(malformed_value) = malformed_value else {
            unreachable!("test value must form a valid header value");
        };
        malformed.insert(header::AUTHORIZATION, malformed_value);
        assert!(bearer_token(&malformed).is_none());
    }

    #[test]
    fn scoped_policy_rejects_oversized_file() -> TestResult {
        let mut contents = String::from("{");
        let repeat = usize::try_from(MAX_AUTH_POLICY_FILE_BYTES)?;
        contents.push_str(&" ".repeat(repeat));
        contents.push('}');
        let file = TempAuthPolicyFile::new(&contents)?;

        let error = WebhookAuth::from_config(None, None, Some(&file.path), false)
            .err()
            .ok_or("oversized auth policy unexpectedly succeeded")?;
        assert!(error.to_string().contains("exceeds the"));
        Ok(())
    }
}
