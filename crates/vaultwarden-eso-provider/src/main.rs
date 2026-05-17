#![forbid(unsafe_code)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use axum::{
    body::{to_bytes, Body},
    extract::{MatchedPath, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bweso_bitwarden::{
    BitwardenApiClient, BitwardenApiClientOptions, BitwardenApiError, BitwardenAuth,
    BitwardenCacheConfig, BitwardenClientError, BitwardenDevice, BitwardenEndpoint,
    BitwardenEndpoints, BitwardenHttpConfig, BitwardenProvider, BitwardenSelector, CipherError,
};
use bweso_core::{require_non_empty, RemoteRef, SecretDocument};
use clap::Parser;
use http::{header, HeaderMap, Request, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use zeroize::Zeroize;

mod lifecycle;
mod metrics;

use lifecycle::Lifecycle;
use metrics::{AppMetrics, PROMETHEUS_CONTENT_TYPE};

const RESOLVE_BODY_LIMIT_BYTES: usize = 16 * 1024;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(long, env = "BWESO_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    #[arg(long, env = "BWESO_SINGLE_ORIGIN_URL")]
    single_origin_url: Option<String>,
    #[arg(long, env = "BWESO_IDENTITY_URL")]
    identity_url: Option<String>,
    #[arg(long, env = "BWESO_API_URL")]
    api_url: Option<String>,
    #[arg(long, env = "BWESO_CLIENT_ID")]
    client_id: Option<String>,
    #[arg(long, env = "BWESO_CLIENT_ID_FILE")]
    client_id_file: Option<PathBuf>,
    #[arg(long, env = "BWESO_CLIENT_SECRET")]
    client_secret: Option<String>,
    #[arg(long, env = "BWESO_CLIENT_SECRET_FILE")]
    client_secret_file: Option<PathBuf>,
    #[arg(long, env = "BWESO_MASTER_PASSWORD")]
    master_password: Option<String>,
    #[arg(long, env = "BWESO_MASTER_PASSWORD_FILE")]
    master_password_file: Option<PathBuf>,
    #[arg(
        long,
        env = "BWESO_DEVICE_IDENTIFIER",
        default_value = "vaultwarden-eso-provider"
    )]
    device_identifier: String,
    #[arg(
        long,
        env = "BWESO_DEVICE_NAME",
        default_value = "Vaultwarden ESO Provider"
    )]
    device_name: String,
    #[arg(long, env = "BWESO_DEVICE_TYPE", default_value_t = 22)]
    device_type: u8,
    #[arg(long, env = "BWESO_CACHE_TTL_SECONDS", default_value_t = 60)]
    cache_ttl_seconds: u64,
    #[arg(
        long = "allowed-key",
        env = "BWESO_ALLOWED_KEYS",
        value_delimiter = ',',
        value_name = "KEY"
    )]
    allowed_keys: Vec<String>,
    #[arg(
        long = "allowed-key-prefix",
        env = "BWESO_ALLOWED_KEY_PREFIXES",
        value_delimiter = ',',
        value_name = "PREFIX"
    )]
    allowed_key_prefixes: Vec<String>,
    /// File listing additional allowed exact selector keys, one entry per line
    /// (commas also split; blank lines and `#` comments are ignored). Entries
    /// are unioned with `--allowed-key`. When set, the file is re-read on the
    /// reload interval so a mounted `ConfigMap` can change the policy without a
    /// provider restart.
    #[arg(long, env = "BWESO_ALLOWED_KEYS_FILE")]
    allowed_keys_file: Option<PathBuf>,
    /// File listing additional allowed selector key prefixes. Same format and
    /// reload semantics as `--allowed-keys-file`; entries are unioned with
    /// `--allowed-key-prefix`.
    #[arg(long, env = "BWESO_ALLOWED_KEY_PREFIXES_FILE")]
    allowed_key_prefixes_file: Option<PathBuf>,
    /// Explicitly allow every selector visible to the configured account. This is
    /// intended only when the Bitwarden/Vaultwarden account is already scoped to
    /// the same trust boundary.
    #[arg(long, env = "BWESO_ALLOW_ALL_SELECTORS", default_value_t = false)]
    allow_all_selectors: bool,
    /// How often to re-read the policy files, in seconds. `0` disables
    /// reloading (the files are still read once at startup). Ignored when no
    /// policy file is configured.
    #[arg(
        long,
        env = "BWESO_POLICY_RELOAD_INTERVAL_SECONDS",
        default_value_t = 30
    )]
    policy_reload_interval_seconds: u64,
    #[arg(long, env = "BWESO_HTTP_CONNECT_TIMEOUT_SECONDS", default_value_t = 5)]
    http_connect_timeout_seconds: u64,
    #[arg(long, env = "BWESO_HTTP_REQUEST_TIMEOUT_SECONDS", default_value_t = 25)]
    http_request_timeout_seconds: u64,
    /// PEM-encoded CA bundle to trust in addition to the bundled Web PKI roots.
    /// Use for Vaultwarden installs on a private CA.
    #[arg(long, env = "BWESO_CA_BUNDLE_FILE")]
    ca_bundle_file: Option<PathBuf>,
    #[arg(long, env = "BWESO_WEBHOOK_AUTH_TOKEN")]
    webhook_auth_token: Option<String>,
    #[arg(long, env = "BWESO_WEBHOOK_AUTH_TOKEN_FILE")]
    webhook_auth_token_file: Option<PathBuf>,
    #[arg(
        long,
        env = "BWESO_INSECURE_ALLOW_UNAUTHENTICATED",
        default_value_t = false
    )]
    insecure_allow_unauthenticated: bool,
    /// Maximum concurrent /v1/resolve requests. Excess requests are shed with
    /// 503. Set to 0 to disable the cap (not recommended for production).
    #[arg(long, env = "BWESO_RESOLVE_CONCURRENCY_LIMIT", default_value_t = 16)]
    resolve_concurrency_limit: u32,
    /// Run one HTTP healthcheck request and exit.
    #[arg(long, env = "BWESO_HEALTHCHECK_URL")]
    healthcheck_url: Option<String>,
}

#[derive(Clone)]
struct AppState {
    provider: Arc<dyn BitwardenProvider>,
    selector_policy: SelectorPolicy,
    auth: WebhookAuth,
    metrics: Arc<AppMetrics>,
    lifecycle: Lifecycle,
    resolve_semaphore: Option<Arc<tokio::sync::Semaphore>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveRequest {
    remote_ref: RemoteRef,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let mut args = Args::parse();
    if let Some(url) = args.healthcheck_url.as_deref() {
        run_healthcheck(url)?;
        return Ok(());
    }

    let listen = args.listen;
    let lifecycle = Lifecycle::default();

    let resolve_semaphore = resolve_semaphore(args.resolve_concurrency_limit);
    let state = AppState {
        provider: provider_from_args(&args)?,
        selector_policy: SelectorPolicy::from_args(&args)?,
        auth: WebhookAuth::from_args(&args)?,
        metrics: Arc::new(AppMetrics::new()),
        lifecycle: lifecycle.clone(),
        resolve_semaphore,
    };
    args.zeroize_sensitive();

    // Seed policy gauges from the startup evaluation so a file-backed policy
    // is observable from t0 — including reloadIntervalSeconds:0 (no task) and
    // the warm-up window before the first reload tick.
    if state.selector_policy.sources.has_file() {
        let (active_keys, active_key_prefixes) = state.selector_policy.snapshot().counts();
        state
            .metrics
            .record_policy_baseline(active_keys, active_key_prefixes);
    }

    // The task observes shutdown via Lifecycle and is reaped on runtime drop;
    // no handle to retain here.
    let _ = spawn_policy_reload(
        state.selector_policy.clone(),
        lifecycle.clone(),
        state.metrics.clone(),
        args.policy_reload_interval_seconds,
    );

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(address = %listen, "starting ESO webhook provider");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(lifecycle))
        .await?;

    Ok(())
}

fn resolve_semaphore(limit: u32) -> Option<Arc<tokio::sync::Semaphore>> {
    if limit > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(limit as usize)))
    } else {
        None
    }
}

/// Immutable evaluated selector policy. Allow-all is an explicit variant, so
/// an empty allow-list cannot accidentally widen access to every item.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PolicyRules {
    AllowAll,
    AllowList {
        allowed_keys: Vec<String>,
        allowed_key_prefixes: Vec<String>,
    },
}

impl PolicyRules {
    fn allows(&self, key: &str) -> bool {
        match self {
            Self::AllowAll => true,
            Self::AllowList {
                allowed_keys,
                allowed_key_prefixes,
            } => {
                allowed_keys.iter().any(|allowed_key| allowed_key == key)
                    || allowed_key_prefixes
                        .iter()
                        .any(|prefix| key.starts_with(prefix))
            }
        }
    }

    fn counts(&self) -> (usize, usize) {
        match self {
            Self::AllowAll => (0, 0),
            Self::AllowList {
                allowed_keys,
                allowed_key_prefixes,
            } => (allowed_keys.len(), allowed_key_prefixes.len()),
        }
    }
}

/// Sources the policy is built from. Inline entries come from flags/env and are
/// fixed for the process lifetime; file entries are re-read on the reload
/// interval so a mounted `ConfigMap` can change the policy without a restart.
#[derive(Clone, Debug, Default)]
struct PolicySources {
    inline_keys: Vec<String>,
    inline_key_prefixes: Vec<String>,
    keys_file: Option<PathBuf>,
    key_prefixes_file: Option<PathBuf>,
}

impl PolicySources {
    fn has_file(&self) -> bool {
        self.keys_file.is_some() || self.key_prefixes_file.is_some()
    }

    /// Re-read the file sources and union them with the inline entries.
    /// Inline entries are validated once (at startup) via [`SelectorPolicy::from_args`].
    fn evaluate(&self) -> anyhow::Result<PolicyRules> {
        let mut allowed_keys = self.inline_keys.clone();
        if let Some(path) = &self.keys_file {
            allowed_keys.extend(read_policy_file(path, "allowed_key")?);
        }
        let mut allowed_key_prefixes = self.inline_key_prefixes.clone();
        if let Some(path) = &self.key_prefixes_file {
            allowed_key_prefixes.extend(read_policy_file(path, "allowed_key_prefix")?);
        }

        if self.has_file() && allowed_keys.is_empty() && allowed_key_prefixes.is_empty() {
            bail!(
                "selector policy file source is configured but evaluated to zero entries; \
                 refusing to fall back to allow-all"
            );
        }
        if allowed_keys.is_empty() && allowed_key_prefixes.is_empty() {
            bail!("selector policy allow-list evaluated to zero entries");
        }

        Ok(PolicyRules::AllowList {
            allowed_keys,
            allowed_key_prefixes,
        })
    }
}

/// Hot-swappable selector policy. Reads take a short read lock and clone the
/// shared `Arc`; reloads swap the `Arc` under a brief write lock. No new
/// dependency: the read path is uncontended in steady state and the swap is
/// rare (reload interval, default 30s).
#[derive(Clone)]
struct SelectorPolicy {
    rules: Arc<std::sync::RwLock<Arc<PolicyRules>>>,
    sources: Arc<PolicySources>,
}

impl SelectorPolicy {
    fn from_rules(rules: PolicyRules, sources: PolicySources) -> Self {
        Self {
            rules: Arc::new(std::sync::RwLock::new(Arc::new(rules))),
            sources: Arc::new(sources),
        }
    }

    fn from_args(args: &Args) -> anyhow::Result<Self> {
        let has_inline_entries =
            !args.allowed_keys.is_empty() || !args.allowed_key_prefixes.is_empty();
        let has_file_entries =
            args.allowed_keys_file.is_some() || args.allowed_key_prefixes_file.is_some();
        if !args.allow_all_selectors && !has_inline_entries && !has_file_entries {
            bail!(
                "configure selector policy with allowed keys/prefixes, or explicitly set BWESO_ALLOW_ALL_SELECTORS=true when the provider account is already scoped to this trust boundary"
            );
        }
        if args.allow_all_selectors && (has_inline_entries || has_file_entries) {
            bail!(
                "configure either selector allow-list entries or BWESO_ALLOW_ALL_SELECTORS=true, not both"
            );
        }
        let sources = PolicySources {
            inline_keys: normalize_policy_entries(&args.allowed_keys, "allowed_key")?,
            inline_key_prefixes: normalize_policy_entries(
                &args.allowed_key_prefixes,
                "allowed_key_prefix",
            )?,
            keys_file: args.allowed_keys_file.clone(),
            key_prefixes_file: args.allowed_key_prefixes_file.clone(),
        };
        // Fail fast at startup if a configured file is unreadable or invalid.
        let rules = if args.allow_all_selectors {
            PolicyRules::AllowAll
        } else {
            sources.evaluate()?
        };
        Ok(Self::from_rules(rules, sources))
    }

    fn allows(&self, key: &str) -> bool {
        let snapshot = self.snapshot();
        snapshot.allows(key)
    }

    fn snapshot(&self) -> Arc<PolicyRules> {
        // The read/write critical sections are panic-free (Arc clone / assign),
        // so recovering a poisoned guard is sound and avoids a panic path.
        let guard = self
            .rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Re-evaluate the sources and swap the active rules in place. Returns
    /// whether the effective policy changed. Never logs selector keys.
    fn reload(&self) -> anyhow::Result<bool> {
        if !self.sources.has_file() {
            return Ok(false);
        }
        let next = self.sources.evaluate()?;
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
}

impl Args {
    fn zeroize_sensitive(&mut self) {
        zeroize_option(&mut self.client_id);
        zeroize_option(&mut self.client_secret);
        zeroize_option(&mut self.master_password);
        zeroize_option(&mut self.webhook_auth_token);
    }
}

fn zeroize_option(value: &mut Option<String>) {
    if let Some(secret) = value {
        secret.zeroize();
    }
    *value = None;
}

fn normalize_policy_entries(entries: &[String], name: &'static str) -> anyhow::Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.trim();
        require_non_empty(entry, name)?;
        normalized.push(entry.to_string());
    }

    Ok(normalized)
}

/// Upper bound on a policy file. A Kubernetes `ConfigMap` is itself capped near
/// 1 MiB; this is a defensive ceiling for the generic file path so an
/// unexpected large/non-`ConfigMap` file cannot be slurped wholesale on every
/// reload.
const MAX_POLICY_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Parse a policy file: one entry per line, commas also split, surrounding
/// whitespace trimmed, blank lines and `#` comment lines ignored.
fn read_policy_file(path: &Path, name: &'static str) -> anyhow::Result<Vec<String>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat {name}_file {}", path.display()))?;
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        bail!(
            "{name}_file {} is {} bytes, exceeding the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_POLICY_FILE_BYTES
        );
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read {name}_file {}", path.display()))?;
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for raw in line.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            entries.push(entry.to_string());
        }
    }

    Ok(entries)
}

/// Spawn the background task that periodically re-reads file-backed policy
/// sources and hot-swaps the active rules. Returns `None` (and spawns no task)
/// when no policy file is configured or the interval is `0`; in those cases the
/// policy stays exactly as evaluated at startup. The task exits promptly on
/// shutdown via [`Lifecycle::shutdown_requested`], not only on its next tick.
fn spawn_policy_reload(
    policy: SelectorPolicy,
    lifecycle: Lifecycle,
    metrics: Arc<AppMetrics>,
    interval_seconds: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    if !policy.sources.has_file() {
        return None;
    }
    if interval_seconds == 0 {
        tracing::info!("policy file reload disabled (interval 0); policy is fixed at startup");
        return None;
    }

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately; the startup evaluation already loaded
        // the files, so skip it and wait one interval before re-reading.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                () = lifecycle.shutdown_requested() => break,
            }
            // Covers the rare case where the tick and shutdown race and the
            // tick wins the select.
            if !lifecycle.is_ready() {
                break;
            }
            let outcome = match policy.reload() {
                Ok(true) => {
                    let rules = policy.snapshot();
                    let (active_keys, active_key_prefixes) = rules.counts();
                    // Counts only — never log selector keys or prefixes.
                    tracing::info!(
                        allowed_keys = active_keys,
                        allowed_key_prefixes = active_key_prefixes,
                        "selector policy reloaded"
                    );
                    "success"
                }
                Ok(false) => "unchanged",
                Err(error) => {
                    // Keep serving the last good policy on a transient read or
                    // validation failure. Redacted: errors carry paths, not keys.
                    tracing::warn!(error = %error, "selector policy reload failed; keeping previous policy");
                    "failure"
                }
            };
            // Active counts reflect the currently-served policy (last-good on
            // failure). Counts only — never the selector keys themselves.
            let (active_keys, active_key_prefixes) = policy.snapshot().counts();
            metrics.record_policy_reload(outcome, active_keys, active_key_prefixes);
        }
    }))
}

fn run_healthcheck(raw_url: &str) -> anyhow::Result<()> {
    let target = parse_healthcheck_target(raw_url)?;
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.path, target.host
    )?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    ensure_successful_healthcheck_response(&response)
}

struct HealthcheckTarget {
    host: String,
    port: u16,
    path: String,
}

fn parse_healthcheck_target(raw_url: &str) -> anyhow::Result<HealthcheckTarget> {
    let url = Url::parse(raw_url)?;
    anyhow::ensure!(url.scheme() == "http", "healthcheck URL must use http");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("healthcheck URL must include a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("healthcheck URL must include a port"))?;

    Ok(HealthcheckTarget {
        host: host.to_string(),
        port,
        path: healthcheck_request_path(&url),
    })
}

fn healthcheck_request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    path
}

fn ensure_successful_healthcheck_response(response: &str) -> anyhow::Result<()> {
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("healthcheck returned an empty response"))?;
    anyhow::ensure!(
        status_line.starts_with("HTTP/1.1 2") || status_line.starts_with("HTTP/1.0 2"),
        "healthcheck returned non-success status: {status_line}"
    );
    Ok(())
}

fn provider_from_args(args: &Args) -> anyhow::Result<Arc<dyn BitwardenProvider>> {
    let client_id = read_sensitive_arg(
        args.client_id.as_deref(),
        args.client_id_file.as_deref(),
        "client_id",
    )?;
    let client_secret = read_sensitive_arg(
        args.client_secret.as_deref(),
        args.client_secret_file.as_deref(),
        "client_secret",
    )?;
    let master_password = read_sensitive_arg(
        args.master_password.as_deref(),
        args.master_password_file.as_deref(),
        "master_password",
    )?;
    require_non_empty(&args.device_identifier, "device_identifier")?;
    require_non_empty(&args.device_name, "device_name")?;
    if args.http_connect_timeout_seconds == 0 {
        bail!("http_connect_timeout_seconds must be greater than zero");
    }
    if args.http_request_timeout_seconds == 0 {
        bail!("http_request_timeout_seconds must be greater than zero");
    }

    let endpoints = endpoints_from_args(args)?;
    let auth = BitwardenAuth {
        client_id,
        client_secret: client_secret.into(),
        master_password: master_password.into(),
    };
    let device = BitwardenDevice {
        device_type: args.device_type,
        identifier: args.device_identifier.clone(),
        name: args.device_name.clone(),
    };
    let cache_config = BitwardenCacheConfig::new(Duration::from_secs(args.cache_ttl_seconds));
    let extra_root_certificates = load_extra_root_certificates(args.ca_bundle_file.as_deref())?;
    let http_config = BitwardenHttpConfig::new(
        Duration::from_secs(args.http_connect_timeout_seconds),
        Duration::from_secs(args.http_request_timeout_seconds),
    )
    .with_extra_root_certificates(extra_root_certificates);
    let provider = BitwardenApiClient::with_options(BitwardenApiClientOptions {
        endpoints,
        auth,
        device,
        cache_config,
        http_config,
    })
    .context("failed to build Bitwarden-compatible API client")?;

    Ok(Arc::new(provider))
}

fn read_sensitive_arg(
    value: Option<&str>,
    file: Option<&Path>,
    name: &'static str,
) -> anyhow::Result<String> {
    let resolved = match (value, file) {
        (Some(_), Some(_)) => bail!("configure either {name} or {name}_file, not both"),
        (Some(value), None) => value.to_string(),
        (None, Some(path)) => fs::read_to_string(path)
            .with_context(|| format!("failed to read {name}_file"))?
            .trim_end_matches(['\r', '\n'])
            .to_string(),
        (None, None) => bail!("configure {name} or {name}_file"),
    };

    require_non_empty(&resolved, name)?;
    Ok(resolved)
}

fn endpoints_from_args(args: &Args) -> anyhow::Result<BitwardenEndpoints> {
    match (&args.single_origin_url, &args.identity_url, &args.api_url) {
        (Some(single_origin_url), None, None) => {
            let endpoint = BitwardenEndpoint::parse(single_origin_url).context(
                "invalid single-origin Bitwarden/Vaultwarden endpoint configuration",
            )?;
            Ok(BitwardenEndpoints::from_single_origin(endpoint))
        }
        (None, Some(identity_url), Some(api_url)) => {
            BitwardenEndpoints::parse_split(identity_url, api_url)
                .context("invalid split Bitwarden endpoint configuration")
        }
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            bail!(
                "configure either BWESO_SINGLE_ORIGIN_URL or both BWESO_IDENTITY_URL and BWESO_API_URL, not both endpoint modes"
            )
        }
        _ => bail!(
            "configure BWESO_SINGLE_ORIGIN_URL for single-origin Vaultwarden/self-hosted Bitwarden, or both BWESO_IDENTITY_URL and BWESO_API_URL for split Bitwarden endpoints"
        ),
    }
}

#[derive(Clone)]
enum WebhookAuth {
    Required(Arc<SecretString>),
    DisabledInsecure,
}

impl WebhookAuth {
    fn from_args(args: &Args) -> anyhow::Result<Self> {
        let token = read_optional_sensitive_arg(
            args.webhook_auth_token.as_deref(),
            args.webhook_auth_token_file.as_deref(),
            "webhook_auth_token",
        )?;
        match (token, args.insecure_allow_unauthenticated) {
            (Some(mut token), true) => {
                token.zeroize();
                bail!(
                    "configure either BWESO_WEBHOOK_AUTH_TOKEN or BWESO_INSECURE_ALLOW_UNAUTHENTICATED=true, not both"
                )
            }
            (Some(token), false) => Ok(Self::Required(Arc::new(token.into()))),
            (None, true) => {
                tracing::warn!(
                    "webhook authentication is disabled; use only for local or isolated tests"
                );
                Ok(Self::DisabledInsecure)
            }
            (None, false) => bail!(
                "configure BWESO_WEBHOOK_AUTH_TOKEN, or explicitly set BWESO_INSECURE_ALLOW_UNAUTHENTICATED=true for local tests"
            ),
        }
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::DisabledInsecure => true,
            Self::Required(expected) => {
                let Some(raw) = headers.get(header::AUTHORIZATION) else {
                    return false;
                };
                let Ok(raw) = raw.to_str() else {
                    return false;
                };
                let Some((scheme, token)) = raw.split_once(' ') else {
                    return false;
                };
                scheme.eq_ignore_ascii_case("Bearer")
                    && !token.is_empty()
                    && token.trim() == token
                    && expected
                        .expose_secret()
                        .as_bytes()
                        .ct_eq(token.as_bytes())
                        .into()
            }
        }
    }
}

fn read_optional_sensitive_arg(
    value: Option<&str>,
    file: Option<&Path>,
    name: &'static str,
) -> anyhow::Result<Option<String>> {
    match (value, file) {
        (Some(_), Some(_)) => bail!("configure either {name} or {name}_file, not both"),
        (Some(value), None) => {
            require_non_empty(value, name)?;
            Ok(Some(value.to_string()))
        }
        (None, Some(path)) => {
            let resolved = fs::read_to_string(path)
                .with_context(|| format!("failed to read {name}_file"))?
                .trim_end_matches(['\r', '\n'])
                .to_string();
            require_non_empty(&resolved, name)?;
            Ok(Some(resolved))
        }
        (None, None) => Ok(None),
    }
}

fn load_extra_root_certificates(path: Option<&Path>) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };

    let display = path.display();
    let pem = fs::read(path).with_context(|| format!("failed to read ca_bundle_file {display}"))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)
        .with_context(|| format!("failed to parse PEM certificates from {display}"))?;

    if certificates.is_empty() {
        anyhow::bail!("ca_bundle_file {display} contained no PEM certificates");
    }

    Ok(certificates)
}

fn build_router(state: AppState) -> Router {
    let middleware_state = state.clone();

    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/resolve", post(resolve))
        .layer(middleware::from_fn_with_state(
            middleware_state,
            record_http_metrics,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

async fn livez() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.lifecycle.is_ready() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state
            .metrics
            .render(state.lifecycle.is_ready(), state.provider.cache_metrics()),
    )
}

async fn record_http_metrics(
    State(state): State<AppState>,
    matched_path: Option<MatchedPath>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let route = matched_path
        .as_ref()
        .map_or("unmatched", MatchedPath::as_str)
        .to_string();
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();

    state
        .metrics
        .record_http_request(&method, &route, status, started.elapsed());

    response
}

async fn resolve(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<SecretDocument>, (StatusCode, Json<ErrorResponse>)> {
    let started = Instant::now();
    if !state.auth.is_authorized(request.headers()) {
        state.metrics.record_resolve_request(
            StatusCode::UNAUTHORIZED,
            "error",
            "auth",
            started.elapsed(),
        );
        return Err(auth_error());
    }

    let _permit = match state
        .resolve_semaphore
        .as_ref()
        .map(|semaphore| semaphore.clone().try_acquire_owned())
    {
        None => None,
        Some(Ok(permit)) => Some(permit),
        Some(Err(_)) => {
            state.metrics.record_resolve_request(
                StatusCode::SERVICE_UNAVAILABLE,
                "error",
                "overloaded",
                started.elapsed(),
            );
            return Err(public_error(StatusCode::SERVICE_UNAVAILABLE, "overloaded"));
        }
    };

    let request = match decode_resolve_request(request).await {
        Ok(request) => request,
        Err(status) => {
            state
                .metrics
                .record_resolve_request(status, "error", "validation", started.elapsed());
            return Err(public_error(status, "validation"));
        }
    };

    let selector = match BitwardenSelector::try_from(request.remote_ref) {
        Ok(selector) => selector,
        Err(error) => {
            let (status, error_kind) = provider_status_and_kind(&error);
            state
                .metrics
                .record_resolve_request(status, "error", error_kind, started.elapsed());
            return Err(provider_error(&error));
        }
    };

    if !state.selector_policy.allows(&selector.key) {
        let status = StatusCode::FORBIDDEN;
        state
            .metrics
            .record_resolve_request(status, "error", "policy_denied", started.elapsed());
        return Err(public_error(status, "policy_denied"));
    }

    match state.provider.resolve(selector).await {
        Ok(document) => {
            state.metrics.record_resolve_request(
                StatusCode::OK,
                "success",
                "none",
                started.elapsed(),
            );
            Ok(Json(document))
        }
        Err(error) => {
            let (status, error_kind) = provider_status_and_kind(&error);
            state
                .metrics
                .record_resolve_request(status, "error", error_kind, started.elapsed());
            Err(provider_error(&error))
        }
    }
}

async fn decode_resolve_request(request: Request<Body>) -> Result<ResolveRequest, StatusCode> {
    if !is_json_content_type(request.headers()) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    let body = to_bytes(request.into_body(), RESOLVE_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    let Some((_, subtype)) = media_type.rsplit_once('/') else {
        return false;
    };

    subtype.eq_ignore_ascii_case("json") || subtype.to_ascii_lowercase().ends_with("+json")
}

fn auth_error() -> (StatusCode, Json<ErrorResponse>) {
    public_error(StatusCode::UNAUTHORIZED, "auth")
}

fn public_error(status: StatusCode, error_kind: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: public_error_message(error_kind).to_string(),
        }),
    )
}

fn provider_error(error: &BitwardenClientError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, error_kind) = provider_status_and_kind(error);
    let message = public_error_message(error_kind).to_string();

    (status, Json(ErrorResponse { error: message }))
}

fn provider_status_and_kind(error: &BitwardenClientError) -> (StatusCode, &'static str) {
    match error {
        BitwardenClientError::Validation(_)
        | BitwardenClientError::Cipher(CipherError::BlankProperty) => {
            (StatusCode::BAD_REQUEST, "validation")
        }
        BitwardenClientError::Cipher(CipherError::MissingProperty { .. })
        | BitwardenClientError::Api(BitwardenApiError::CipherNotFound) => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        BitwardenClientError::Cipher(CipherError::UnsupportedAttachment) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_attachment")
        }
        BitwardenClientError::Api(BitwardenApiError::AmbiguousCipherName) => {
            (StatusCode::CONFLICT, "ambiguous_selector")
        }
        BitwardenClientError::Api(BitwardenApiError::UnsupportedSharedItem) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_shared_item")
        }
        BitwardenClientError::Api(BitwardenApiError::Http(_)) => {
            (StatusCode::BAD_GATEWAY, "upstream_http")
        }
        BitwardenClientError::Api(BitwardenApiError::HttpStatus { .. }) => {
            (StatusCode::BAD_GATEWAY, "upstream_status")
        }
        BitwardenClientError::Crypto(_)
        | BitwardenClientError::Cipher(
            CipherError::Crypto(_) | CipherError::NoExtractableFields { .. },
        ) => (StatusCode::INTERNAL_SERVER_ERROR, "crypto"),
        BitwardenClientError::KeyDerivation(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "key_derivation")
        }
        BitwardenClientError::Api(
            BitwardenApiError::UnsupportedKdfType { .. }
            | BitwardenApiError::MissingKdfParameter { .. },
        ) => (StatusCode::INTERNAL_SERVER_ERROR, "kdf_parameters"),
        BitwardenClientError::Api(
            BitwardenApiError::MissingMasterPasswordUnlock
            | BitwardenApiError::MissingMasterKeyWrappedUserKey
            | BitwardenApiError::MissingCachedSync,
        ) => (StatusCode::INTERNAL_SERVER_ERROR, "sync_payload"),
        BitwardenClientError::Api(BitwardenApiError::InvalidBaseUrl)
        | BitwardenClientError::InvalidEndpoint { .. }
        | BitwardenClientError::InsecureEndpoint => (StatusCode::INTERNAL_SERVER_ERROR, "endpoint"),
        BitwardenClientError::UnsupportedVersionSelector => {
            (StatusCode::BAD_REQUEST, "unsupported_version")
        }
        BitwardenClientError::UnprefixedSelectorKey => (StatusCode::BAD_REQUEST, "validation"),
    }
}

fn public_error_message(error_kind: &str) -> &'static str {
    match error_kind {
        "auth" => "provider authentication failed",
        "validation" => "invalid resolve request",
        "unsupported_version" => "remoteRef.version is not supported",
        "policy_denied" => "requested Bitwarden item is not allowed by provider policy",
        "not_found" => "requested Bitwarden item or property was not found",
        "ambiguous_selector" => "requested Bitwarden item name is ambiguous; use the item ID",
        "unsupported_attachment" => "Bitwarden attachment extraction is not supported",
        "unsupported_shared_item" => "shared organization Bitwarden items are not supported",
        "upstream_http" => "Bitwarden-compatible upstream request failed",
        "upstream_status" => "Bitwarden-compatible upstream returned an error status",
        "crypto" => "failed to decrypt selected Bitwarden item",
        "key_derivation" => "failed to unlock Bitwarden vault key",
        "kdf_parameters" => "Bitwarden-compatible KDF parameters are unsupported",
        "sync_payload" => "Bitwarden-compatible sync payload is missing required unlock data",
        "endpoint" => "provider endpoint configuration is invalid",
        "overloaded" => "provider is at concurrency limit; retry shortly",
        _ => "provider request failed",
    }
}

async fn shutdown_signal(lifecycle: Lifecycle) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C signal handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM signal handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    lifecycle.mark_shutting_down();
    tracing::info!("shutdown signal received; terminating HTTP server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use http::{header, Method, Request};
    use tower::ServiceExt;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct StaticProvider;

    #[async_trait]
    impl BitwardenProvider for StaticProvider {
        async fn resolve(
            &self,
            selector: BitwardenSelector,
        ) -> Result<SecretDocument, BitwardenClientError> {
            let data_key = selector.property.unwrap_or_else(|| "value".to_string());

            Ok(SecretDocument::single(data_key, "resolved-secret"))
        }

        fn cache_metrics(&self) -> Option<bweso_bitwarden::BitwardenCacheMetrics> {
            Some(bweso_bitwarden::BitwardenCacheMetrics {
                cache_hits: 2,
                refresh_successes: 1,
                refresh_failures: 0,
                last_success_unix_seconds: Some(1_700_000_000),
                last_success_age_seconds: Some(5),
            })
        }
    }

    struct MissingPropertyProvider;

    #[async_trait]
    impl BitwardenProvider for MissingPropertyProvider {
        async fn resolve(
            &self,
            selector: BitwardenSelector,
        ) -> Result<SecretDocument, BitwardenClientError> {
            Err(CipherError::MissingProperty {
                property: selector.property.unwrap_or_else(|| "unknown".to_string()),
            }
            .into())
        }
    }

    fn test_app(provider: Arc<dyn BitwardenProvider>) -> Router {
        build_router(test_state(provider))
    }

    fn test_state(provider: Arc<dyn BitwardenProvider>) -> AppState {
        AppState {
            provider,
            selector_policy: test_allow_all_selector_policy(),
            auth: WebhookAuth::DisabledInsecure,
            metrics: Arc::new(AppMetrics::new()),
            lifecycle: Lifecycle::default(),
            resolve_semaphore: Some(Arc::new(tokio::sync::Semaphore::new(16))),
        }
    }

    fn test_state_with_auth(provider: Arc<dyn BitwardenProvider>, token: &str) -> AppState {
        AppState {
            provider,
            selector_policy: test_allow_all_selector_policy(),
            auth: WebhookAuth::Required(Arc::new(token.to_string().into())),
            metrics: Arc::new(AppMetrics::new()),
            lifecycle: Lifecycle::default(),
            resolve_semaphore: Some(Arc::new(tokio::sync::Semaphore::new(16))),
        }
    }

    fn test_allow_all_selector_policy() -> SelectorPolicy {
        SelectorPolicy::from_rules(PolicyRules::AllowAll, PolicySources::default())
    }

    fn valid_args() -> Args {
        Args {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            single_origin_url: Some("http://127.0.0.1:8081".to_string()),
            identity_url: None,
            api_url: None,
            client_id: Some("user.fixture".to_string()),
            client_id_file: None,
            client_secret: Some("super-secret-api-key".to_string()),
            client_secret_file: None,
            master_password: Some("super-secret-master-password".to_string()),
            master_password_file: None,
            device_identifier: "bweso-test".to_string(),
            device_name: "BWESO Test".to_string(),
            device_type: 22,
            cache_ttl_seconds: 60,
            allowed_keys: Vec::new(),
            allowed_key_prefixes: Vec::new(),
            allowed_keys_file: None,
            allowed_key_prefixes_file: None,
            allow_all_selectors: true,
            policy_reload_interval_seconds: 30,
            http_connect_timeout_seconds: 5,
            http_request_timeout_seconds: 25,
            ca_bundle_file: None,
            resolve_concurrency_limit: 16,
            webhook_auth_token: Some("test-webhook-token".to_string()),
            webhook_auth_token_file: None,
            insecure_allow_unauthenticated: false,
            healthcheck_url: None,
        }
    }

    #[test]
    fn security_related_size_limits_stay_at_documented_values() {
        assert_eq!(RESOLVE_BODY_LIMIT_BYTES, 16 * 1024);
        assert_eq!(MAX_POLICY_FILE_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn resolve_semaphore_zero_disables_the_cap() {
        assert!(resolve_semaphore(0).is_none());
        let Some(semaphore) = resolve_semaphore(3) else {
            unreachable!("positive limit should create a semaphore");
        };
        assert_eq!(semaphore.available_permits(), 3);
    }

    #[test]
    fn args_zeroize_sensitive_clears_runtime_secret_fields() {
        let mut args = valid_args();

        args.zeroize_sensitive();

        assert!(args.client_id.is_none());
        assert!(args.client_secret.is_none());
        assert!(args.master_password.is_none());
        assert!(args.webhook_auth_token.is_none());
    }

    #[test]
    fn provider_config_rejects_insecure_remote_endpoint() {
        let mut args = valid_args();
        args.single_origin_url = Some("http://vault.example.test".to_string());

        let Some(error) = provider_from_args(&args).err() else {
            unreachable!("insecure remote endpoint should fail");
        };
        let error = format!("{error:#}");

        assert!(
            error.contains("invalid single-origin Bitwarden/Vaultwarden endpoint configuration")
        );
        assert!(!error.contains("super-secret-api-key"));
        assert!(!error.contains("super-secret-master-password"));
    }

    #[test]
    fn provider_config_accepts_split_bitwarden_endpoints() {
        let mut args = valid_args();
        args.single_origin_url = None;
        args.identity_url = Some("http://127.0.0.1:8081".to_string());
        args.api_url = Some("http://127.0.0.1:8082".to_string());

        if let Err(error) = provider_from_args(&args) {
            unreachable!("local split endpoints should be accepted: {error:#}");
        }
    }

    #[test]
    fn provider_config_rejects_partial_split_endpoints() {
        let mut args = valid_args();
        args.single_origin_url = None;
        args.identity_url = Some("http://127.0.0.1:8081".to_string());

        let Some(error) = provider_from_args(&args).err() else {
            unreachable!("partial split endpoint configuration should fail");
        };

        assert!(error
            .to_string()
            .contains("both BWESO_IDENTITY_URL and BWESO_API_URL"));
    }

    #[test]
    fn provider_config_rejects_mixed_endpoint_modes() {
        let mut args = valid_args();
        args.identity_url = Some("https://identity.bitwarden.com".to_string());
        args.api_url = Some("https://api.bitwarden.com".to_string());

        let Some(error) = provider_from_args(&args).err() else {
            unreachable!("mixed endpoint modes should fail");
        };

        assert!(error.to_string().contains("not both endpoint modes"));
    }

    #[test]
    fn provider_config_rejects_blank_credentials() {
        let mut args = valid_args();
        args.client_secret = Some(" ".to_string());

        let Some(error) = provider_from_args(&args).err() else {
            unreachable!("blank client secret should fail");
        };

        assert!(error
            .to_string()
            .contains("client_secret must not be empty"));
    }

    #[test]
    fn provider_config_accepts_credentials_from_files() -> TestResult {
        let dir = std::env::temp_dir().join(format!("bweso-provider-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let client_id_file = dir.join("client-id");
        let client_secret_file = dir.join("client-secret");
        let master_password_file = dir.join("master-password");
        std::fs::write(&client_id_file, "user.fixture\n")?;
        std::fs::write(&client_secret_file, "super-secret-api-key\n")?;
        std::fs::write(&master_password_file, "super-secret-master-password\n")?;

        let mut args = valid_args();
        args.client_id = None;
        args.client_id_file = Some(client_id_file);
        args.client_secret = None;
        args.client_secret_file = Some(client_secret_file);
        args.master_password = None;
        args.master_password_file = Some(master_password_file);

        let result = provider_from_args(&args);
        std::fs::remove_dir_all(&dir)?;

        if let Err(error) = result {
            unreachable!("credential files should be accepted: {error:#}");
        }
        Ok(())
    }

    #[test]
    fn webhook_auth_requires_token_unless_explicitly_disabled() {
        let mut args = valid_args();
        args.webhook_auth_token = None;

        let Some(error) = WebhookAuth::from_args(&args).err() else {
            unreachable!("missing webhook token should fail");
        };
        assert!(error.to_string().contains("BWESO_WEBHOOK_AUTH_TOKEN"));

        args.insecure_allow_unauthenticated = true;
        if let Err(error) = WebhookAuth::from_args(&args) {
            unreachable!("explicit insecure local mode should be accepted: {error:#}");
        }
    }

    #[test]
    fn webhook_auth_rejects_blank_token() {
        let mut args = valid_args();
        args.webhook_auth_token = Some(" ".to_string());

        let Some(error) = WebhookAuth::from_args(&args).err() else {
            unreachable!("blank webhook token should fail");
        };
        assert!(error
            .to_string()
            .contains("webhook_auth_token must not be empty"));
    }

    #[test]
    fn selector_policy_allows_everything_with_explicit_allow_all() -> TestResult {
        let policy = SelectorPolicy::from_args(&valid_args())?;

        assert!(policy.allows("id:item-a"));
        assert!(policy.allows("name:anything"));
        Ok(())
    }

    #[test]
    fn selector_policy_requires_allow_list_or_explicit_allow_all() {
        let mut args = valid_args();
        args.allow_all_selectors = false;

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("unconfigured selector policy should fail without explicit allow-all");
        };

        assert!(error.to_string().contains("BWESO_ALLOW_ALL_SELECTORS"));
    }

    #[test]
    fn selector_policy_rejects_allow_all_with_allow_list() {
        let mut args = valid_args();
        args.allow_all_selectors = true;
        args.allowed_keys = vec!["id:item-a".to_string()];

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("allow-all and allow-list should be mutually exclusive");
        };

        assert!(error.to_string().contains("not both"));
    }

    #[test]
    fn selector_policy_allows_exact_keys_and_prefixes() -> TestResult {
        let mut args = valid_args();
        args.allowed_keys = vec!["id:item-a".to_string()];
        args.allowed_key_prefixes = vec!["id:team-a/".to_string()];
        args.allow_all_selectors = false;
        let policy = SelectorPolicy::from_args(&args)?;

        assert!(policy.allows("id:item-a"));
        assert!(policy.allows("id:team-a/database"));
        assert!(!policy.allows("id:item-b"));
        assert!(!policy.allows("name:item-a"));
        Ok(())
    }

    #[test]
    fn policy_rules_counts_active_allow_list_entries() {
        let allow_list = PolicyRules::AllowList {
            allowed_keys: vec!["id:item-a".to_string(), "id:item-b".to_string()],
            allowed_key_prefixes: vec!["id:team-a/".to_string()],
        };

        assert_eq!(allow_list.counts(), (2, 1));
        assert_eq!(PolicyRules::AllowAll.counts(), (0, 0));
    }

    #[test]
    fn selector_policy_rejects_blank_entries() {
        let mut args = valid_args();
        args.allowed_keys = vec!["id:item-a".to_string(), " ".to_string()];
        args.allow_all_selectors = false;

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("blank policy entry should fail");
        };

        assert!(error.to_string().contains("allowed_key must not be empty"));
    }

    /// Unique temp file that removes itself on drop, so a panicking assertion
    /// never leaks a file into the temp dir.
    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bweso-policy-{}-{}-{tag}.txt",
                std::process::id(),
                unique
            ));
            Self { path }
        }

        fn write(&self, contents: &str) -> std::io::Result<()> {
            fs::write(&self.path, contents)
        }

        fn remove(&self) {
            fs::remove_file(&self.path).ok();
        }

        fn path(&self) -> PathBuf {
            self.path.clone()
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            fs::remove_file(&self.path).ok();
        }
    }

    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUSlo2f67ehKubY3NrE56UeO6UtEgwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNYndlc28tdGVzdC1jYTAeFw0yNjA1MTcxMjAyMzRaFw0y
NjA1MTgxMjAyMzRaMBgxFjAUBgNVBAMMDWJ3ZXNvLXRlc3QtY2EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9TjwVnieLgFTIsMdx9iM/wiE0792d3VHV
u9/rC0d59O0yWHtlFAsRT4qKQgIVw2TaAp3IrkykmhPlxoX/gbWSsxTnpmBeVG2D
y8FOmLnkb5u+mA238/BDYHvitxflQwSd4L/JNVi913nbYgTtmDqWGpWP643PlPXm
NryDkHuzauJM0q5m7r+Lo1rTS/WXbuc4ArEYQvRowYEteehlo622pfGSJXPdKHaM
Zgzol5l0xClWMeWskIaZOKlksPXAT1/n7hvBQQUr28+w+n/xXu/p4/89jEqRLx5w
jSnahgc93orpO3UWRDibypg0MEVcOsAPCk9BGpZDZeKPCDFeNVORAgMBAAGjUzBR
MB0GA1UdDgQWBBQhSR0/X5F8Xv6ctTjZIdciJxKOFDAfBgNVHSMEGDAWgBQhSR0/
X5F8Xv6ctTjZIdciJxKOFDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQCgEju0Nv7tdND/QBV/2P2kg3QTpuwTJp3Ik1IrlvNWSfp8RLIR0Dio6VLx
tMvljLF7PI0x6rKUGSxHjrD+pFi8tJE7jQVUcKMsvylZWXBPot5t140ATOlDa3Ds
GRhGSvWALmr7f4FRONCi/+mPoYLShQnlMjpsyQCFD/krnaflxEYT8jaaehio8XlF
Ss8xqydle1hGxqAcjwm5U2+WNdWrgbgEN8lkMADBu4Sq8lG4RxFPehXsFqc1ETNc
cUZqSvmpFg+x1PNHCg8Fh1WuysQRSoLFPW5szcmj+P3Q/v/L7PuEarqvluQzz4vf
frW69DSxg6/fcNRyvdTH+twvVnzH
-----END CERTIFICATE-----
";

    #[test]
    fn ca_bundle_loader_accepts_valid_pem_bundle() -> TestResult {
        let file = TempPolicyFile::new("ca-valid");
        file.write(TEST_CA_PEM)?;

        let certificates = load_extra_root_certificates(Some(&file.path()))?;

        assert_eq!(certificates.len(), 1);
        Ok(())
    }

    #[test]
    fn ca_bundle_loader_rejects_empty_pem_bundle() -> TestResult {
        let file = TempPolicyFile::new("ca-empty");
        file.write("")?;

        let Some(error) = load_extra_root_certificates(Some(&file.path())).err() else {
            unreachable!("empty CA bundle should fail");
        };

        assert!(error.to_string().contains("contained no PEM certificates"));
        Ok(())
    }

    #[test]
    fn ca_bundle_loader_rejects_invalid_pem_bundle() -> TestResult {
        let file = TempPolicyFile::new("ca-invalid");
        file.write("not a certificate")?;

        let Some(error) = load_extra_root_certificates(Some(&file.path())).err() else {
            unreachable!("invalid CA bundle should fail");
        };

        assert!(error.to_string().contains("PEM certificates"));
        Ok(())
    }

    #[test]
    fn selector_policy_reads_and_unions_file_entries() -> TestResult {
        let file = TempPolicyFile::new("union");
        file.write("# managed by GitOps\nid:from-file\n\n  id:also-file  ,id:csv-file\n")?;
        let mut args = valid_args();
        args.allowed_keys = vec!["id:from-inline".to_string()];
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;

        assert!(policy.allows("id:from-inline"));
        assert!(policy.allows("id:from-file"));
        assert!(policy.allows("id:also-file"));
        assert!(policy.allows("id:csv-file"));
        assert!(!policy.allows("id:not-listed"));
        Ok(())
    }

    #[test]
    fn selector_policy_reload_picks_up_file_changes_without_restart() -> TestResult {
        let file = TempPolicyFile::new("reload");
        file.write("id:initial\n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        assert!(policy.allows("id:initial"));
        assert!(!policy.allows("id:added-later"));

        // Simulate a ConfigMap update landing on the mounted file.
        file.write("id:initial\nid:added-later\n")?;
        assert!(policy.reload()?, "policy should report a change");
        assert!(policy.allows("id:added-later"));
        assert!(policy.allows("id:initial"));

        // A reload with no on-disk change reports no change.
        assert!(!policy.reload()?, "unchanged file should not swap");
        Ok(())
    }

    #[test]
    fn selector_policy_from_args_fails_when_file_missing() {
        let missing = TempPolicyFile::new("missing");
        let mut args = valid_args();
        args.allowed_keys_file = Some(missing.path());
        args.allow_all_selectors = false;

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("missing policy file should fail at startup");
        };

        assert!(error
            .to_string()
            .contains("failed to stat allowed_key_file"));
    }

    #[test]
    fn selector_policy_reload_keeps_previous_on_invalid_file() -> TestResult {
        let file = TempPolicyFile::new("invalid");
        file.write("id:good\n")?;
        let mut args = valid_args();
        args.allowed_key_prefixes_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        assert!(policy.allows("id:good/db"));

        // Removing the file makes the next reload error; the live policy must
        // keep serving the last good rules instead of failing open or closed.
        file.remove();
        assert!(policy.reload().is_err());
        assert!(policy.allows("id:good/db"));
        Ok(())
    }

    #[test]
    fn selector_policy_has_no_file_when_unconfigured() -> TestResult {
        let policy = SelectorPolicy::from_args(&valid_args())?;
        assert!(!policy.sources.has_file());
        Ok(())
    }

    #[test]
    fn policy_reload_not_spawned_without_file_source() -> TestResult {
        let policy = SelectorPolicy::from_args(&valid_args())?;
        let metrics = Arc::new(AppMetrics::new());
        let handle = spawn_policy_reload(policy, Lifecycle::default(), metrics, 30);

        assert!(handle.is_none());
        Ok(())
    }

    #[test]
    fn selector_policy_from_args_fails_when_configured_file_is_empty() -> TestResult {
        let file = TempPolicyFile::new("empty");
        // Comment- and blank-only: a configured allow-list that evaluates to
        // zero entries must NOT fall back to allow-all.
        file.write("# only comments\n\n   \n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let result = SelectorPolicy::from_args(&args);

        let Some(error) = result.err() else {
            unreachable!("configured-empty policy file must fail fast at startup");
        };
        assert!(error
            .to_string()
            .contains("refusing to fall back to allow-all"));
        Ok(())
    }

    #[test]
    fn selector_policy_reload_rejects_emptying_a_file() -> TestResult {
        let file = TempPolicyFile::new("emptied");
        file.write("id:restricted\n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        assert!(policy.allows("id:restricted"));
        assert!(!policy.allows("id:anything-else"));

        // Simulate a bad GitOps render that empties the ConfigMap. The reload
        // must error (keeping last-known-good), NOT swap in an allow-all.
        file.write("# emptied by mistake\n")?;
        assert!(policy.reload().is_err());
        assert!(policy.allows("id:restricted"));
        assert!(
            !policy.allows("id:anything-else"),
            "an emptied policy file must not widen to allow-all"
        );
        Ok(())
    }

    #[test]
    fn selector_policy_rejects_oversized_file() -> TestResult {
        let file = TempPolicyFile::new("oversize");
        let over = usize::try_from(MAX_POLICY_FILE_BYTES)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let mut content = String::from("id:ok\n");
        content.push_str(&"#".repeat(over));
        file.write(&content)?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("oversized policy file must be rejected");
        };
        assert!(error.to_string().contains("exceeding the"));
        Ok(())
    }

    #[test]
    fn selector_policy_accepts_file_at_exact_size_limit() -> TestResult {
        let file = TempPolicyFile::new("exact-size");
        let mut content = String::from("id:ok\n");
        let target_len = 4 * 1024 * 1024;
        content.push_str(&"#".repeat(target_len - content.len()));
        file.write(&content)?;

        let entries = read_policy_file(&file.path(), "allowed_key")?;

        assert_eq!(entries, vec!["id:ok".to_string()]);
        Ok(())
    }

    #[test]
    fn policy_reload_disabled_when_interval_zero() -> TestResult {
        let file = TempPolicyFile::new("interval0");
        file.write("id:only\n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        let metrics = Arc::new(AppMetrics::new());
        let handle = spawn_policy_reload(policy, Lifecycle::default(), metrics, 0);

        assert!(
            handle.is_none(),
            "interval 0 must not spawn a reload task (policy stays as evaluated at startup)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn policy_reload_task_stops_promptly_on_shutdown() -> TestResult {
        let file = TempPolicyFile::new("shutdown");
        file.write("id:initial\n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        let lifecycle = Lifecycle::default();
        // Huge interval: the task is parked on the tick. It must still exit
        // because of the shutdown signal, not the timer.
        let metrics = Arc::new(AppMetrics::new());
        let Some(handle) = spawn_policy_reload(policy, lifecycle.clone(), metrics, 3_600) else {
            unreachable!("a file source is configured, so a task must spawn");
        };

        lifecycle.mark_shutting_down();
        let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;

        let Ok(join_result) = joined else {
            unreachable!("reload task did not exit promptly on shutdown");
        };
        join_result?;
        Ok(())
    }

    #[tokio::test]
    async fn policy_reload_task_picks_up_changes_while_ready() -> TestResult {
        let file = TempPolicyFile::new("task-reload");
        file.write("id:initial\n")?;
        let mut args = valid_args();
        args.allowed_keys_file = Some(file.path());
        args.allow_all_selectors = false;

        let policy = SelectorPolicy::from_args(&args)?;
        let lifecycle = Lifecycle::default();
        let metrics = Arc::new(AppMetrics::new());
        let Some(handle) = spawn_policy_reload(policy.clone(), lifecycle.clone(), metrics, 1)
        else {
            unreachable!("a file source is configured, so a task must spawn");
        };

        file.write("id:updated\n")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if policy.allows("id:updated") {
                lifecycle.mark_shutting_down();
                let joined = tokio::time::timeout(Duration::from_secs(2), handle).await;
                let Ok(join_result) = joined else {
                    unreachable!("reload task did not exit promptly after test shutdown");
                };
                join_result?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        lifecycle.mark_shutting_down();
        handle.abort();
        unreachable!("policy reload task did not pick up file changes while ready");
    }

    #[test]
    fn public_error_messages_cover_all_error_classes() {
        let expected = [
            ("auth", "provider authentication failed"),
            ("validation", "invalid resolve request"),
            ("unsupported_version", "remoteRef.version is not supported"),
            (
                "policy_denied",
                "requested Bitwarden item is not allowed by provider policy",
            ),
            (
                "not_found",
                "requested Bitwarden item or property was not found",
            ),
            (
                "ambiguous_selector",
                "requested Bitwarden item name is ambiguous; use the item ID",
            ),
            (
                "unsupported_attachment",
                "Bitwarden attachment extraction is not supported",
            ),
            (
                "unsupported_shared_item",
                "shared organization Bitwarden items are not supported",
            ),
            (
                "upstream_http",
                "Bitwarden-compatible upstream request failed",
            ),
            (
                "upstream_status",
                "Bitwarden-compatible upstream returned an error status",
            ),
            ("crypto", "failed to decrypt selected Bitwarden item"),
            ("key_derivation", "failed to unlock Bitwarden vault key"),
            (
                "kdf_parameters",
                "Bitwarden-compatible KDF parameters are unsupported",
            ),
            (
                "sync_payload",
                "Bitwarden-compatible sync payload is missing required unlock data",
            ),
            ("endpoint", "provider endpoint configuration is invalid"),
            (
                "overloaded",
                "provider is at concurrency limit; retry shortly",
            ),
            ("unknown", "provider request failed"),
        ];

        for (kind, message) in expected {
            assert_eq!(public_error_message(kind), message);
        }
    }

    #[test]
    fn provider_status_maps_unsupported_surfaces() {
        let attachment_error = BitwardenClientError::from(CipherError::UnsupportedAttachment);
        assert_eq!(
            provider_status_and_kind(&attachment_error),
            (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_attachment")
        );

        let shared_error = BitwardenClientError::from(BitwardenApiError::UnsupportedSharedItem);
        assert_eq!(
            provider_status_and_kind(&shared_error),
            (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_shared_item")
        );
    }

    #[test]
    fn healthcheck_accepts_successful_http_response() -> TestResult {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let handle = std::thread::spawn(move || -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "healthcheck did not connect to test server",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut request = [0_u8; 512];
            let len = stream.read(&mut request)?;
            let request = std::str::from_utf8(&request[..len])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            if !request.starts_with("GET /livez?ready=1 HTTP/1.1\r\n") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected healthcheck request: {request:?}"),
                ));
            }
            stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")?;
            Ok(())
        });

        run_healthcheck(&format!("http://{address}/livez?ready=1"))?;
        handle
            .join()
            .map_err(|_| "healthcheck test server panicked")??;
        Ok(())
    }

    #[test]
    fn healthcheck_rejects_non_successful_http_response() {
        let Some(error) =
            ensure_successful_healthcheck_response("HTTP/1.1 503 Service Unavailable\r\n\r\n")
                .err()
        else {
            unreachable!("non-2xx healthcheck response should fail");
        };

        assert!(error.to_string().contains("non-success status"));
    }

    #[test]
    fn healthcheck_rejects_non_http_urls() {
        let Some(error) = run_healthcheck("https://127.0.0.1:8080/livez").err() else {
            unreachable!("https healthcheck URL should fail");
        };

        assert!(error.to_string().contains("healthcheck URL must use http"));
    }

    #[tokio::test]
    async fn livez_and_readyz_return_no_content() -> TestResult {
        let app = test_app(Arc::new(StaticProvider));

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/livez").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn readyz_returns_unavailable_while_shutting_down() -> TestResult {
        let state = test_state(Arc::new(StaticProvider));
        state.lifecycle.mark_shutting_down();

        let response = build_router(state)
            .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_sheds_when_semaphore_is_exhausted() -> TestResult {
        let mut state = test_state(Arc::new(StaticProvider));
        state.resolve_semaphore = Some(Arc::new(tokio::sync::Semaphore::new(1)));
        let exhauster = state
            .resolve_semaphore
            .as_ref()
            .ok_or("semaphore should be configured")?
            .clone()
            .try_acquire_owned()?;

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("provider is at concurrency limit"));
        assert!(!body.contains("app/database"));
        assert!(!body.contains("DATABASE_URL"));
        drop(exhauster);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_returns_secret_document() -> TestResult {
        let response = test_app(Arc::new(StaticProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let document: SecretDocument = serde_json::from_slice(&body)?;

        assert_eq!(
            document.data.get("DATABASE_URL"),
            Some(&"resolved-secret".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn resolve_requires_bearer_token_when_configured() -> TestResult {
        let app = build_router(test_state_with_auth(
            Arc::new(StaticProvider),
            "expected-webhook-token",
        ));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer wrong-token")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer expected-webhook-token")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_authenticates_before_json_parsing() -> TestResult {
        let app = build_router(test_state_with_auth(
            Arc::new(StaticProvider),
            "expected-webhook-token",
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{not-json"))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("provider authentication failed"));
        assert!(!body.contains("not-json"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_invalid_json_after_authentication() -> TestResult {
        let response = test_app(Arc::new(StaticProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{not-json"))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("invalid resolve request"));
        assert!(!body.contains("not-json"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_missing_json_content_type() -> TestResult {
        let response = test_app(Arc::new(StaticProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("invalid resolve request"));
        assert!(!body.contains("app/database"));
        assert!(!body.contains("DATABASE_URL"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_oversized_body_without_leaking_content() -> TestResult {
        let oversize = format!(
            r#"{{"remoteRef":{{"key":"{}","property":"DATABASE_URL"}}}}"#,
            "x".repeat(RESOLVE_BODY_LIMIT_BYTES)
        );
        let app = test_app(Arc::new(StaticProvider));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(oversize))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("invalid resolve request"));
        assert!(!body.contains("DATABASE_URL"));

        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
            .await?;
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains(
            "bweso_resolve_requests_total{outcome=\"error\",error_kind=\"validation\",status=\"413\"} 1"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn metrics_exports_redacted_http_and_resolve_series() -> TestResult {
        let app = test_app(Arc::new(StaticProvider));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE))
        );

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;

        assert!(body.contains("bweso_build_info{version=\""));
        assert!(body.contains("bweso_ready 1"));
        assert!(body.contains("# TYPE bweso_http_requests_total counter"));
        assert!(body.contains(
            "bweso_http_requests_total{method=\"POST\",route=\"/v1/resolve\",status=\"200\"} 1"
        ));
        assert!(body.contains("# TYPE bweso_resolve_requests_total counter"));
        assert!(body.contains(
            "bweso_resolve_requests_total{outcome=\"success\",error_kind=\"none\",status=\"200\"} 1"
        ));
        assert!(body.contains("bweso_cache_hits_total 2"));
        assert!(body.contains("bweso_cache_refreshes_total{outcome=\"success\"} 1"));
        assert!(body.contains("bweso_cache_last_success_timestamp_seconds 1700000000"));
        assert!(body.contains("bweso_cache_last_success_age_seconds 5"));
        assert!(!body.contains("app/database"));
        assert!(!body.contains("DATABASE_URL"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_blank_remote_key() -> TestResult {
        let response = test_app(Arc::new(StaticProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"remoteRef":{"key":" "}}"#))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_unsupported_remote_ref_version() -> TestResult {
        let response = test_app(Arc::new(StaticProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL","version":"42"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("remoteRef.version is not supported"));
        assert!(!body.contains("app/database"));
        assert!(!body.contains("DATABASE_URL"));
        assert!(!body.contains("42"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_rejects_selector_denied_by_policy_without_leaking_key() -> TestResult {
        let mut state = test_state(Arc::new(StaticProvider));
        state.selector_policy = SelectorPolicy::from_rules(
            PolicyRules::AllowList {
                allowed_keys: vec!["id:allowed".to_string()],
                allowed_key_prefixes: Vec::new(),
            },
            PolicySources::default(),
        );
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"id:denied","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("requested Bitwarden item is not allowed"));
        assert!(!body.contains("id:denied"));
        assert!(!body.contains("DATABASE_URL"));

        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
            .await?;
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains(
            "bweso_resolve_requests_total{outcome=\"error\",error_kind=\"policy_denied\",status=\"403\"} 1"
        ));
        assert!(!body.contains("id:denied"));
        assert!(!body.contains("DATABASE_URL"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_error_body_redacts_selector() -> TestResult {
        let response = test_app(Arc::new(MissingPropertyProvider))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/resolve")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"remoteRef":{"key":"name:app/database","property":"DATABASE_URL"}}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("requested Bitwarden item or property was not found"));
        assert!(!body.contains("app/database"));
        assert!(!body.contains("DATABASE_URL"));
        Ok(())
    }
}
