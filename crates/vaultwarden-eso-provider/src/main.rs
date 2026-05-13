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
        default_value = "bitwarden-eso-provider"
    )]
    device_identifier: String,
    #[arg(
        long,
        env = "BWESO_DEVICE_NAME",
        default_value = "Bitwarden ESO Provider"
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
    #[arg(long, env = "BWESO_HTTP_CONNECT_TIMEOUT_SECONDS", default_value_t = 5)]
    http_connect_timeout_seconds: u64,
    #[arg(long, env = "BWESO_HTTP_REQUEST_TIMEOUT_SECONDS", default_value_t = 25)]
    http_request_timeout_seconds: u64,
    /// PEM-encoded CA bundle to trust in addition to the system store. Use for
    /// Vaultwarden installs on a private CA.
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
    let args = Args::parse();
    if let Some(url) = args.healthcheck_url.as_deref() {
        run_healthcheck(url)?;
        return Ok(());
    }

    let listen = args.listen;
    let lifecycle = Lifecycle::default();

    let resolve_semaphore = if args.resolve_concurrency_limit > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(
            args.resolve_concurrency_limit as usize,
        )))
    } else {
        None
    };
    let state = AppState {
        provider: provider_from_args(&args)?,
        selector_policy: SelectorPolicy::from_args(&args)?,
        auth: WebhookAuth::from_args(&args)?,
        metrics: Arc::new(AppMetrics::new()),
        lifecycle: lifecycle.clone(),
        resolve_semaphore,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(address = %listen, "starting ESO webhook provider");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(lifecycle))
        .await?;

    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SelectorPolicy {
    allowed_keys: Arc<Vec<String>>,
    allowed_key_prefixes: Arc<Vec<String>>,
}

impl SelectorPolicy {
    fn from_args(args: &Args) -> anyhow::Result<Self> {
        let allowed_keys = normalize_policy_entries(&args.allowed_keys, "allowed_key")?;
        let allowed_key_prefixes =
            normalize_policy_entries(&args.allowed_key_prefixes, "allowed_key_prefix")?;

        Ok(Self {
            allowed_keys: Arc::new(allowed_keys),
            allowed_key_prefixes: Arc::new(allowed_key_prefixes),
        })
    }

    fn allows(&self, key: &str) -> bool {
        if self.allowed_keys.is_empty() && self.allowed_key_prefixes.is_empty() {
            return true;
        }

        self.allowed_keys
            .iter()
            .any(|allowed_key| allowed_key == key)
            || self
                .allowed_key_prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix))
    }
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
        match (
            token.as_deref(),
            args.insecure_allow_unauthenticated,
        ) {
            (Some(_), true) => bail!(
                "configure either BWESO_WEBHOOK_AUTH_TOKEN or BWESO_INSECURE_ALLOW_UNAUTHENTICATED=true, not both"
            ),
            (Some(token), false) => Ok(Self::Required(Arc::new(token.to_string().into()))),
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
            selector_policy: SelectorPolicy::default(),
            auth: WebhookAuth::DisabledInsecure,
            metrics: Arc::new(AppMetrics::new()),
            lifecycle: Lifecycle::default(),
            resolve_semaphore: Some(Arc::new(tokio::sync::Semaphore::new(16))),
        }
    }

    fn test_state_with_auth(provider: Arc<dyn BitwardenProvider>, token: &str) -> AppState {
        AppState {
            provider,
            selector_policy: SelectorPolicy::default(),
            auth: WebhookAuth::Required(Arc::new(token.to_string().into())),
            metrics: Arc::new(AppMetrics::new()),
            lifecycle: Lifecycle::default(),
            resolve_semaphore: Some(Arc::new(tokio::sync::Semaphore::new(16))),
        }
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
    fn selector_policy_allows_everything_when_unconfigured() -> TestResult {
        let policy = SelectorPolicy::from_args(&valid_args())?;

        assert!(policy.allows("id:item-a"));
        assert!(policy.allows("name:anything"));
        Ok(())
    }

    #[test]
    fn selector_policy_allows_exact_keys_and_prefixes() -> TestResult {
        let mut args = valid_args();
        args.allowed_keys = vec!["id:item-a".to_string()];
        args.allowed_key_prefixes = vec!["id:team-a/".to_string()];
        let policy = SelectorPolicy::from_args(&args)?;

        assert!(policy.allows("id:item-a"));
        assert!(policy.allows("id:team-a/database"));
        assert!(!policy.allows("id:item-b"));
        assert!(!policy.allows("name:item-a"));
        Ok(())
    }

    #[test]
    fn selector_policy_rejects_blank_entries() {
        let mut args = valid_args();
        args.allowed_keys = vec!["id:item-a".to_string(), " ".to_string()];

        let Some(error) = SelectorPolicy::from_args(&args).err() else {
            unreachable!("blank policy entry should fail");
        };

        assert!(error.to_string().contains("allowed_key must not be empty"));
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
            let _ = stream.read(&mut request)?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")?;
            Ok(())
        });

        run_healthcheck(&format!("http://{address}/livez"))?;
        handle
            .join()
            .map_err(|_| "healthcheck test server panicked")??;
        Ok(())
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
        state.selector_policy = SelectorPolicy {
            allowed_keys: Arc::new(vec!["id:allowed".to_string()]),
            allowed_key_prefixes: Arc::new(Vec::new()),
        };
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
