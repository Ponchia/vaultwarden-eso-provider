//! Bitwarden-compatible HTTP API client and sync resolver.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bweso_core::SecretDocument;
use reqwest::{Client as HttpClient, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    AuthenticatedSymmetricKey, BitwardenAuth, BitwardenClientError, BitwardenEndpoint,
    BitwardenEndpoints, BitwardenProvider, BitwardenSelector, DecryptedCipher, EncryptedCipher,
    KdfConfig, MasterPasswordUnlockData,
};

const BITWARDEN_CLIENT_VERSION: &str = "2025.12.0";
const DEFAULT_DEVICE_TYPE_SERVER: u8 = 22;
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
const TOKEN_EXPIRY_REFRESH_SKEW: Duration = Duration::from_secs(30);

/// Bitwarden-compatible HTTP API client.
#[derive(Clone)]
pub struct BitwardenApiClient {
    endpoints: BitwardenEndpoints,
    auth: BitwardenAuth,
    http: HttpClient,
    device: BitwardenDevice,
    cache_config: BitwardenCacheConfig,
    cache: Arc<Mutex<Option<CachedVault>>>,
    refresh_lock: Arc<Mutex<()>>,
    metrics: Arc<CacheMetricState>,
}

impl BitwardenApiClient {
    /// Build an API client from a fully-populated options struct.
    ///
    /// Use [`BitwardenApiClientOptions::single_origin`] for Vaultwarden /
    /// self-hosted Bitwarden, or [`BitwardenApiClientOptions::split`] for
    /// Bitwarden Cloud and other split identity/API deployments.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn with_options(options: BitwardenApiClientOptions) -> Result<Self, BitwardenApiError> {
        let BitwardenApiClientOptions {
            endpoints,
            auth,
            device,
            cache_config,
            http_config,
        } = options;

        let mut builder = HttpClient::builder()
            .user_agent("vaultwarden-eso-provider")
            .connect_timeout(http_config.connect_timeout)
            .timeout(http_config.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        for certificate in http_config.extra_root_certificates {
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build()?;

        Ok(Self {
            endpoints,
            auth,
            http,
            device,
            cache_config,
            cache: Arc::new(Mutex::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
            metrics: Arc::new(CacheMetricState::default()),
        })
    }

    /// Fetch the password prelogin KDF configuration for an email address.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failures, non-success status codes,
    /// malformed responses, or KDF downgrade/resource validation failures.
    pub async fn prelogin(&self, email: &str) -> Result<KdfConfig, BitwardenClientError> {
        let url = Self::endpoint_url(
            self.endpoints.identity_url(),
            &["accounts", "prelogin", "password"],
        )?;
        let response = self
            .http
            .post(url)
            .bitwarden_headers()
            .json(&PreloginRequest { email })
            .send()
            .await
            .map_err(BitwardenApiError::from)?;
        let response = decode_json::<PreloginResponse>(response, "prelogin").await?;

        Ok(response.try_into()?)
    }

    /// Authenticate with the configured user API key and unlock the user key.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication, response parsing, or local unlock
    /// fails.
    pub async fn login_with_api_key(&self) -> Result<BitwardenSession, BitwardenClientError> {
        let url = Self::endpoint_url(self.endpoints.identity_url(), &["connect", "token"])?;
        let scope = if self.auth.client_id.starts_with("organization.") {
            "api.organization"
        } else {
            "api"
        };
        let request = ApiKeyTokenRequest {
            grant_type: "client_credentials",
            scope,
            client_id: &self.auth.client_id,
            client_secret: self.auth.client_secret.expose_secret(),
            device_identifier: &self.device.identifier,
            device_name: &self.device.name,
            device_type: self.device.device_type,
        };

        let response = self
            .http
            .post(url)
            .bitwarden_headers()
            .form(&request)
            .send()
            .await
            .map_err(BitwardenApiError::from)?;
        let response = decode_json::<TokenResponse>(response, "token").await?;

        self.unlock_session(response)
    }

    /// Fetch a full vault sync response with an authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error when the sync request fails or the response cannot be
    /// decoded.
    pub async fn sync(
        &self,
        session: &BitwardenSession,
    ) -> Result<SyncResponse, BitwardenClientError> {
        let mut url = Self::endpoint_url(self.endpoints.api_url(), &["sync"])?;
        url.query_pairs_mut().append_pair("excludeDomains", "true");

        let response = self
            .http
            .get(url)
            .bitwarden_headers()
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await
            .map_err(BitwardenApiError::from)?;

        Ok(decode_json::<SyncResponse>(response, "sync").await?)
    }

    fn unlock_session(
        &self,
        response: TokenResponse,
    ) -> Result<BitwardenSession, BitwardenClientError> {
        let unlock = response
            .user_decryption_options
            .and_then(|options| options.master_password_unlock)
            .ok_or(BitwardenApiError::MissingMasterPasswordUnlock)?;
        let unlock_data = MasterPasswordUnlockData::try_from(unlock)?;
        let user_key = unlock_data.unlock_user_key(self.auth.master_password.expose_secret())?;

        Ok(BitwardenSession {
            access_token: response.access_token.into(),
            expires_in: response.expires_in,
            token_type: response.token_type.unwrap_or_else(|| "Bearer".to_string()),
            user_key,
        })
    }

    async fn resolve_with_cached_sync(
        &self,
        selector: BitwardenSelector,
    ) -> Result<SecretDocument, BitwardenClientError> {
        self.ensure_fresh_cached_sync().await?;

        let cache = self.cache.lock().await;
        let cached = cache.as_ref().ok_or(BitwardenApiError::MissingCachedSync)?;
        let cipher =
            Self::resolve_synced_cipher(&cached.sync, &cached.session.user_key, &selector.key)?;
        if cipher.organization_id.is_some() {
            return Err(BitwardenApiError::UnsupportedSharedItem.into());
        }

        if let Some(property) = selector.property {
            let value = cipher.extract_property(&property)?;
            let mut document = SecretDocument::single("value", value.clone());
            if property != "value" {
                document.data.insert(property, value);
            }
            return Ok(document);
        }

        Ok(cipher.to_secret_document()?)
    }

    async fn ensure_fresh_cached_sync(&self) -> Result<(), BitwardenClientError> {
        if self.has_fresh_cache().await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let _guard = self.refresh_lock.lock().await;
        if self.has_fresh_cache().await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let refreshed = match self.fetch_vault().await {
            Ok(refreshed) => {
                self.metrics
                    .refresh_successes
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics.record_last_success_now();
                refreshed
            }
            Err(error) => {
                self.metrics
                    .refresh_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        let mut cache = self.cache.lock().await;
        *cache = Some(refreshed);
        Ok(())
    }

    async fn has_fresh_cache(&self) -> bool {
        self.cache
            .lock()
            .await
            .as_ref()
            .is_some_and(|cached| cached.is_fresh(self.cache_config.ttl))
    }

    async fn fetch_vault(&self) -> Result<CachedVault, BitwardenClientError> {
        let session = self.login_with_api_key().await?;
        let sync = self.sync(&session).await?;

        Ok(CachedVault::new(session, sync, Instant::now()))
    }

    fn resolve_synced_cipher(
        sync: &SyncResponse,
        user_key: &AuthenticatedSymmetricKey,
        key: &str,
    ) -> Result<DecryptedCipher, BitwardenClientError> {
        match CipherLookup::from_key(key)? {
            CipherLookup::Id(id) => Self::resolve_synced_cipher_by_id(sync, user_key, id),
            CipherLookup::Name(name) => Self::resolve_synced_cipher_by_name(sync, user_key, name),
        }
    }

    fn resolve_synced_cipher_by_id(
        sync: &SyncResponse,
        user_key: &AuthenticatedSymmetricKey,
        id: &str,
    ) -> Result<DecryptedCipher, BitwardenClientError> {
        let cipher = Self::find_cipher_by_id(sync, id)?;
        if cipher.organization_id.is_some() {
            return Err(BitwardenApiError::UnsupportedSharedItem.into());
        }
        cipher.decrypt(user_key).map_err(BitwardenClientError::from)
    }

    fn find_cipher_by_id<'a>(
        sync: &'a SyncResponse,
        id: &str,
    ) -> Result<&'a EncryptedCipher, BitwardenApiError> {
        sync.ciphers
            .iter()
            .find(|cipher| cipher.id == id)
            .ok_or(BitwardenApiError::CipherNotFound)
    }

    fn resolve_synced_cipher_by_name(
        sync: &SyncResponse,
        user_key: &AuthenticatedSymmetricKey,
        name: &str,
    ) -> Result<DecryptedCipher, BitwardenClientError> {
        let mut name_match = None;

        for cipher in &sync.ciphers {
            if let Ok(decrypted) = cipher.decrypt(user_key) {
                if decrypted.name.as_deref() == Some(name) {
                    if cipher.organization_id.is_some() {
                        return Err(BitwardenApiError::UnsupportedSharedItem.into());
                    }
                    if name_match.is_some() {
                        return Err(BitwardenApiError::AmbiguousCipherName.into());
                    }
                    name_match = Some(decrypted);
                }
            }
        }

        name_match.ok_or_else(|| BitwardenApiError::CipherNotFound.into())
    }

    fn endpoint_url(base_url: &Url, segments: &[&str]) -> Result<Url, BitwardenApiError> {
        let mut url = base_url.clone();
        url.set_query(None);
        url.set_fragment(None);

        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| BitwardenApiError::InvalidBaseUrl)?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }

        Ok(url)
    }
}

#[async_trait]
impl BitwardenProvider for BitwardenApiClient {
    async fn resolve(
        &self,
        selector: BitwardenSelector,
    ) -> Result<SecretDocument, BitwardenClientError> {
        self.resolve_with_cached_sync(selector).await
    }

    fn cache_metrics(&self) -> Option<BitwardenCacheMetrics> {
        Some(self.metrics.snapshot())
    }
}

enum CipherLookup<'a> {
    Id(&'a str),
    Name(&'a str),
}

impl<'a> CipherLookup<'a> {
    fn from_key(key: &'a str) -> Result<Self, BitwardenClientError> {
        if let Some(id) = key.strip_prefix("id:") {
            return Ok(Self::Id(id));
        }
        if let Some(name) = key.strip_prefix("name:") {
            return Ok(Self::Name(name));
        }
        Err(BitwardenClientError::UnprefixedSelectorKey)
    }
}

/// Construction options for [`BitwardenApiClient`].
///
/// Build the struct directly or via the [`BitwardenApiClientOptions::single_origin`]
/// and [`BitwardenApiClientOptions::split`] helpers, then hand it to
/// [`BitwardenApiClient::with_options`].
pub struct BitwardenApiClientOptions {
    /// Identity and API endpoint bases.
    pub endpoints: BitwardenEndpoints,
    /// User API-key credentials and master password.
    pub auth: BitwardenAuth,
    /// Stable device identity sent during API-key login.
    pub device: BitwardenDevice,
    /// Vault sync cache settings.
    pub cache_config: BitwardenCacheConfig,
    /// HTTP transport timeouts.
    pub http_config: BitwardenHttpConfig,
}

impl BitwardenApiClientOptions {
    /// Options for a single-origin Vaultwarden or self-hosted Bitwarden server.
    #[must_use]
    pub fn single_origin(endpoint: BitwardenEndpoint, auth: BitwardenAuth) -> Self {
        Self {
            endpoints: BitwardenEndpoints::from_single_origin(endpoint),
            auth,
            device: BitwardenDevice::default(),
            cache_config: BitwardenCacheConfig::default(),
            http_config: BitwardenHttpConfig::default(),
        }
    }

    /// Options for split identity / API endpoints (Bitwarden Cloud).
    #[must_use]
    pub fn split(endpoints: BitwardenEndpoints, auth: BitwardenAuth) -> Self {
        Self {
            endpoints,
            auth,
            device: BitwardenDevice::default(),
            cache_config: BitwardenCacheConfig::default(),
            http_config: BitwardenHttpConfig::default(),
        }
    }

    /// Override the device identity.
    #[must_use]
    pub fn with_device(mut self, device: BitwardenDevice) -> Self {
        self.device = device;
        self
    }

    /// Override the sync cache config.
    #[must_use]
    pub fn with_cache_config(mut self, cache_config: BitwardenCacheConfig) -> Self {
        self.cache_config = cache_config;
        self
    }

    /// Override the HTTP transport config.
    #[must_use]
    pub fn with_http_config(mut self, http_config: BitwardenHttpConfig) -> Self {
        self.http_config = http_config;
        self
    }
}

/// In-memory cache settings for the API provider.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BitwardenCacheConfig {
    /// Maximum age for the cached unlocked user key plus encrypted sync
    /// response. A zero duration disables reuse across requests.
    pub ttl: Duration,
}

impl BitwardenCacheConfig {
    /// Build cache settings with an explicit TTL.
    #[must_use]
    pub const fn new(ttl: Duration) -> Self {
        Self { ttl }
    }

    /// Disable cache reuse across requests.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            ttl: Duration::ZERO,
        }
    }
}

impl Default for BitwardenCacheConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

/// HTTP transport settings for the Bitwarden-compatible API client.
#[derive(Debug, Clone)]
pub struct BitwardenHttpConfig {
    connect_timeout: Duration,
    request_timeout: Duration,
    extra_root_certificates: Vec<reqwest::Certificate>,
}

impl BitwardenHttpConfig {
    /// Build HTTP settings with explicit connect and whole-request timeouts.
    #[must_use]
    pub fn new(connect_timeout: Duration, request_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            request_timeout,
            extra_root_certificates: Vec::new(),
        }
    }

    /// Add additional root certificates to the HTTP client's trust store.
    ///
    /// Certificates supplement, not replace, the system trust store. Use this
    /// for Vaultwarden installs on a private CA.
    #[must_use]
    pub fn with_extra_root_certificates(mut self, certificates: Vec<reqwest::Certificate>) -> Self {
        self.extra_root_certificates = certificates;
        self
    }
}

impl Default for BitwardenHttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_HTTP_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_HTTP_REQUEST_TIMEOUT,
            extra_root_certificates: Vec::new(),
        }
    }
}

/// Snapshot of sync cache metrics.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BitwardenCacheMetrics {
    /// Number of resolve requests served from a fresh sync cache.
    pub cache_hits: u64,
    /// Number of successful full vault refreshes.
    pub refresh_successes: u64,
    /// Number of failed full vault refresh attempts.
    pub refresh_failures: u64,
    /// Unix timestamp of the latest successful refresh.
    pub last_success_unix_seconds: Option<u64>,
    /// Age in seconds of the latest successful refresh at snapshot time.
    pub last_success_age_seconds: Option<u64>,
}

#[derive(Debug, Default)]
struct CacheMetricState {
    cache_hits: AtomicU64,
    refresh_successes: AtomicU64,
    refresh_failures: AtomicU64,
    last_success_unix_seconds: AtomicU64,
}

impl CacheMetricState {
    fn record_last_success_now(&self) {
        self.last_success_unix_seconds
            .store(unix_now_seconds(), Ordering::Relaxed);
    }

    fn snapshot(&self) -> BitwardenCacheMetrics {
        let last_success = self.last_success_unix_seconds.load(Ordering::Relaxed);
        let last_success_unix_seconds = (last_success > 0).then_some(last_success);
        let last_success_age_seconds =
            last_success_unix_seconds.map(|timestamp| unix_now_seconds().saturating_sub(timestamp));

        BitwardenCacheMetrics {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            refresh_successes: self.refresh_successes.load(Ordering::Relaxed),
            refresh_failures: self.refresh_failures.load(Ordering::Relaxed),
            last_success_unix_seconds,
            last_success_age_seconds,
        }
    }
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

struct CachedVault {
    session: BitwardenSession,
    sync: SyncResponse,
    fetched_at: Instant,
    expires_at: Option<Instant>,
}

impl CachedVault {
    fn new(session: BitwardenSession, sync: SyncResponse, fetched_at: Instant) -> Self {
        let expires_at = session
            .expires_in
            .and_then(|seconds| fetched_at.checked_add(Duration::from_secs(seconds)));

        Self {
            session,
            sync,
            fetched_at,
            expires_at,
        }
    }

    fn is_fresh(&self, ttl: Duration) -> bool {
        self.is_fresh_at(ttl, Instant::now())
    }

    fn is_fresh_at(&self, ttl: Duration, now: Instant) -> bool {
        if ttl.is_zero() || now.duration_since(self.fetched_at) >= ttl {
            return false;
        }

        match self.expires_at {
            Some(expires_at) => expires_at
                .checked_sub(TOKEN_EXPIRY_REFRESH_SKEW)
                .is_some_and(|refresh_deadline| now < refresh_deadline),
            None => true,
        }
    }
}

/// Stable device identity sent during API-key login.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BitwardenDevice {
    /// Bitwarden device type numeric value.
    pub device_type: u8,
    /// Stable device identifier.
    pub identifier: String,
    /// Human-readable device name.
    pub name: String,
}

impl Default for BitwardenDevice {
    fn default() -> Self {
        Self {
            device_type: DEFAULT_DEVICE_TYPE_SERVER,
            identifier: "bitwarden-eso-provider".to_string(),
            name: "Bitwarden ESO Provider".to_string(),
        }
    }
}

/// Authenticated Bitwarden-compatible session with an unlocked user key.
pub struct BitwardenSession {
    access_token: SecretString,
    /// Server token expiry in seconds.
    pub expires_in: Option<u64>,
    /// Token type returned by the server.
    pub token_type: String,
    /// Locally unlocked user key.
    pub user_key: AuthenticatedSymmetricKey,
}

/// Minimal sync response fields needed by the provider.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    /// Vault ciphers visible to the authenticated user.
    #[serde(default, alias = "Ciphers")]
    pub ciphers: Vec<EncryptedCipher>,
}

#[derive(Debug, Serialize)]
struct PreloginRequest<'a> {
    email: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreloginResponse {
    #[serde(alias = "Kdf")]
    kdf: u8,
    #[serde(alias = "KdfIterations")]
    kdf_iterations: u32,
    #[serde(default, alias = "KdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(default, alias = "KdfParallelism")]
    kdf_parallelism: Option<u32>,
}

impl TryFrom<PreloginResponse> for KdfConfig {
    type Error = BitwardenApiError;

    fn try_from(response: PreloginResponse) -> Result<Self, Self::Error> {
        kdf_from_parts(
            response.kdf,
            response.kdf_iterations,
            response.kdf_memory,
            response.kdf_parallelism,
        )
    }
}

#[derive(Debug, Serialize)]
struct ApiKeyTokenRequest<'a> {
    #[serde(rename = "grant_type")]
    grant_type: &'static str,
    scope: &'static str,
    #[serde(rename = "client_id")]
    client_id: &'a str,
    #[serde(rename = "client_secret")]
    client_secret: &'a str,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: &'a str,
    #[serde(rename = "deviceName")]
    device_name: &'a str,
    #[serde(rename = "deviceType")]
    device_type: u8,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(alias = "accessToken")]
    access_token: String,
    #[serde(default)]
    #[serde(alias = "expiresIn")]
    expires_in: Option<u64>,
    #[serde(default)]
    #[serde(alias = "tokenType")]
    token_type: Option<String>,
    #[serde(
        default,
        rename = "userDecryptionOptions",
        alias = "UserDecryptionOptions"
    )]
    user_decryption_options: Option<UserDecryptionOptionsResponse>,
}

#[derive(Debug, Deserialize)]
struct UserDecryptionOptionsResponse {
    #[serde(
        default,
        rename = "masterPasswordUnlock",
        alias = "MasterPasswordUnlock"
    )]
    master_password_unlock: Option<MasterPasswordUnlockResponse>,
}

#[derive(Debug, Deserialize)]
struct MasterPasswordUnlockResponse {
    #[serde(rename = "kdf", alias = "Kdf")]
    kdf: TokenKdfResponse,
    #[serde(
        default,
        rename = "masterKeyWrappedUserKey",
        alias = "MasterKeyWrappedUserKey"
    )]
    master_key_wrapped_user_key: Option<String>,
    #[serde(
        default,
        rename = "masterKeyEncryptedUserKey",
        alias = "MasterKeyEncryptedUserKey"
    )]
    master_key_encrypted_user_key: Option<String>,
    #[serde(rename = "salt", alias = "Salt")]
    salt: String,
}

impl TryFrom<MasterPasswordUnlockResponse> for MasterPasswordUnlockData {
    type Error = BitwardenApiError;

    fn try_from(response: MasterPasswordUnlockResponse) -> Result<Self, Self::Error> {
        let master_key_wrapped_user_key = response
            .master_key_wrapped_user_key
            .or(response.master_key_encrypted_user_key)
            .ok_or(BitwardenApiError::MissingMasterKeyWrappedUserKey)?;

        Ok(Self {
            salt: response.salt,
            kdf: response.kdf.try_into()?,
            master_key_wrapped_user_key,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TokenKdfResponse {
    #[serde(rename = "kdfType", alias = "KdfType")]
    kdf_type: u8,
    #[serde(alias = "Iterations")]
    iterations: u32,
    #[serde(default, alias = "Memory")]
    memory: Option<u32>,
    #[serde(default, alias = "Parallelism")]
    parallelism: Option<u32>,
}

impl TryFrom<TokenKdfResponse> for KdfConfig {
    type Error = BitwardenApiError;

    fn try_from(response: TokenKdfResponse) -> Result<Self, Self::Error> {
        kdf_from_parts(
            response.kdf_type,
            response.iterations,
            response.memory,
            response.parallelism,
        )
    }
}

fn kdf_from_parts(
    kdf_type: u8,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<KdfConfig, BitwardenApiError> {
    match kdf_type {
        0 => Ok(KdfConfig::Pbkdf2Sha256 { iterations }),
        1 => Ok(KdfConfig::Argon2id {
            iterations,
            memory_mib: memory.ok_or(BitwardenApiError::MissingKdfParameter {
                parameter: "memory",
            })?,
            parallelism: parallelism.ok_or(BitwardenApiError::MissingKdfParameter {
                parameter: "parallelism",
            })?,
        }),
        value => Err(BitwardenApiError::UnsupportedKdfType { kdf_type: value }),
    }
}

async fn decode_json<T>(
    response: reqwest::Response,
    endpoint: &'static str,
) -> Result<T, BitwardenApiError>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    if !status.is_success() {
        return Err(BitwardenApiError::HttpStatus {
            endpoint,
            status: status.as_u16(),
        });
    }

    Ok(response.json::<T>().await?)
}

trait BitwardenRequestHeaders {
    fn bitwarden_headers(self) -> Self;
}

impl BitwardenRequestHeaders for reqwest::RequestBuilder {
    fn bitwarden_headers(self) -> Self {
        self.header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
    }
}

/// Bitwarden-compatible API errors.
#[derive(Debug, Error)]
pub enum BitwardenApiError {
    /// HTTP client error.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Base URL cannot be used for endpoint construction.
    #[error("Bitwarden-compatible base URL cannot be used to build API endpoints")]
    InvalidBaseUrl,
    /// Server returned a non-success status.
    #[error("Bitwarden-compatible {endpoint} request returned HTTP {status}")]
    HttpStatus {
        /// Logical endpoint name.
        endpoint: &'static str,
        /// HTTP status code.
        status: u16,
    },
    /// KDF type is unknown.
    #[error("unsupported Bitwarden-compatible KDF type {kdf_type}")]
    UnsupportedKdfType {
        /// Numeric KDF type returned by the server.
        kdf_type: u8,
    },
    /// KDF response is missing a required parameter.
    #[error("Bitwarden-compatible KDF response is missing {parameter}")]
    MissingKdfParameter {
        /// Missing parameter name.
        parameter: &'static str,
    },
    /// API-key login did not return master-password unlock data.
    #[error("Bitwarden-compatible token response did not include master-password unlock data")]
    MissingMasterPasswordUnlock,
    /// API-key login did not return the wrapped user key needed for local unlock.
    #[error("Bitwarden-compatible token response did not include a master-key-wrapped user key")]
    MissingMasterKeyWrappedUserKey,
    /// Cache refresh did not produce a sync response.
    #[error("Bitwarden-compatible sync cache is empty after refresh")]
    MissingCachedSync,
    /// Requested cipher was not present in the sync response.
    #[error("Bitwarden-compatible cipher was not found")]
    CipherNotFound,
    /// More than one cipher matched the requested item name.
    #[error("Bitwarden-compatible cipher name is ambiguous")]
    AmbiguousCipherName,
    /// Selected item is a shared organization item that this release does not
    /// decrypt intentionally.
    #[error("shared organization vault items are not supported by this provider release")]
    UnsupportedSharedItem,
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use axum::{
        extract::State,
        http::{header, HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post},
        Form, Json, Router,
    };
    use bweso_core::RemoteRef;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PASSWORD: &str = "correct horse battery staple";
    const KEY_B64: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    const WRAPPED_CIPHER_TEST_KEY: &str =
        "2.AAECAwQFBgcICQoLDA0ODw==|rjzJWhStJXa0gPxMK+QGHB11ccKE8Q8NPFwsxqnI2yjMiiEWnwgY5nr1JWhyD4A5Sk4zDqfAoY91Gkr2QBfYQW14lXNe3qb+pHOsLqJ2Qa0=|Jsse4qMpeoqJ6VzlA9ta9PXyWNBJGfyPgRxFo5RupbE=";
    const LOGIN_CIPHER_JSON: &str = r#"
{
  "id": "cipher-login",
  "type": 1,
  "organizationId": null,
  "name": "2.UFFSU1RVVldYWVpbXF1eXw==|StyR/qx1FDl2IiD+llUqbw==|mX23ZTaSooPqZL9DzozpOa4pZH6Q3EO1oEyCfLHAUTA=",
  "notes": "2.gIGCg4SFhoeIiYqLjI2Ojw==|iFVXYOIlaeVXv98BkXhsX9RonhSa845FON4Gz7ibpKk=|OLWFugRmFHwv6y45LU3rP+5CYeUrnlCsOtZGoJIWELI=",
  "fields": [
    {
      "name": "2.kJGSk5SVlpeYmZqbnJ2enw==|2xgwPgtCaGbLNZe2aV+eQA==|rTu4SR2oEKPpx9fpaTt4sBwPF1e2m6D9yS7uoTyNsqg=",
      "value": "2.QEFCQ0RFRkdISUpLTE1OTw==|SgvILpma5dxrOQiNaAGR699WX5rwBVaPsidtZD2BxAKBaMLSm4jnP2eD70tV04Nh|SH6OgAyy4VoHgC7ilEbBcvDKZUdH330hZpp5ImjlwU0=",
      "type": 1
    }
  ],
  "login": {
    "username": "2.YGFiY2RlZmdoaWprbG1ubw==|b+km1T/4QuXHSTO/qKV9+g==|t1Dmr15Mywo7Z0kRd0wlFsoj31Pa+HRs8v/8QC2nG5Q=",
    "password": "2.cHFyc3R1dnd4eXp7fH1+fw==|VOCFi5yrDwretU6eHBCbMLgy3Arezxhx4kmIp9olCcY=|AV5iXNORGRrVvOAyXdJ2aGMu+tv9wPJvpbxUEO8y2/8=",
    "totp": null
  }
}
"#;

    #[derive(Clone)]
    struct FakeState {
        cipher: serde_json::Value,
        counters: FakeCounters,
    }

    #[derive(Clone, Default)]
    struct FakeCounters {
        token_requests: Arc<AtomicUsize>,
        sync_requests: Arc<AtomicUsize>,
    }

    impl FakeCounters {
        fn token_requests(&self) -> usize {
            self.token_requests.load(Ordering::SeqCst)
        }

        fn sync_requests(&self) -> usize {
            self.sync_requests.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug, Deserialize)]
    struct FakePreloginRequest {
        email: String,
    }

    #[derive(Debug, Deserialize)]
    struct FakeTokenForm {
        grant_type: String,
        scope: String,
        client_id: String,
        client_secret: String,
        #[serde(rename = "deviceIdentifier")]
        device_identifier: String,
        #[serde(rename = "deviceName")]
        device_name: String,
        #[serde(rename = "deviceType")]
        device_type: u8,
    }

    #[test]
    fn builds_single_origin_vaultwarden_endpoint_paths() -> TestResult {
        let endpoint = BitwardenEndpoint::parse("https://vault.example.test/base/")?;
        let endpoints = BitwardenEndpoints::from_single_origin(endpoint);
        let prelogin = BitwardenApiClient::endpoint_url(
            endpoints.identity_url(),
            &["accounts", "prelogin", "password"],
        )?;
        let token =
            BitwardenApiClient::endpoint_url(endpoints.identity_url(), &["connect", "token"])?;
        let sync = BitwardenApiClient::endpoint_url(endpoints.api_url(), &["sync"])?;

        assert_eq!(
            prelogin.as_str(),
            "https://vault.example.test/base/identity/accounts/prelogin/password"
        );
        assert_eq!(
            token.as_str(),
            "https://vault.example.test/base/identity/connect/token"
        );
        assert_eq!(sync.as_str(), "https://vault.example.test/base/api/sync");
        Ok(())
    }

    #[test]
    fn builds_split_bitwarden_cloud_endpoint_paths() -> TestResult {
        let endpoints = BitwardenEndpoints::parse_split(
            "https://identity.bitwarden.com/",
            "https://api.bitwarden.com/",
        )?;
        let prelogin = BitwardenApiClient::endpoint_url(
            endpoints.identity_url(),
            &["accounts", "prelogin", "password"],
        )?;
        let token =
            BitwardenApiClient::endpoint_url(endpoints.identity_url(), &["connect", "token"])?;
        let sync = BitwardenApiClient::endpoint_url(endpoints.api_url(), &["sync"])?;

        assert_eq!(
            prelogin.as_str(),
            "https://identity.bitwarden.com/accounts/prelogin/password"
        );
        assert_eq!(
            token.as_str(),
            "https://identity.bitwarden.com/connect/token"
        );
        assert_eq!(sync.as_str(), "https://api.bitwarden.com/sync");
        Ok(())
    }

    #[tokio::test]
    async fn parses_prelogin_kdf_response() -> TestResult {
        let client = fake_client().await?;

        assert_eq!(
            client.prelogin("User@Example.COM").await?,
            KdfConfig::Pbkdf2Sha256 { iterations: 5_000 }
        );
        Ok(())
    }

    #[tokio::test]
    async fn resolves_cipher_property_with_split_bitwarden_endpoints() -> TestResult {
        let (client, counters) =
            fake_split_client_with_cache(BitwardenCacheConfig::default()).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        let document = client.resolve(selector).await?;

        assert_eq!(
            document.data.get("DATABASE_URL"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert_eq!(
            document.data.get("value"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert_eq!(counters.token_requests(), 1);
        assert_eq!(counters.sync_requests(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn resolves_explicit_id_selector() -> TestResult {
        let client = fake_client().await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "id:cipher-login".to_string(),
            property: Some("username".to_string()),
            version: None,
        })?;

        let document = client.resolve(selector).await?;

        assert_eq!(document.data.get("username"), Some(&"app".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn resolves_explicit_name_selector() -> TestResult {
        let client = fake_client().await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("username".to_string()),
            version: None,
        })?;

        let document = client.resolve(selector).await?;

        assert_eq!(document.data.get("username"), Some(&"app".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn explicit_id_selector_does_not_fall_back_to_name() -> TestResult {
        let client = fake_client().await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "id:app/database".to_string(),
            property: Some("username".to_string()),
            version: None,
        })?;

        let Err(error) = client.resolve(selector).await else {
            unreachable!("explicit id selector should not fall back to item names");
        };

        assert!(matches!(
            error,
            BitwardenClientError::Api(BitwardenApiError::CipherNotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn resolves_cipher_property_through_api_key_login_and_sync() -> TestResult {
        let client = fake_client().await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        let document = client.resolve(selector).await?;

        assert_eq!(
            document.data.get("DATABASE_URL"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert_eq!(
            document.data.get("value"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn resolves_whole_cipher_to_secret_document() -> TestResult {
        let client = fake_client().await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "id:cipher-login".to_string(),
            property: None,
            version: None,
        })?;

        let document = client.resolve(selector).await?;

        assert_eq!(document.data.get("username"), Some(&"app".to_string()));
        assert_eq!(
            document.data.get("DATABASE_URL"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert!(document.metadata.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn selected_organization_item_fails_explicitly() -> TestResult {
        let mut cipher = serde_json::from_str::<serde_json::Value>(LOGIN_CIPHER_JSON)?;
        cipher["organizationId"] = json!("organization-id");
        let (client, _) = fake_client_with_cipher(cipher, BitwardenCacheConfig::default()).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "id:cipher-login".to_string(),
            property: Some("username".to_string()),
            version: None,
        })?;

        let Err(error) = client.resolve(selector).await else {
            unreachable!("organization item should fail explicitly");
        };

        assert!(matches!(
            error,
            BitwardenClientError::Api(BitwardenApiError::UnsupportedSharedItem)
        ));
        Ok(())
    }

    #[test]
    fn name_lookup_rejects_ambiguous_cipher_names() -> TestResult {
        let user_key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let first = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let mut second = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        second.id = "cipher-login-copy".to_string();
        let sync = SyncResponse {
            ciphers: vec![first, second],
        };

        let Err(error) =
            BitwardenApiClient::resolve_synced_cipher(&sync, &user_key, "name:app/database")
        else {
            unreachable!("duplicate item names should be ambiguous");
        };

        assert!(matches!(
            error,
            BitwardenClientError::Api(BitwardenApiError::AmbiguousCipherName)
        ));
        Ok(())
    }

    #[test]
    fn explicit_name_lookup_rejects_ambiguous_cipher_names() -> TestResult {
        let user_key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let first = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let mut second = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        second.id = "cipher-login-copy".to_string();
        let sync = SyncResponse {
            ciphers: vec![first, second],
        };

        let Err(error) =
            BitwardenApiClient::resolve_synced_cipher(&sync, &user_key, "name:app/database")
        else {
            unreachable!("duplicate explicit item names should be ambiguous");
        };

        assert!(matches!(
            error,
            BitwardenClientError::Api(BitwardenApiError::AmbiguousCipherName)
        ));
        Ok(())
    }

    #[test]
    fn name_lookup_reports_unsupported_shared_item() -> TestResult {
        let user_key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let mut cipher = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        cipher.organization_id = Some("organization-id".to_string());
        let sync = SyncResponse {
            ciphers: vec![cipher],
        };

        let Err(error) =
            BitwardenApiClient::resolve_synced_cipher(&sync, &user_key, "name:app/database")
        else {
            unreachable!("shared item selected by name should fail explicitly");
        };

        assert!(matches!(
            error,
            BitwardenClientError::Api(BitwardenApiError::UnsupportedSharedItem)
        ));
        Ok(())
    }

    #[test]
    fn name_lookup_skips_undecryptable_cipher_names() -> TestResult {
        let user_key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let mut broken = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        broken.id = "broken-cipher".to_string();
        broken.name = Some("2.invalid".to_string());
        let valid = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let sync = SyncResponse {
            ciphers: vec![broken, valid],
        };

        let decrypted =
            BitwardenApiClient::resolve_synced_cipher(&sync, &user_key, "name:app/database")?;

        assert_eq!(decrypted.id, "cipher-login");
        Ok(())
    }

    #[test]
    fn cached_vault_freshness_respects_ttl_and_token_expiry() -> TestResult {
        let now = Instant::now();
        let sync = SyncResponse { ciphers: vec![] };

        let fresh = CachedVault::new(fake_session(Some(3600))?, sync, now);
        assert!(fresh.is_fresh(Duration::from_secs(60)));

        let Some(stale_fetched_at) = now.checked_sub(Duration::from_secs(61)) else {
            unreachable!("test instant should support a short subtraction");
        };
        let expired_ttl = CachedVault::new(
            fake_session(Some(3600))?,
            SyncResponse { ciphers: vec![] },
            stale_fetched_at,
        );
        assert!(!expired_ttl.is_fresh(Duration::from_secs(60)));

        let expiring_token = CachedVault::new(
            fake_session(Some(20))?,
            SyncResponse { ciphers: vec![] },
            now,
        );
        assert!(!expiring_token.is_fresh(Duration::from_secs(60)));
        Ok(())
    }

    #[test]
    fn cached_vault_is_stale_at_token_refresh_deadline() -> TestResult {
        let now = Instant::now();
        let vault = CachedVault::new(
            fake_session(Some(TOKEN_EXPIRY_REFRESH_SKEW.as_secs()))?,
            SyncResponse { ciphers: vec![] },
            now,
        );

        assert!(!vault.is_fresh_at(Duration::from_secs(60), now));
        Ok(())
    }

    #[tokio::test]
    async fn reuses_sync_cache_within_ttl() -> TestResult {
        let (client, counters) =
            fake_client_with_cache(BitwardenCacheConfig::new(Duration::from_secs(60))).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        client.resolve(selector.clone()).await?;
        client.resolve(selector).await?;

        assert_eq!(counters.token_requests(), 1);
        assert_eq!(counters.sync_requests(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn cache_metrics_track_refreshes_hits_and_last_success() -> TestResult {
        let (client, counters) =
            fake_client_with_cache(BitwardenCacheConfig::new(Duration::from_secs(60))).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        let initial = client
            .cache_metrics()
            .ok_or("Bitwarden API client should expose cache metrics")?;
        assert_eq!(initial.cache_hits, 0);
        assert_eq!(initial.refresh_successes, 0);
        assert_eq!(initial.refresh_failures, 0);
        assert_eq!(initial.last_success_unix_seconds, None);
        assert_eq!(initial.last_success_age_seconds, None);

        client.resolve(selector.clone()).await?;
        let after_refresh = client
            .cache_metrics()
            .ok_or("Bitwarden API client should expose cache metrics")?;
        let refresh_timestamp = after_refresh
            .last_success_unix_seconds
            .ok_or("successful refresh should record a timestamp")?;
        assert!(refresh_timestamp > 1_600_000_000);
        assert_eq!(after_refresh.cache_hits, 0);
        assert_eq!(after_refresh.refresh_successes, 1);
        assert_eq!(after_refresh.refresh_failures, 0);
        assert!(after_refresh.last_success_age_seconds.is_some());

        client.resolve(selector).await?;
        let after_hit = client
            .cache_metrics()
            .ok_or("Bitwarden API client should expose cache metrics")?;
        assert_eq!(after_hit.cache_hits, 1);
        assert_eq!(after_hit.refresh_successes, 1);
        assert_eq!(after_hit.refresh_failures, 0);
        assert_eq!(after_hit.last_success_unix_seconds, Some(refresh_timestamp));
        assert!(after_hit.last_success_age_seconds.is_some());
        assert_eq!(counters.token_requests(), 1);
        assert_eq!(counters.sync_requests(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cache_refreshes_every_resolve() -> TestResult {
        let (client, counters) = fake_client_with_cache(BitwardenCacheConfig::disabled()).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        client.resolve(selector.clone()).await?;
        client.resolve(selector).await?;

        assert_eq!(counters.token_requests(), 2);
        assert_eq!(counters.sync_requests(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn refreshes_after_cache_ttl() -> TestResult {
        let (client, counters) =
            fake_client_with_cache(BitwardenCacheConfig::new(Duration::from_millis(10))).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        client.resolve(selector.clone()).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.resolve(selector).await?;

        assert_eq!(counters.token_requests(), 2);
        assert_eq!(counters.sync_requests(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn coalesces_concurrent_stale_resolves() -> TestResult {
        let (client, counters) =
            fake_client_with_cache(BitwardenCacheConfig::new(Duration::from_secs(60))).await?;
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: None,
        })?;

        let (first, second) = tokio::join!(
            client.resolve(selector.clone()),
            client.resolve(selector.clone())
        );

        assert_eq!(
            first?.data.get("DATABASE_URL"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert_eq!(
            second?.data.get("DATABASE_URL"),
            Some(&"postgres://app:secret@db:5432/app".to_string())
        );
        assert_eq!(counters.token_requests(), 1);
        assert_eq!(counters.sync_requests(), 1);
        Ok(())
    }

    async fn fake_client() -> Result<BitwardenApiClient, Box<dyn std::error::Error>> {
        let (client, _) = fake_client_with_cache(BitwardenCacheConfig::default()).await?;
        Ok(client)
    }

    async fn fake_client_with_cache(
        cache_config: BitwardenCacheConfig,
    ) -> Result<(BitwardenApiClient, FakeCounters), Box<dyn std::error::Error>> {
        let cipher = serde_json::from_str::<serde_json::Value>(LOGIN_CIPHER_JSON)?;
        fake_client_with_cipher(cipher, cache_config).await
    }

    async fn fake_client_with_cipher(
        cipher: serde_json::Value,
        cache_config: BitwardenCacheConfig,
    ) -> Result<(BitwardenApiClient, FakeCounters), Box<dyn std::error::Error>> {
        let (base_url, counters) = spawn_fake_server_with_cipher(cipher).await?;
        let endpoint = BitwardenEndpoint::parse(&base_url)?;
        let auth = BitwardenAuth {
            client_id: "user.fixture".to_string(),
            client_secret: "api-secret".into(),
            master_password: PASSWORD.into(),
        };

        let client = BitwardenApiClient::with_options(
            BitwardenApiClientOptions::single_origin(endpoint, auth)
                .with_cache_config(cache_config),
        )?;

        Ok((client, counters))
    }

    async fn fake_split_client_with_cache(
        cache_config: BitwardenCacheConfig,
    ) -> Result<(BitwardenApiClient, FakeCounters), Box<dyn std::error::Error>> {
        let (identity_url, api_url, counters) = spawn_fake_split_servers().await?;
        let endpoints = BitwardenEndpoints::parse_split(&identity_url, &api_url)?;
        let auth = BitwardenAuth {
            client_id: "user.fixture".to_string(),
            client_secret: "api-secret".into(),
            master_password: PASSWORD.into(),
        };

        let client = BitwardenApiClient::with_options(
            BitwardenApiClientOptions::split(endpoints, auth).with_cache_config(cache_config),
        )?;

        Ok((client, counters))
    }

    async fn spawn_fake_server_with_cipher(
        cipher: serde_json::Value,
    ) -> Result<(String, FakeCounters), Box<dyn std::error::Error>> {
        let counters = FakeCounters::default();
        let state = FakeState {
            cipher,
            counters: counters.clone(),
        };
        let app = Router::new()
            .route("/identity/accounts/prelogin/password", post(fake_prelogin))
            .route("/identity/connect/token", post(fake_token))
            .route("/api/sync", get(fake_sync))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                eprintln!("fake Vaultwarden server failed: {error}");
            }
        });

        Ok((format!("http://{}", socket_addr(address)), counters))
    }

    async fn spawn_fake_split_servers(
    ) -> Result<(String, String, FakeCounters), Box<dyn std::error::Error>> {
        let cipher = serde_json::from_str::<serde_json::Value>(LOGIN_CIPHER_JSON)?;
        let counters = FakeCounters::default();
        let state = FakeState {
            cipher,
            counters: counters.clone(),
        };
        let identity_app = Router::new()
            .route("/accounts/prelogin/password", post(fake_prelogin))
            .route("/connect/token", post(fake_token))
            .with_state(state.clone());
        let api_app = Router::new()
            .route("/sync", get(fake_sync))
            .with_state(state);

        let identity_listener = TcpListener::bind("127.0.0.1:0").await?;
        let identity_address = identity_listener.local_addr()?;
        tokio::spawn(async move {
            if let Err(error) = axum::serve(identity_listener, identity_app).await {
                eprintln!("fake Bitwarden identity server failed: {error}");
            }
        });

        let api_listener = TcpListener::bind("127.0.0.1:0").await?;
        let api_address = api_listener.local_addr()?;
        tokio::spawn(async move {
            if let Err(error) = axum::serve(api_listener, api_app).await {
                eprintln!("fake Bitwarden API server failed: {error}");
            }
        });

        Ok((
            format!("http://{}", socket_addr(identity_address)),
            format!("http://{}", socket_addr(api_address)),
            counters,
        ))
    }

    async fn fake_prelogin(Json(request): Json<FakePreloginRequest>) -> impl IntoResponse {
        if request.email.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "email is required" })),
            )
                .into_response();
        }

        Json(json!({
            "kdf": 0,
            "kdfIterations": 5_000,
            "kdfMemory": null,
            "kdfParallelism": null
        }))
        .into_response()
    }

    async fn fake_token(
        State(state): State<FakeState>,
        Form(form): Form<FakeTokenForm>,
    ) -> impl IntoResponse {
        state.counters.token_requests.fetch_add(1, Ordering::SeqCst);

        let valid = form.grant_type == "client_credentials"
            && form.scope == "api"
            && form.client_id == "user.fixture"
            && form.client_secret == "api-secret"
            && form.device_identifier == "bitwarden-eso-provider"
            && form.device_name == "Bitwarden ESO Provider"
            && form.device_type == DEFAULT_DEVICE_TYPE_SERVER;
        if !valid {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid token form" })),
            )
                .into_response();
        }

        Json(json!({
            "access_token": "fake-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "MasterPasswordUnlock": {
                    "Kdf": {
                        "KdfType": 0,
                        "Iterations": 5_000,
                        "Memory": null,
                        "Parallelism": null
                    },
                    "MasterKeyWrappedUserKey": WRAPPED_CIPHER_TEST_KEY,
                    "MasterKeyEncryptedUserKey": WRAPPED_CIPHER_TEST_KEY,
                    "Salt": " User@Example.COM "
                }
            }
        }))
        .into_response()
    }

    async fn fake_sync(State(state): State<FakeState>, headers: HeaderMap) -> impl IntoResponse {
        state.counters.sync_requests.fetch_add(1, Ordering::SeqCst);

        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if auth != Some("Bearer fake-access-token") {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing bearer token" })),
            )
                .into_response();
        }

        Json(json!({
            "profile": {},
            "ciphers": [state.cipher],
            "folders": [],
            "collections": [],
            "domains": null,
            "sends": [],
            "userDecryption": {
                "masterPasswordUnlock": null
            },
            "object": "sync"
        }))
        .into_response()
    }

    fn socket_addr(address: SocketAddr) -> String {
        address.to_string()
    }

    fn fake_session(
        expires_in: Option<u64>,
    ) -> Result<BitwardenSession, Box<dyn std::error::Error>> {
        Ok(BitwardenSession {
            access_token: "fake-access-token".to_string().into(),
            expires_in,
            token_type: "Bearer".to_string(),
            user_key: AuthenticatedSymmetricKey::from_base64(KEY_B64)?,
        })
    }
}
