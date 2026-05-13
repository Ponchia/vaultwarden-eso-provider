#![forbid(unsafe_code)]

//! Bitwarden Password Manager and Vaultwarden-compatible client boundary.
//!
//! This crate owns endpoint validation, API-key login, local vault unlock,
//! encrypted cipher decryption, selector resolution, and the provider trait used
//! by Kubernetes-facing adapters.

pub mod api;
pub mod cipher;
pub mod crypto;
pub mod keys;

use async_trait::async_trait;
use bweso_core::{require_non_empty, RemoteRef, SecretDocument, ValidationError};
use secrecy::SecretString;
use thiserror::Error;
use url::Url;

pub use api::{
    BitwardenApiClient, BitwardenApiClientOptions, BitwardenApiError, BitwardenCacheConfig,
    BitwardenCacheMetrics, BitwardenDevice, BitwardenHttpConfig, BitwardenSession, SyncResponse,
};
pub use cipher::{
    CipherError, DecryptedCipher, DecryptedField, DecryptedLogin, DecryptedSshKey, EncryptedCipher,
    EncryptedField, EncryptedLogin, EncryptedSshKey,
};
pub use crypto::{AuthenticatedSymmetricKey, CryptoError, EncryptedString, EncryptionType};
pub use keys::{
    derive_master_key, master_password_authentication_hash, normalize_master_password_salt,
    stretch_master_key, unwrap_user_key_with_master_key, KdfConfig, KeyDerivationError, MasterKey,
    MasterPasswordUnlockData,
};

/// Single-origin Vaultwarden or self-hosted Bitwarden endpoint configuration.
#[derive(Debug, Clone)]
pub struct BitwardenEndpoint {
    base_url: Url,
}

impl BitwardenEndpoint {
    /// Parse and validate a single-origin Vaultwarden or self-hosted Bitwarden
    /// base URL.
    ///
    /// HTTP is allowed only for localhost development endpoints. Production
    /// deployments must use HTTPS.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is empty, malformed, or uses an insecure
    /// non-local transport.
    pub fn parse(raw: &str) -> Result<Self, BitwardenClientError> {
        Self::parse_named(raw, "single_origin_url")
    }

    fn parse_named(raw: &str, field_name: &'static str) -> Result<Self, BitwardenClientError> {
        require_non_empty(raw, field_name)?;
        let base_url =
            Url::parse(raw).map_err(|source| BitwardenClientError::InvalidEndpoint { source })?;

        let host = base_url.host_str().unwrap_or_default();
        let is_localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
        if base_url.scheme() != "https" && !(base_url.scheme() == "http" && is_localhost) {
            return Err(BitwardenClientError::InsecureEndpoint);
        }

        Ok(Self { base_url })
    }

    /// Return the configured base URL.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }
}

/// Fully resolved Bitwarden-compatible endpoint bases.
#[derive(Debug, Clone)]
pub struct BitwardenEndpoints {
    identity_url: Url,
    api_url: Url,
}

impl BitwardenEndpoints {
    /// Build endpoint bases from a single Vaultwarden or self-hosted Bitwarden
    /// origin.
    #[must_use]
    pub fn from_single_origin(endpoint: BitwardenEndpoint) -> Self {
        let base_url = endpoint.base_url;

        Self {
            identity_url: append_path_segments(&base_url, &["identity"]),
            api_url: append_path_segments(&base_url, &["api"]),
        }
    }

    /// Parse explicit identity and API endpoint bases.
    ///
    /// This is the mode used by Bitwarden Cloud, for example
    /// `https://identity.bitwarden.com` plus `https://api.bitwarden.com`.
    ///
    /// # Errors
    ///
    /// Returns an error when either URL is empty, malformed, or uses an
    /// insecure non-local transport.
    pub fn parse_split(identity_url: &str, api_url: &str) -> Result<Self, BitwardenClientError> {
        let identity = BitwardenEndpoint::parse_named(identity_url, "identity_url")?;
        let api = BitwardenEndpoint::parse_named(api_url, "api_url")?;

        Ok(Self {
            identity_url: normalize_endpoint_base(identity.base_url()),
            api_url: normalize_endpoint_base(api.base_url()),
        })
    }

    /// Return the configured identity endpoint base.
    #[must_use]
    pub fn identity_url(&self) -> &Url {
        &self.identity_url
    }

    /// Return the configured API endpoint base.
    #[must_use]
    pub fn api_url(&self) -> &Url {
        &self.api_url
    }
}

fn normalize_endpoint_base(base_url: &Url) -> Url {
    append_path_segments(base_url, &[])
}

fn append_path_segments(base_url: &Url, segments: &[&str]) -> Url {
    let mut url = base_url.clone();
    url.set_query(None);
    url.set_fragment(None);

    let mut path = url.path().trim_end_matches('/').to_string();
    for segment in segments {
        path.push('/');
        path.push_str(segment.trim_matches('/'));
    }
    url.set_path(&path);

    url
}

/// Authentication material for a dedicated Bitwarden Password Manager or
/// Vaultwarden user.
#[derive(Clone)]
pub struct BitwardenAuth {
    /// User API key client ID.
    pub client_id: String,
    /// User API key client secret.
    pub client_secret: SecretString,
    /// Master password used for local vault decryption.
    pub master_password: SecretString,
}

/// Source selector understood by the Bitwarden-compatible provider.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BitwardenSelector {
    /// Vault item key. Supports bare ID/name lookup, `id:<item-id>`, or
    /// `name:<item-name>`.
    pub key: String,
    /// Optional item field to extract.
    pub property: Option<String>,
}

impl TryFrom<RemoteRef> for BitwardenSelector {
    type Error = BitwardenClientError;

    fn try_from(remote_ref: RemoteRef) -> Result<Self, Self::Error> {
        require_non_empty(&remote_ref.key, "remote_ref.key")?;
        if remote_ref
            .version
            .as_deref()
            .is_some_and(|version| !version.trim().is_empty())
        {
            return Err(BitwardenClientError::UnsupportedVersionSelector);
        }

        let property = match remote_ref.property {
            Some(property) => {
                require_non_empty(&property, "remote_ref.property")?;
                Some(property.trim().to_string())
            }
            None => None,
        };

        let key = remote_ref.key.trim().to_string();
        validate_selector_key(&key)?;

        Ok(Self { key, property })
    }
}

fn validate_selector_key(key: &str) -> Result<(), BitwardenClientError> {
    if let Some(value) = key
        .strip_prefix("id:")
        .or_else(|| key.strip_prefix("name:"))
    {
        require_non_empty(value, "remote_ref.key")?;
        return Ok(());
    }

    Err(BitwardenClientError::UnprefixedSelectorKey)
}

/// Provider boundary used by Kubernetes-facing adapters.
#[async_trait]
pub trait BitwardenProvider: Send + Sync {
    /// Resolve a selector into a secret document.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot authenticate, locate, decrypt,
    /// or map the selected vault item.
    async fn resolve(
        &self,
        selector: BitwardenSelector,
    ) -> Result<SecretDocument, BitwardenClientError>;

    /// Return cache metrics when the provider has a sync cache.
    fn cache_metrics(&self) -> Option<BitwardenCacheMetrics> {
        None
    }
}

/// Errors returned by the Bitwarden-compatible client boundary.
#[derive(Debug, Error)]
pub enum BitwardenClientError {
    /// Shared validation failure.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Symmetric crypto failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Cipher model or field extraction failure.
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// Master-password key derivation or unlock failure.
    #[error(transparent)]
    KeyDerivation(#[from] KeyDerivationError),
    /// Bitwarden-compatible HTTP API failure.
    #[error(transparent)]
    Api(#[from] BitwardenApiError),
    /// URL parsing failed.
    #[error("invalid Bitwarden-compatible endpoint")]
    InvalidEndpoint {
        /// URL parser source error.
        #[source]
        source: url::ParseError,
    },
    /// Endpoint does not meet transport security requirements.
    #[error("Bitwarden-compatible endpoint must use HTTPS except for localhost development")]
    InsecureEndpoint,
    /// ESO requested an item version or revision, which this provider cannot
    /// resolve safely yet.
    #[error("remote_ref.version is not supported by this provider")]
    UnsupportedVersionSelector,
    /// Selector key did not start with an explicit `id:` or `name:` prefix.
    #[error("remote_ref.key must start with 'id:' or 'name:'")]
    UnprefixedSelectorKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_https_for_non_local_hosts() {
        let Err(err) = BitwardenEndpoint::parse("http://vault.example.test") else {
            unreachable!("non-local HTTP endpoint should fail validation");
        };

        assert!(matches!(err, BitwardenClientError::InsecureEndpoint));
    }

    #[test]
    fn endpoint_allows_local_http_for_development() {
        let endpoint = match BitwardenEndpoint::parse("http://127.0.0.1:8080") {
            Ok(endpoint) => endpoint,
            Err(error) => unreachable!("local HTTP endpoint should be accepted: {error}"),
        };

        assert_eq!(endpoint.base_url().scheme(), "http");
    }

    #[test]
    fn single_origin_endpoints_append_identity_and_api_paths() {
        let endpoint = match BitwardenEndpoint::parse("https://vault.example.test/base/") {
            Ok(endpoint) => endpoint,
            Err(error) => unreachable!("endpoint should parse: {error}"),
        };
        let endpoints = BitwardenEndpoints::from_single_origin(endpoint);

        assert_eq!(
            endpoints.identity_url().as_str(),
            "https://vault.example.test/base/identity"
        );
        assert_eq!(
            endpoints.api_url().as_str(),
            "https://vault.example.test/base/api"
        );
    }

    #[test]
    fn split_endpoints_keep_identity_and_api_bases_separate() {
        let endpoints = match BitwardenEndpoints::parse_split(
            "https://identity.bitwarden.com/",
            "https://api.bitwarden.com/",
        ) {
            Ok(endpoints) => endpoints,
            Err(error) => unreachable!("split endpoints should parse: {error}"),
        };

        assert_eq!(
            endpoints.identity_url().as_str(),
            "https://identity.bitwarden.com/"
        );
        assert_eq!(endpoints.api_url().as_str(), "https://api.bitwarden.com/");
    }

    #[test]
    fn split_endpoints_reject_insecure_remote_http() {
        let Err(err) = BitwardenEndpoints::parse_split(
            "https://identity.bitwarden.com",
            "http://api.example.test",
        ) else {
            unreachable!("split endpoints should reject insecure remote HTTP");
        };

        assert!(matches!(err, BitwardenClientError::InsecureEndpoint));
    }

    #[test]
    fn selector_rejects_empty_keys() {
        let Err(err) = BitwardenSelector::try_from(RemoteRef {
            key: " ".to_string(),
            property: None,
            version: None,
        }) else {
            unreachable!("empty selector key should fail validation");
        };

        assert!(matches!(err, BitwardenClientError::Validation(_)));
    }

    #[test]
    fn selector_rejects_empty_properties() {
        let Err(err) = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some(" ".to_string()),
            version: None,
        }) else {
            unreachable!("empty selector property should fail validation");
        };

        assert!(matches!(err, BitwardenClientError::Validation(_)));
    }

    #[test]
    fn selector_rejects_unprefixed_key() {
        let Err(err) = BitwardenSelector::try_from(RemoteRef {
            key: "app/database".to_string(),
            property: None,
            version: None,
        }) else {
            unreachable!("unprefixed key should fail validation");
        };

        assert!(matches!(err, BitwardenClientError::UnprefixedSelectorKey));
    }

    #[test]
    fn selector_rejects_empty_explicit_lookup_values() {
        let Err(err) = BitwardenSelector::try_from(RemoteRef {
            key: "id: ".to_string(),
            property: None,
            version: None,
        }) else {
            unreachable!("empty explicit id selector should fail validation");
        };

        assert!(matches!(err, BitwardenClientError::Validation(_)));
    }

    #[test]
    fn selector_rejects_unsupported_versions() {
        let Err(err) = BitwardenSelector::try_from(RemoteRef {
            key: "name:app/database".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: Some("42".to_string()),
        }) else {
            unreachable!("version selectors should fail until implemented");
        };

        assert!(matches!(
            err,
            BitwardenClientError::UnsupportedVersionSelector
        ));
    }

    #[test]
    fn selector_normalizes_property_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let selector = BitwardenSelector::try_from(RemoteRef {
            key: " name:app/database ".to_string(),
            property: Some(" DATABASE_URL ".to_string()),
            version: None,
        })?;

        assert_eq!(selector.key, "name:app/database");
        assert_eq!(selector.property.as_deref(), Some("DATABASE_URL"));
        Ok(())
    }
}
