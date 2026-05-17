use std::{env, fs, time::Duration};

use bweso_bitwarden::{
    BitwardenApiClient, BitwardenApiClientOptions, BitwardenAuth, BitwardenCacheConfig,
    BitwardenEndpoint, BitwardenEndpoints, BitwardenProvider, BitwardenSelector,
};
use bweso_core::SecretDocument;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn resolves_configured_live_bitwarden_compatible_secret() -> TestResult {
    let Some(config) = LiveConfig::from_env()? else {
        eprintln!(
            "skipping live Bitwarden-compatible test; set BWESO_TEST_LIVE=true, \
             BWESO_TEST_SINGLE_ORIGIN_URL \
             or both BWESO_TEST_IDENTITY_URL and BWESO_TEST_API_URL, plus \
             BWESO_TEST_CLIENT_ID, BWESO_TEST_CLIENT_SECRET, BWESO_TEST_MASTER_PASSWORD, \
             and BWESO_TEST_ITEM_KEY or BWESO_TEST_ALLOW_ANY_ITEM=true"
        );
        return Ok(());
    };

    let endpoints = config.endpoint.endpoints()?;
    let auth = BitwardenAuth {
        client_id: config.client_id,
        client_secret: config.client_secret.into(),
        master_password: config.master_password.into(),
    };
    let client = BitwardenApiClient::with_options(
        BitwardenApiClientOptions::split(endpoints, auth)
            .with_cache_config(BitwardenCacheConfig::new(Duration::from_secs(1))),
    )?;

    let selector = match config.selector {
        LiveSelectorConfig::Explicit { key, property } => BitwardenSelector { key, property },
        LiveSelectorConfig::FirstExtractable { property } => {
            first_extractable_selector(&client, property).await?
        }
    };
    let requested_property = selector.property.clone();

    if let Some(path) = config.selector_output_path {
        write_selector_output(&path, &selector)?;
    }

    let document = client.resolve(selector).await?;
    assert_document_contains_expected_data(&document, requested_property.as_deref());

    Ok(())
}

struct LiveConfig {
    endpoint: LiveEndpointConfig,
    client_id: String,
    client_secret: String,
    master_password: String,
    selector: LiveSelectorConfig,
    selector_output_path: Option<String>,
}

enum LiveSelectorConfig {
    Explicit {
        key: String,
        property: Option<String>,
    },
    FirstExtractable {
        property: Option<String>,
    },
}

impl LiveConfig {
    fn from_env() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if !truthy_env("BWESO_TEST_LIVE") {
            return Ok(None);
        }

        let endpoint = match (
            optional_env("BWESO_TEST_SINGLE_ORIGIN_URL"),
            optional_env("BWESO_TEST_IDENTITY_URL"),
            optional_env("BWESO_TEST_API_URL"),
        ) {
            (Some(single_origin_url), None, None) => {
                LiveEndpointConfig::SingleOrigin { single_origin_url }
            }
            (None, Some(identity_url), Some(api_url)) => LiveEndpointConfig::Split {
                identity_url,
                api_url,
            },
            (None, None, None) => {
                return Err(config_error(
                    "BWESO_TEST_LIVE=true requires BWESO_TEST_SINGLE_ORIGIN_URL or both BWESO_TEST_IDENTITY_URL and BWESO_TEST_API_URL",
                ));
            }
            _ => {
                return Err(config_error(
                    "live test endpoint config must use BWESO_TEST_SINGLE_ORIGIN_URL or both BWESO_TEST_IDENTITY_URL and BWESO_TEST_API_URL",
                ));
            }
        };

        let client_id = required_env("BWESO_TEST_CLIENT_ID")?;
        let client_secret = required_env("BWESO_TEST_CLIENT_SECRET")?;
        let master_password = required_env("BWESO_TEST_MASTER_PASSWORD")?;
        let property = optional_env("BWESO_TEST_PROPERTY");
        let selector = match (
            optional_env("BWESO_TEST_ITEM_KEY"),
            truthy_env("BWESO_TEST_ALLOW_ANY_ITEM"),
        ) {
            (Some(key), _) => LiveSelectorConfig::Explicit { key, property },
            (None, true) => LiveSelectorConfig::FirstExtractable { property },
            (None, false) => {
                return Err(config_error(
                    "BWESO_TEST_LIVE=true requires BWESO_TEST_ITEM_KEY or BWESO_TEST_ALLOW_ANY_ITEM=true",
                ));
            }
        };

        Ok(Some(Self {
            endpoint,
            client_id,
            client_secret,
            master_password,
            selector,
            selector_output_path: optional_env("BWESO_TEST_SELECTOR_OUTPUT"),
        }))
    }
}

async fn first_extractable_selector(
    client: &BitwardenApiClient,
    property: Option<String>,
) -> Result<BitwardenSelector, Box<dyn std::error::Error>> {
    let session = client.login_with_api_key().await?;
    let sync = client.sync(&session).await?;
    let mut decrypted_count = 0usize;
    let mut non_extractable_count = 0usize;

    for cipher in &sync.ciphers {
        let Ok(decrypted) = cipher.decrypt(&session.user_key) else {
            continue;
        };
        if decrypted.organization_id.is_some() {
            continue;
        }
        decrypted_count += 1;

        if let Some(property) = property.as_deref() {
            if decrypted.extract_property(property).is_ok() {
                return Ok(BitwardenSelector {
                    key: format!("id:{}", cipher.id),
                    property: Some(property.to_string()),
                });
            }
        } else if let Ok(document) = decrypted.to_secret_document() {
            return Ok(BitwardenSelector {
                key: format!("id:{}", cipher.id),
                property: document.data.keys().next().cloned(),
            });
        }

        non_extractable_count += 1;
    }

    Err(dynamic_test_error(format!(
        "live test could not find a decryptable cipher with extractable secret fields; \
         synced {} ciphers, decrypted {decrypted_count}, non-extractable {non_extractable_count}",
        sync.ciphers.len()
    )))
}

fn assert_document_contains_expected_data(document: &SecretDocument, property: Option<&str>) {
    if let Some(property) = property {
        assert!(
            document.data.contains_key(property.trim()),
            "resolved document did not contain the requested property key"
        );
    } else {
        assert!(
            !document.data.is_empty(),
            "resolved document did not contain any secret data"
        );
    }
}

fn write_selector_output(path: &str, selector: &BitwardenSelector) -> TestResult {
    let output = serde_json::json!({
        "key": &selector.key,
        "property": &selector.property,
    });
    fs::write(path, serde_json::to_vec_pretty(&output)?)?;
    Ok(())
}

enum LiveEndpointConfig {
    SingleOrigin {
        single_origin_url: String,
    },
    Split {
        identity_url: String,
        api_url: String,
    },
}

impl LiveEndpointConfig {
    fn endpoints(&self) -> Result<BitwardenEndpoints, bweso_bitwarden::BitwardenClientError> {
        match self {
            Self::SingleOrigin { single_origin_url } => {
                let endpoint = BitwardenEndpoint::parse(single_origin_url)?;
                Ok(BitwardenEndpoints::from_single_origin(endpoint))
            }
            Self::Split {
                identity_url,
                api_url,
            } => BitwardenEndpoints::parse_split(identity_url, api_url),
        }
    }
}

fn config_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}

fn dynamic_test_error(message: String) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}

fn truthy_env(name: &str) -> bool {
    optional_env(name).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        )
    })
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    optional_env(name).ok_or_else(|| config_error(format!("BWESO_TEST_LIVE=true requires {name}")))
}
