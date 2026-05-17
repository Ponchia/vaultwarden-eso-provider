#![forbid(unsafe_code)]

//! Shared data types for Vaultwarden ESO Provider.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A remote secret selector supplied by an integration adapter.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRef {
    /// Provider-specific item key.
    pub key: String,
    /// Optional field or property within the item.
    #[serde(default)]
    pub property: Option<String>,
    /// Optional item version or revision selector.
    #[serde(default)]
    pub version: Option<String>,
}

impl fmt::Debug for RemoteRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRef")
            .field("key", &"<redacted>")
            .field("property", &self.property.as_ref().map(|_| "<redacted>"))
            .field("version", &self.version.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// A resolved secret document before adapter-specific response formatting.
#[derive(Clone, Eq, PartialEq, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretDocument {
    /// Secret key-value pairs.
    pub data: BTreeMap<String, String>,
    /// Non-sensitive metadata about the resolved source.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for SecretDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretDocument")
            .field("data_keys", &self.data.len())
            .field("metadata_keys", &self.metadata.len())
            .finish()
    }
}

impl SecretDocument {
    /// Build a single-key secret document.
    #[must_use]
    pub fn single(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut data = BTreeMap::new();
        data.insert(key.into(), value.into());
        Self {
            data,
            metadata: BTreeMap::new(),
        }
    }
}

/// Shared validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// A required field was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
}

/// Result alias for core validation.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validate a non-empty string field.
///
/// # Errors
///
/// Returns [`ValidationError::EmptyField`] when the value is empty after
/// trimming whitespace.
pub fn require_non_empty(value: &str, field: &'static str) -> ValidationResult<()> {
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField { field });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_secret_document_contains_one_value() {
        let doc = SecretDocument::single("DATABASE_URL", "postgres://example");

        assert_eq!(
            doc.data.get("DATABASE_URL"),
            Some(&"postgres://example".to_string())
        );
        assert!(doc.metadata.is_empty());
    }

    #[test]
    fn remote_ref_debug_redacts_selector_values() {
        let remote_ref = RemoteRef {
            key: "id:secret-item".to_string(),
            property: Some("DATABASE_URL".to_string()),
            version: Some("42".to_string()),
        };

        let output = format!("{remote_ref:?}");

        assert!(output.contains("RemoteRef"));
        assert!(output.contains("<redacted>"));
        assert!(output.contains("<present>"));
        assert!(!output.contains("secret-item"));
        assert!(!output.contains("DATABASE_URL"));
        assert!(!output.contains("42"));
    }

    #[test]
    fn secret_document_debug_reports_counts_without_values() {
        let mut doc = SecretDocument::single("DATABASE_URL", "postgres://example");
        doc.metadata
            .insert("item_name".to_string(), "app/database".to_string());

        let output = format!("{doc:?}");

        assert!(output.contains("SecretDocument"));
        assert!(output.contains("data_keys"));
        assert!(output.contains("metadata_keys"));
        assert!(!output.contains("DATABASE_URL"));
        assert!(!output.contains("postgres://example"));
        assert!(!output.contains("app/database"));
    }

    #[test]
    fn non_empty_validation_rejects_blank_values() {
        let Err(err) = require_non_empty("  ", "key") else {
            unreachable!("blank value should fail validation");
        };

        assert_eq!(err.to_string(), "key must not be empty");
    }
}
