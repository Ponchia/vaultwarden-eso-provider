//! Bitwarden-compatible cipher response models and field extraction.

use std::fmt;

use bweso_core::SecretDocument;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroize;

use crate::crypto::{AuthenticatedSymmetricKey, CryptoError, EncryptedString};

/// Encrypted Bitwarden-compatible cipher as returned by sync and cipher detail APIs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCipher {
    /// Cipher identifier.
    pub id: String,
    /// Bitwarden cipher type.
    #[serde(rename = "type")]
    pub cipher_type: u8,
    /// Optional organization identifier.
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Optional per-cipher key. Decryption of this key is a later milestone.
    #[serde(default)]
    pub key: Option<String>,
    /// Encrypted item name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted item notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// Encrypted custom fields.
    #[serde(default)]
    pub fields: Vec<EncryptedField>,
    /// Login payload for login ciphers.
    #[serde(default)]
    pub login: Option<EncryptedLogin>,
    /// SSH key payload for SSH key ciphers.
    #[serde(default)]
    pub ssh_key: Option<EncryptedSshKey>,
}

impl fmt::Debug for EncryptedCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedCipher")
            .field("id", &"<redacted>")
            .field("cipher_type", &self.cipher_type)
            .field(
                "organization_id",
                &self.organization_id.as_ref().map(|_| "<redacted>"),
            )
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("fields", &self.fields.len())
            .field("login", &self.login.as_ref().map(|_| "<present>"))
            .field("ssh_key", &self.ssh_key.as_ref().map(|_| "<present>"))
            .finish()
    }
}

impl EncryptedCipher {
    /// Decrypt this cipher with an already-resolved symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error when any encrypted string is malformed, fails MAC
    /// verification, or cannot be decoded as UTF-8.
    pub fn decrypt(&self, key: &AuthenticatedSymmetricKey) -> Result<DecryptedCipher, CipherError> {
        let cipher_key;
        let decryption_key = if let Some(wrapped_key) = self.key.as_deref() {
            let mut plain = wrapped_key.parse::<EncryptedString>()?.decrypt_bytes(key)?;
            let parsed_key = AuthenticatedSymmetricKey::try_from(plain.as_slice())?;
            plain.zeroize();
            cipher_key = parsed_key;
            &cipher_key
        } else {
            key
        };

        let name = decrypt_optional(self.name.as_deref(), decryption_key)?;
        let notes = decrypt_optional(self.notes.as_deref(), decryption_key)?;
        let fields = self
            .fields
            .iter()
            .map(|field| field.decrypt(decryption_key))
            .collect::<Result<Vec<_>, _>>()?;
        let login = self
            .login
            .as_ref()
            .map(|login| login.decrypt(decryption_key))
            .transpose()?;
        let ssh_key = self
            .ssh_key
            .as_ref()
            .map(|ssh_key| ssh_key.decrypt(decryption_key))
            .transpose()?;

        Ok(DecryptedCipher {
            id: self.id.clone(),
            cipher_type: self.cipher_type,
            organization_id: self.organization_id.clone(),
            name,
            notes,
            fields,
            login,
            ssh_key,
        })
    }
}

/// Encrypted custom field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedField {
    /// Encrypted custom field name.
    #[serde(default)]
    pub name: Option<String>,
    /// Encrypted custom field value.
    #[serde(default)]
    pub value: Option<String>,
    /// Bitwarden field type.
    #[serde(default, rename = "type")]
    pub field_type: Option<u8>,
}

impl EncryptedField {
    fn decrypt(&self, key: &AuthenticatedSymmetricKey) -> Result<DecryptedField, CipherError> {
        Ok(DecryptedField {
            name: decrypt_optional(self.name.as_deref(), key)?,
            value: decrypt_optional(self.value.as_deref(), key)?,
            field_type: self.field_type,
        })
    }
}

/// Encrypted login payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedLogin {
    /// Encrypted username.
    #[serde(default)]
    pub username: Option<String>,
    /// Encrypted password.
    #[serde(default)]
    pub password: Option<String>,
    /// Encrypted TOTP seed.
    #[serde(default)]
    pub totp: Option<String>,
}

impl EncryptedLogin {
    fn decrypt(&self, key: &AuthenticatedSymmetricKey) -> Result<DecryptedLogin, CipherError> {
        Ok(DecryptedLogin {
            username: decrypt_optional(self.username.as_deref(), key)?,
            password: decrypt_optional(self.password.as_deref(), key)?,
            totp: decrypt_optional(self.totp.as_deref(), key)?,
        })
    }
}

/// Encrypted SSH key payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSshKey {
    /// Encrypted private key.
    #[serde(default)]
    pub private_key: Option<String>,
    /// Encrypted public key.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Encrypted key fingerprint.
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

impl EncryptedSshKey {
    fn decrypt(&self, key: &AuthenticatedSymmetricKey) -> Result<DecryptedSshKey, CipherError> {
        Ok(DecryptedSshKey {
            private_key: decrypt_optional(self.private_key.as_deref(), key)?,
            public_key: decrypt_optional(self.public_key.as_deref(), key)?,
            key_fingerprint: decrypt_optional(self.key_fingerprint.as_deref(), key)?,
        })
    }
}

/// Decrypted cipher ready for field extraction.
#[derive(Clone, Eq, PartialEq)]
pub struct DecryptedCipher {
    /// Cipher identifier.
    pub id: String,
    /// Bitwarden cipher type.
    pub cipher_type: u8,
    /// Optional organization identifier.
    pub organization_id: Option<String>,
    /// Decrypted item name.
    pub name: Option<String>,
    /// Decrypted item notes.
    pub notes: Option<String>,
    /// Decrypted custom fields.
    pub fields: Vec<DecryptedField>,
    /// Decrypted login payload.
    pub login: Option<DecryptedLogin>,
    /// Decrypted SSH key payload.
    pub ssh_key: Option<DecryptedSshKey>,
}

impl fmt::Debug for DecryptedCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedCipher")
            .field("id", &"<redacted>")
            .field("cipher_type", &self.cipher_type)
            .field(
                "organization_id",
                &self.organization_id.as_ref().map(|_| "<redacted>"),
            )
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("fields", &self.fields.len())
            .field("login", &self.login.as_ref().map(|_| "<present>"))
            .field("ssh_key", &self.ssh_key.as_ref().map(|_| "<present>"))
            .finish()
    }
}

impl DecryptedCipher {
    /// Extract a field by property name.
    ///
    /// # Errors
    ///
    /// Returns an error when the property is blank or does not exist on the
    /// decrypted cipher.
    pub fn extract_property(&self, property: &str) -> Result<String, CipherError> {
        let property = property.trim();
        if property.is_empty() {
            return Err(CipherError::BlankProperty);
        }
        if property.starts_with("attachment.") || property.starts_with("attachments.") {
            return Err(CipherError::UnsupportedAttachment);
        }

        match property {
            "name" => return existing(property, self.name.as_deref()),
            "notes" => return existing(property, self.notes.as_deref()),
            "username" | "login.username" => {
                return existing(
                    property,
                    self.login
                        .as_ref()
                        .and_then(|login| login.username.as_deref()),
                );
            }
            "password" | "login.password" => {
                return existing(
                    property,
                    self.login
                        .as_ref()
                        .and_then(|login| login.password.as_deref()),
                );
            }
            "totp" | "login.totp" => {
                return existing(
                    property,
                    self.login.as_ref().and_then(|login| login.totp.as_deref()),
                );
            }
            "privateKey" | "sshPrivateKey" | "sshKey.privateKey" => {
                return existing(
                    property,
                    self.ssh_key
                        .as_ref()
                        .and_then(|ssh_key| ssh_key.private_key.as_deref()),
                );
            }
            "publicKey" | "sshPublicKey" | "sshKey.publicKey" => {
                return existing(
                    property,
                    self.ssh_key
                        .as_ref()
                        .and_then(|ssh_key| ssh_key.public_key.as_deref()),
                );
            }
            "keyFingerprint" | "sshKey.keyFingerprint" => {
                return existing(
                    property,
                    self.ssh_key
                        .as_ref()
                        .and_then(|ssh_key| ssh_key.key_fingerprint.as_deref()),
                );
            }
            _ => {}
        }

        let custom_name = property
            .strip_prefix("field.")
            .or_else(|| property.strip_prefix("custom."))
            .unwrap_or(property);

        self.fields
            .iter()
            .find(|field| field.name.as_deref() == Some(custom_name))
            .and_then(|field| field.value.clone())
            .ok_or_else(|| CipherError::MissingProperty {
                property: property.to_string(),
            })
    }

    /// Convert all conventional fields on this cipher into a secret document.
    ///
    /// # Errors
    ///
    /// Returns an error when the decrypted cipher has no extractable secret
    /// values.
    pub fn to_secret_document(&self) -> Result<SecretDocument, CipherError> {
        let mut document = SecretDocument::default();

        insert_optional(&mut document, "notes", self.notes.as_deref());

        if let Some(login) = &self.login {
            insert_optional(&mut document, "username", login.username.as_deref());
            insert_optional(&mut document, "password", login.password.as_deref());
            insert_optional(&mut document, "totp", login.totp.as_deref());
        }

        if let Some(ssh_key) = &self.ssh_key {
            insert_optional(&mut document, "privateKey", ssh_key.private_key.as_deref());
            insert_optional(&mut document, "publicKey", ssh_key.public_key.as_deref());
            insert_optional(
                &mut document,
                "keyFingerprint",
                ssh_key.key_fingerprint.as_deref(),
            );
        }

        for field in &self.fields {
            if let (Some(name), Some(value)) = (&field.name, &field.value) {
                if !name.trim().is_empty() {
                    document.data.insert(name.clone(), value.clone());
                }
            }
        }

        if document.data.is_empty() {
            return Err(CipherError::NoExtractableFields {
                id: self.id.clone(),
            });
        }

        Ok(document)
    }
}

/// Decrypted custom field.
#[derive(Clone, Eq, PartialEq)]
pub struct DecryptedField {
    /// Decrypted field name.
    pub name: Option<String>,
    /// Decrypted field value.
    pub value: Option<String>,
    /// Bitwarden field type.
    pub field_type: Option<u8>,
}

impl fmt::Debug for DecryptedField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedField")
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .field("field_type", &self.field_type)
            .finish()
    }
}

/// Decrypted login payload.
#[derive(Clone, Eq, PartialEq)]
pub struct DecryptedLogin {
    /// Decrypted username.
    pub username: Option<String>,
    /// Decrypted password.
    pub password: Option<String>,
    /// Decrypted TOTP seed.
    pub totp: Option<String>,
}

impl fmt::Debug for DecryptedLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedLogin")
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Decrypted SSH key payload.
#[derive(Clone, Eq, PartialEq)]
pub struct DecryptedSshKey {
    /// Decrypted private key.
    pub private_key: Option<String>,
    /// Decrypted public key.
    pub public_key: Option<String>,
    /// Decrypted key fingerprint.
    pub key_fingerprint: Option<String>,
}

impl fmt::Debug for DecryptedSshKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedSshKey")
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "public_key",
                &self.public_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "key_fingerprint",
                &self.key_fingerprint.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Cipher model and extraction errors.
#[derive(Error)]
pub enum CipherError {
    /// Crypto failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Requested property was blank.
    #[error("cipher property must not be blank")]
    BlankProperty,
    /// Requested property does not exist.
    #[error("cipher property was not found")]
    MissingProperty {
        /// Requested property name.
        property: String,
    },
    /// The cipher has no conventional fields that can be mapped to a Secret.
    #[error("cipher has no extractable secret fields")]
    NoExtractableFields {
        /// Cipher identifier.
        id: String,
    },
    /// Attachment download and decryption is intentionally out of scope for this release.
    #[error("Bitwarden attachment extraction is not supported by this provider release")]
    UnsupportedAttachment,
}

impl fmt::Debug for CipherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => formatter.debug_tuple("Crypto").field(error).finish(),
            Self::BlankProperty => formatter.write_str("BlankProperty"),
            Self::MissingProperty { .. } => formatter.write_str("MissingProperty"),
            Self::NoExtractableFields { .. } => formatter.write_str("NoExtractableFields"),
            Self::UnsupportedAttachment => formatter.write_str("UnsupportedAttachment"),
        }
    }
}

fn decrypt_optional(
    value: Option<&str>,
    key: &AuthenticatedSymmetricKey,
) -> Result<Option<String>, CipherError> {
    value
        .map(|encrypted| encrypted.parse::<EncryptedString>()?.decrypt_utf8(key))
        .transpose()
        .map_err(CipherError::from)
}

fn existing(property: &str, value: Option<&str>) -> Result<String, CipherError> {
    value
        .map(ToOwned::to_owned)
        .ok_or_else(|| CipherError::MissingProperty {
            property: property.to_string(),
        })
}

fn insert_optional(document: &mut SecretDocument, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        document.data.insert(key.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";

    #[test]
    fn decrypts_login_cipher_and_extracts_custom_field() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let cipher = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let decrypted = cipher.decrypt(&key)?;

        assert_eq!(decrypted.extract_property("name")?, "app/database");
        assert_eq!(decrypted.extract_property("username")?, "app");
        assert_eq!(
            decrypted.extract_property("password")?,
            "correct horse battery staple"
        );
        assert_eq!(
            decrypted.extract_property("DATABASE_URL")?,
            "postgres://app:secret@db:5432/app"
        );
        assert_eq!(
            decrypted.extract_property("field.DATABASE_URL")?,
            "postgres://app:secret@db:5432/app"
        );
        Ok(())
    }

    #[test]
    fn decrypts_ssh_key_cipher() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let cipher = serde_json::from_str::<EncryptedCipher>(SSH_KEY_CIPHER_JSON)?;
        let decrypted = cipher.decrypt(&key)?;

        assert_eq!(
            decrypted.extract_property("sshKey.privateKey")?,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----"
        );
        Ok(())
    }

    #[test]
    fn reports_missing_property() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let cipher = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let decrypted = cipher.decrypt(&key)?;

        let Err(error) = decrypted.extract_property("missing") else {
            unreachable!("missing field should fail");
        };

        assert!(matches!(error, CipherError::MissingProperty { .. }));
        Ok(())
    }

    #[test]
    fn reports_unsupported_attachment_property() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let cipher = serde_json::from_str::<EncryptedCipher>(LOGIN_CIPHER_JSON)?;
        let decrypted = cipher.decrypt(&key)?;

        let Err(error) = decrypted.extract_property("attachment.tls.crt") else {
            unreachable!("attachment properties should fail explicitly");
        };

        assert!(matches!(error, CipherError::UnsupportedAttachment));
        Ok(())
    }

    #[test]
    fn extracts_all_documented_property_aliases() -> Result<(), Box<dyn std::error::Error>> {
        let decrypted = DecryptedCipher {
            id: "cipher".to_string(),
            cipher_type: 5,
            organization_id: None,
            name: Some("item-name".to_string()),
            notes: Some("note-value".to_string()),
            fields: vec![DecryptedField {
                name: Some("CUSTOM".to_string()),
                value: Some("custom-value".to_string()),
                field_type: Some(1),
            }],
            login: Some(DecryptedLogin {
                username: Some("user-value".to_string()),
                password: Some("password-value".to_string()),
                totp: Some("totp-value".to_string()),
            }),
            ssh_key: Some(DecryptedSshKey {
                private_key: Some("private-key-value".to_string()),
                public_key: Some("public-key-value".to_string()),
                key_fingerprint: Some("fingerprint-value".to_string()),
            }),
        };

        assert_eq!(decrypted.extract_property("notes")?, "note-value");
        assert_eq!(decrypted.extract_property("login.username")?, "user-value");
        assert_eq!(
            decrypted.extract_property("login.password")?,
            "password-value"
        );
        assert_eq!(decrypted.extract_property("login.totp")?, "totp-value");
        assert_eq!(
            decrypted.extract_property("sshKey.privateKey")?,
            "private-key-value"
        );
        assert_eq!(
            decrypted.extract_property("sshPublicKey")?,
            "public-key-value"
        );
        assert_eq!(
            decrypted.extract_property("sshKey.keyFingerprint")?,
            "fingerprint-value"
        );
        assert_eq!(decrypted.extract_property("custom.CUSTOM")?, "custom-value");
        Ok(())
    }

    #[test]
    fn encrypted_cipher_debug_redacts_source_values() {
        let cipher = EncryptedCipher {
            id: "cipher-id-secret".to_string(),
            cipher_type: 1,
            organization_id: Some("organization-id-secret".to_string()),
            key: Some("cipher-key-secret".to_string()),
            name: Some("encrypted-name-secret".to_string()),
            notes: Some("encrypted-notes-secret".to_string()),
            fields: vec![EncryptedField {
                name: Some("encrypted-field-name-secret".to_string()),
                value: Some("encrypted-field-value-secret".to_string()),
                field_type: Some(1),
            }],
            login: Some(EncryptedLogin {
                username: Some("encrypted-username-secret".to_string()),
                password: Some("encrypted-password-secret".to_string()),
                totp: Some("encrypted-totp-secret".to_string()),
            }),
            ssh_key: Some(EncryptedSshKey {
                private_key: Some("encrypted-private-key-secret".to_string()),
                public_key: Some("encrypted-public-key-secret".to_string()),
                key_fingerprint: Some("encrypted-fingerprint-secret".to_string()),
            }),
        };

        let output = format!("{cipher:?}");

        assert!(output.contains("EncryptedCipher"));
        assert!(output.contains("<redacted>"));
        assert!(output.contains("<present>"));
        for secret in [
            "cipher-id-secret",
            "organization-id-secret",
            "cipher-key-secret",
            "encrypted-name-secret",
            "encrypted-notes-secret",
            "encrypted-field-name-secret",
            "encrypted-field-value-secret",
            "encrypted-username-secret",
            "encrypted-password-secret",
            "encrypted-totp-secret",
            "encrypted-private-key-secret",
            "encrypted-public-key-secret",
            "encrypted-fingerprint-secret",
        ] {
            assert!(!output.contains(secret), "debug leaked {secret}: {output}");
        }
    }

    #[test]
    fn decrypted_cipher_debug_redacts_secret_values() {
        let cipher = DecryptedCipher {
            id: "cipher-id-secret".to_string(),
            cipher_type: 1,
            organization_id: Some("organization-id-secret".to_string()),
            name: Some("item-name-secret".to_string()),
            notes: Some("notes-secret".to_string()),
            fields: vec![DecryptedField {
                name: Some("field-name-secret".to_string()),
                value: Some("field-value-secret".to_string()),
                field_type: Some(1),
            }],
            login: Some(DecryptedLogin {
                username: Some("username-secret".to_string()),
                password: Some("password-secret".to_string()),
                totp: Some("totp-secret".to_string()),
            }),
            ssh_key: Some(DecryptedSshKey {
                private_key: Some("private-key-secret".to_string()),
                public_key: Some("public-key-secret".to_string()),
                key_fingerprint: Some("fingerprint-secret".to_string()),
            }),
        };
        let field = cipher.fields[0].clone();
        let Some(login) = cipher.login.clone() else {
            unreachable!("fixture has login");
        };
        let Some(ssh_key) = cipher.ssh_key.clone() else {
            unreachable!("fixture has SSH key");
        };

        let outputs = [
            format!("{cipher:?}"),
            format!("{field:?}"),
            format!("{login:?}"),
            format!("{ssh_key:?}"),
        ];

        assert!(outputs[0].contains("DecryptedCipher"));
        assert!(outputs[1].contains("DecryptedField"));
        assert!(outputs[2].contains("DecryptedLogin"));
        assert!(outputs[3].contains("DecryptedSshKey"));
        for output in outputs {
            assert!(output.contains("<redacted>") || output.contains("<present>"));
            for secret in [
                "cipher-id-secret",
                "organization-id-secret",
                "item-name-secret",
                "notes-secret",
                "field-name-secret",
                "field-value-secret",
                "username-secret",
                "password-secret",
                "totp-secret",
                "private-key-secret",
                "public-key-secret",
                "fingerprint-secret",
            ] {
                assert!(!output.contains(secret), "debug leaked {secret}: {output}");
            }
        }
    }

    #[test]
    fn cipher_error_debug_does_not_include_selector_values() {
        let missing_property = CipherError::MissingProperty {
            property: "DATABASE_URL".to_string(),
        };
        let no_extractable_fields = CipherError::NoExtractableFields {
            id: "cipher-id-secret".to_string(),
        };

        assert_eq!(format!("{missing_property:?}"), "MissingProperty");
        assert_eq!(format!("{no_extractable_fields:?}"), "NoExtractableFields");
    }

    #[test]
    fn field_prefix_selects_custom_fields_that_collide_with_login_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let decrypted = DecryptedCipher {
            id: "cipher".to_string(),
            cipher_type: 1,
            organization_id: None,
            name: Some("item-name".to_string()),
            notes: None,
            fields: vec![
                DecryptedField {
                    name: Some("username".to_string()),
                    value: Some("custom-user".to_string()),
                    field_type: Some(1),
                },
                DecryptedField {
                    name: Some("password".to_string()),
                    value: Some("custom-password".to_string()),
                    field_type: Some(1),
                },
            ],
            login: Some(DecryptedLogin {
                username: Some("login-user".to_string()),
                password: Some("login-password".to_string()),
                totp: None,
            }),
            ssh_key: None,
        };

        assert_eq!(decrypted.extract_property("username")?, "login-user");
        assert_eq!(decrypted.extract_property("password")?, "login-password");
        assert_eq!(decrypted.extract_property("field.username")?, "custom-user");
        assert_eq!(
            decrypted.extract_property("field.password")?,
            "custom-password"
        );
        Ok(())
    }

    #[test]
    fn whole_cipher_document_omits_source_metadata() {
        let decrypted = DecryptedCipher {
            id: "cipher-login".to_string(),
            cipher_type: 1,
            organization_id: Some("organization-id".to_string()),
            name: Some("item-name".to_string()),
            notes: None,
            fields: vec![],
            login: Some(DecryptedLogin {
                username: Some("app".to_string()),
                password: Some("secret".to_string()),
                totp: None,
            }),
            ssh_key: None,
        };

        let Ok(document) = decrypted.to_secret_document() else {
            unreachable!("login cipher should have extractable fields");
        };
        assert_eq!(document.data.get("username"), Some(&"app".to_string()));
        assert!(document.metadata.is_empty());
    }

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

    const SSH_KEY_CIPHER_JSON: &str = r#"
{
  "id": "cipher-ssh",
  "type": 5,
  "name": "2.UFFSU1RVVldYWVpbXF1eXw==|StyR/qx1FDl2IiD+llUqbw==|mX23ZTaSooPqZL9DzozpOa4pZH6Q3EO1oEyCfLHAUTA=",
  "fields": [],
  "sshKey": {
    "privateKey": "2.oKGio6SlpqeoqaqrrK2urw==|/IUlZiPH9QsY9bVSXIsC1IkRjVMBA1u1DlXJpYdxq4W94NqtMGYxGSYepXX8/0P38FSZ4MW+EIMIA3hPQrfhhUCm99kTtxmjZVwSuuNnNIs=|HK0Flyea6v5Vcn6BP685jSaiGEzahD4uxMGwmTJDw/M=",
    "publicKey": null,
    "keyFingerprint": null
  }
}
"#;
}
