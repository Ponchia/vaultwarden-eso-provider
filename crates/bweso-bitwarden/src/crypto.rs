//! Bitwarden-compatible symmetric crypto primitives.

use std::str::FromStr;

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const AES_256_KEY_LENGTH: usize = 32;
const AUTHENTICATED_KEY_LENGTH: usize = 64;
const AES_CBC_IV_LENGTH: usize = 16;
const HMAC_SHA256_LENGTH: usize = 32;

/// Bitwarden encrypted string format.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncryptedString {
    encryption_type: EncryptionType,
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedString {
    /// Return the parsed encryption type.
    #[must_use]
    pub fn encryption_type(&self) -> EncryptionType {
        self.encryption_type
    }

    /// Decrypt the encrypted string to UTF-8.
    ///
    /// # Errors
    ///
    /// Returns an error when MAC verification fails, AES-CBC decryption fails,
    /// or the plaintext is not valid UTF-8.
    pub fn decrypt_utf8(&self, key: &AuthenticatedSymmetricKey) -> Result<String, CryptoError> {
        let plain = self.decrypt_bytes(key)?;
        String::from_utf8(plain).map_err(|source| {
            let mut bytes = source.into_bytes();
            bytes.zeroize();
            CryptoError::InvalidUtf8
        })
    }

    /// Decrypt the encrypted string to raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when MAC verification fails or AES-CBC decryption fails.
    pub fn decrypt_bytes(&self, key: &AuthenticatedSymmetricKey) -> Result<Vec<u8>, CryptoError> {
        if self.encryption_type != EncryptionType::AesCbc256HmacSha256B64 {
            return Err(CryptoError::UnsupportedEncryptionType {
                encryption_type: self.encryption_type.as_u8(),
            });
        }

        verify_mac(key.authentication_key(), &self.iv, &self.data, &self.mac)?;

        let mut data = Zeroizing::new(self.data.clone());
        let decrypted =
            Aes256CbcDecryptor::new(key.encryption_key().into(), self.iv.as_slice().into())
                .decrypt_padded_mut::<Pkcs7>(&mut data)
                .map_err(|_| CryptoError::DecryptFailed)?
                .to_vec();

        Ok(decrypted)
    }
}

impl FromStr for EncryptedString {
    type Err = CryptoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let Some((header, payload)) = raw.split_once('.') else {
            return Err(CryptoError::LegacyNoMacDisabled);
        };

        let encryption_type = EncryptionType::parse(header)?;
        if encryption_type != EncryptionType::AesCbc256HmacSha256B64 {
            return Err(CryptoError::UnsupportedEncryptionType {
                encryption_type: encryption_type.as_u8(),
            });
        }

        let mut pieces = payload.split('|');
        let Some(iv) = pieces.next() else {
            return Err(CryptoError::InvalidPartCount);
        };
        let Some(data) = pieces.next() else {
            return Err(CryptoError::InvalidPartCount);
        };
        let Some(mac) = pieces.next() else {
            return Err(CryptoError::InvalidPartCount);
        };
        if pieces.next().is_some() {
            return Err(CryptoError::InvalidPartCount);
        }

        let iv = decode_base64("iv", iv)?;
        let data = decode_base64("data", data)?;
        let mac = decode_base64("mac", mac)?;

        if iv.len() != AES_CBC_IV_LENGTH {
            return Err(CryptoError::InvalidIvLength { actual: iv.len() });
        }
        if mac.len() != HMAC_SHA256_LENGTH {
            return Err(CryptoError::InvalidMacLength { actual: mac.len() });
        }
        if data.is_empty() || data.len() % AES_CBC_IV_LENGTH != 0 {
            return Err(CryptoError::InvalidCiphertextLength { actual: data.len() });
        }

        Ok(Self {
            encryption_type,
            iv,
            data,
            mac,
        })
    }
}

/// Supported Bitwarden encryption types.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EncryptionType {
    /// AES-256-CBC with HMAC-SHA256, serialized as `2.iv|data|mac`.
    AesCbc256HmacSha256B64,
}

impl EncryptionType {
    fn parse(raw: &str) -> Result<Self, CryptoError> {
        let encryption_type = raw
            .parse::<u8>()
            .map_err(|_| CryptoError::InvalidEncryptionTypeHeader)?;

        match encryption_type {
            0 => Err(CryptoError::LegacyNoMacDisabled),
            2 => Ok(Self::AesCbc256HmacSha256B64),
            value => Err(CryptoError::UnsupportedEncryptionType {
                encryption_type: value,
            }),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::AesCbc256HmacSha256B64 => 2,
        }
    }
}

/// A 64-byte Bitwarden symmetric key split into encryption and MAC keys.
pub struct AuthenticatedSymmetricKey {
    encryption_key: [u8; AES_256_KEY_LENGTH],
    authentication_key: [u8; AES_256_KEY_LENGTH],
}

impl AuthenticatedSymmetricKey {
    /// Parse a base64-encoded 64-byte symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not valid base64 or does not decode
    /// to the expected 64-byte key format.
    pub fn from_base64(raw: &str) -> Result<Self, CryptoError> {
        let mut decoded = decode_base64("key", raw)?;
        let key = Self::try_from(decoded.as_slice());
        decoded.zeroize();
        key
    }

    /// Return the AES-256-CBC key half.
    #[must_use]
    pub fn encryption_key(&self) -> &[u8; AES_256_KEY_LENGTH] {
        &self.encryption_key
    }

    /// Return the HMAC-SHA256 key half.
    #[must_use]
    pub fn authentication_key(&self) -> &[u8; AES_256_KEY_LENGTH] {
        &self.authentication_key
    }
}

impl TryFrom<&[u8]> for AuthenticatedSymmetricKey {
    type Error = CryptoError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() != AUTHENTICATED_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength { actual: raw.len() });
        }

        let mut encryption_key = [0_u8; AES_256_KEY_LENGTH];
        encryption_key.copy_from_slice(&raw[..AES_256_KEY_LENGTH]);

        let mut authentication_key = [0_u8; AES_256_KEY_LENGTH];
        authentication_key.copy_from_slice(&raw[AES_256_KEY_LENGTH..]);

        Ok(Self {
            encryption_key,
            authentication_key,
        })
    }
}

impl Drop for AuthenticatedSymmetricKey {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
    }
}

/// Crypto errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The key does not use the authenticated 64-byte Bitwarden format.
    #[error("invalid symmetric key length {actual}, expected 64 bytes")]
    InvalidKeyLength {
        /// Actual decoded byte length.
        actual: usize,
    },
    /// The encrypted string has an invalid type header.
    #[error("invalid encrypted string type header")]
    InvalidEncryptionTypeHeader,
    /// Legacy unauthenticated AES-CBC is disabled.
    #[error("legacy unauthenticated AES-CBC encrypted strings are disabled")]
    LegacyNoMacDisabled,
    /// The encrypted string type is not supported.
    #[error("unsupported encryption type {encryption_type}")]
    UnsupportedEncryptionType {
        /// Numeric Bitwarden encryption type.
        encryption_type: u8,
    },
    /// The encrypted string does not have the expected number of parts.
    #[error("invalid encrypted string part count")]
    InvalidPartCount,
    /// Base64 decoding failed.
    #[error("invalid base64 in {part}")]
    InvalidBase64 {
        /// Failed field name.
        part: &'static str,
        /// Base64 decoder source error.
        #[source]
        source: base64::DecodeError,
    },
    /// AES-CBC IV has an invalid length.
    #[error("invalid AES-CBC IV length {actual}, expected 16 bytes")]
    InvalidIvLength {
        /// Actual decoded byte length.
        actual: usize,
    },
    /// HMAC-SHA256 tag has an invalid length.
    #[error("invalid HMAC-SHA256 length {actual}, expected 32 bytes")]
    InvalidMacLength {
        /// Actual decoded byte length.
        actual: usize,
    },
    /// Ciphertext length is invalid for AES-CBC.
    #[error("invalid AES-CBC ciphertext length {actual}")]
    InvalidCiphertextLength {
        /// Actual decoded byte length.
        actual: usize,
    },
    /// MAC verification failed.
    #[error("encrypted string MAC verification failed")]
    MacVerificationFailed,
    /// AES-CBC decryption failed.
    #[error("AES-CBC decryption failed")]
    DecryptFailed,
    /// Plaintext was not valid UTF-8.
    #[error("decrypted value is not valid UTF-8")]
    InvalidUtf8,
}

fn decode_base64(part: &'static str, raw: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD
        .decode(raw)
        .map_err(|source| CryptoError::InvalidBase64 { part, source })
}

fn verify_mac(
    authentication_key: &[u8],
    iv: &[u8],
    data: &[u8],
    mac: &[u8],
) -> Result<(), CryptoError> {
    let mut verifier = HmacSha256::new_from_slice(authentication_key).map_err(|_| {
        CryptoError::InvalidKeyLength {
            actual: authentication_key.len(),
        }
    })?;
    verifier.update(iv);
    verifier.update(data);
    verifier
        .verify_slice(mac)
        .map_err(|_| CryptoError::MacVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    const DATABASE_URL: &str =
        "2.QEFCQ0RFRkdISUpLTE1OTw==|SgvILpma5dxrOQiNaAGR699WX5rwBVaPsidtZD2BxAKBaMLSm4jnP2eD70tV04Nh|SH6OgAyy4VoHgC7ilEbBcvDKZUdH330hZpp5ImjlwU0=";

    #[test]
    fn decrypts_authenticated_encrypted_string() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let encrypted = DATABASE_URL.parse::<EncryptedString>()?;

        assert_eq!(
            encrypted.decrypt_utf8(&key)?,
            "postgres://app:secret@db:5432/app"
        );
        Ok(())
    }

    #[test]
    fn rejects_tampered_mac() -> Result<(), Box<dyn std::error::Error>> {
        let key = AuthenticatedSymmetricKey::from_base64(KEY_B64)?;
        let mut encrypted = DATABASE_URL.parse::<EncryptedString>()?;
        encrypted.mac = vec![0; HMAC_SHA256_LENGTH];

        let Err(error) = encrypted.decrypt_utf8(&key) else {
            unreachable!("tampered MAC should fail");
        };

        assert!(matches!(error, CryptoError::MacVerificationFailed));
        Ok(())
    }

    #[test]
    fn rejects_legacy_no_mac_strings() {
        let Err(error) = "0.aXY=|ZGF0YQ==".parse::<EncryptedString>() else {
            unreachable!("legacy no-MAC encrypted string should fail");
        };

        assert!(matches!(error, CryptoError::LegacyNoMacDisabled));
    }

    #[test]
    fn rejects_empty_or_unaligned_ciphertext() {
        let Err(empty) = "2.AAECAwQFBgcICQoLDA0ODw==||AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            .parse::<EncryptedString>()
        else {
            unreachable!("empty ciphertext should fail");
        };
        assert!(matches!(
            empty,
            CryptoError::InvalidCiphertextLength { actual: 0 }
        ));

        let Err(unaligned) =
            "2.AAECAwQFBgcICQoLDA0ODw==|AAE=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
                .parse::<EncryptedString>()
        else {
            unreachable!("unaligned ciphertext should fail");
        };
        assert!(matches!(
            unaligned,
            CryptoError::InvalidCiphertextLength { actual: 2 }
        ));
    }

    #[test]
    fn reports_supported_encryption_type_number() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = DATABASE_URL.parse::<EncryptedString>()?;

        assert_eq!(encrypted.encryption_type().as_u8(), 2);
        Ok(())
    }

    #[test]
    fn validates_key_length() {
        let Err(error) = AuthenticatedSymmetricKey::try_from([0_u8; 32].as_slice()) else {
            unreachable!("32-byte no-MAC key should fail");
        };

        assert!(matches!(
            error,
            CryptoError::InvalidKeyLength { actual: 32 }
        ));
    }
}
