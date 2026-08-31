//! Master-password key derivation and user-key unwrap helpers.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use crate::crypto::{AuthenticatedSymmetricKey, CryptoError, EncryptedString};

const MASTER_KEY_LENGTH: usize = 32;
const AUTHENTICATION_HASH_ITERATIONS: u32 = 1;
const PBKDF2_PRELOGIN_ITERATIONS_MIN: u32 = 5_000;
const PBKDF2_PRELOGIN_ITERATIONS_MAX: u32 = 2_000_000;
const ARGON2_PRELOGIN_ITERATIONS_MIN: u32 = 2;
const ARGON2_PRELOGIN_ITERATIONS_MAX: u32 = 10;
const ARGON2_PRELOGIN_MEMORY_MIB_MIN: u32 = 16;
const ARGON2_PRELOGIN_MEMORY_MIB_MAX: u32 = 1024;
const ARGON2_PRELOGIN_PARALLELISM_MIN: u32 = 1;
const ARGON2_PRELOGIN_PARALLELISM_MAX: u32 = 16;

/// Bitwarden KDF configuration returned by prelogin.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KdfConfig {
    /// PBKDF2-HMAC-SHA256 configuration.
    Pbkdf2Sha256 {
        /// Iteration count returned by the server.
        iterations: u32,
    },
    /// Argon2id configuration.
    Argon2id {
        /// Iteration count.
        iterations: u32,
        /// Memory cost in MiB, matching Bitwarden prelogin responses.
        memory_mib: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
}

impl KdfConfig {
    /// Validate prelogin KDF bounds before expensive derivation.
    ///
    /// # Errors
    ///
    /// Returns an error when server-provided KDF parameters are below current
    /// Bitwarden prelogin minimums or above current Bitwarden setting maximums.
    pub fn validate_for_prelogin(&self) -> Result<(), KeyDerivationError> {
        match *self {
            Self::Pbkdf2Sha256 { iterations } => validate_kdf_bounds(
                "pbkdf2_iterations",
                iterations,
                PBKDF2_PRELOGIN_ITERATIONS_MIN,
                PBKDF2_PRELOGIN_ITERATIONS_MAX,
            )?,
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                validate_kdf_bounds(
                    "argon2_iterations",
                    iterations,
                    ARGON2_PRELOGIN_ITERATIONS_MIN,
                    ARGON2_PRELOGIN_ITERATIONS_MAX,
                )?;
                validate_kdf_bounds(
                    "argon2_memory_mib",
                    memory_mib,
                    ARGON2_PRELOGIN_MEMORY_MIB_MIN,
                    ARGON2_PRELOGIN_MEMORY_MIB_MAX,
                )?;
                validate_kdf_bounds(
                    "argon2_parallelism",
                    parallelism,
                    ARGON2_PRELOGIN_PARALLELISM_MIN,
                    ARGON2_PRELOGIN_PARALLELISM_MAX,
                )?;
            }
        }

        Ok(())
    }
}

fn validate_kdf_bounds(
    parameter: &'static str,
    actual: u32,
    minimum: u32,
    maximum: u32,
) -> Result<(), KeyDerivationError> {
    if actual < minimum {
        return Err(KeyDerivationError::KdfDowngrade {
            parameter,
            actual,
            minimum,
        });
    }

    if actual > maximum {
        return Err(KeyDerivationError::KdfTooExpensive {
            parameter,
            actual,
            maximum,
        });
    }

    Ok(())
}

/// 32-byte master key material derived from the master password.
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_LENGTH],
}

impl MasterKey {
    /// Return the raw master key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LENGTH] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for MasterKey {
    type Error = KeyDerivationError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() != MASTER_KEY_LENGTH {
            return Err(KeyDerivationError::InvalidMasterKeyLength { actual: raw.len() });
        }

        let mut bytes = [0_u8; MASTER_KEY_LENGTH];
        bytes.copy_from_slice(raw);
        Ok(Self { bytes })
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Data required to unlock the user key with a master password.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MasterPasswordUnlockData {
    /// Master-password salt, currently the user's email.
    pub salt: String,
    /// Server-provided KDF config.
    pub kdf: KdfConfig,
    /// User key encrypted by the stretched master key.
    pub master_key_wrapped_user_key: String,
}

impl MasterPasswordUnlockData {
    /// Derive the master key from `password` and unwrap the user key.
    ///
    /// # Errors
    ///
    /// Returns an error when KDF parameters fail downgrade validation,
    /// derivation fails, or the wrapped user key cannot be decrypted.
    pub fn unlock_user_key(
        &self,
        password: &str,
    ) -> Result<AuthenticatedSymmetricKey, KeyDerivationError> {
        let master_key = derive_master_key(password, &self.salt, &self.kdf)?;
        unwrap_user_key_with_master_key(&master_key, &self.master_key_wrapped_user_key)
    }
}

/// Derive a Bitwarden master key from a master password and salt.
///
/// # Errors
///
/// Returns an error when KDF parameters fail validation or derivation fails.
pub fn derive_master_key(
    password: &str,
    salt: &str,
    kdf: &KdfConfig,
) -> Result<MasterKey, KeyDerivationError> {
    if password.is_empty() {
        return Err(KeyDerivationError::EmptyPassword);
    }

    kdf.validate_for_prelogin()?;

    match *kdf {
        KdfConfig::Pbkdf2Sha256 { iterations } => {
            let normalized_salt = normalize_master_password_salt(salt);
            let mut derived = [0_u8; MASTER_KEY_LENGTH];
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                normalized_salt.as_bytes(),
                iterations,
                &mut derived,
            );
            Ok(MasterKey { bytes: derived })
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or(KeyDerivationError::InvalidArgon2Parameters)?;
            let params = Params::new(memory_kib, iterations, parallelism, Some(MASTER_KEY_LENGTH))
                .map_err(|_| KeyDerivationError::InvalidArgon2Parameters)?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let normalized_salt = normalize_master_password_salt(salt);
            let mut derived = [0_u8; MASTER_KEY_LENGTH];

            argon2
                .hash_password_into(
                    password.as_bytes(),
                    normalized_salt.as_bytes(),
                    &mut derived,
                )
                .map_err(|_| KeyDerivationError::Argon2Failed)?;

            Ok(MasterKey { bytes: derived })
        }
    }
}

/// Compute the base64 master-password authentication hash sent to the server.
///
/// # Errors
///
/// Returns an error when the password is empty.
pub fn master_password_authentication_hash(
    password: &str,
    master_key: &MasterKey,
) -> Result<String, KeyDerivationError> {
    if password.is_empty() {
        return Err(KeyDerivationError::EmptyPassword);
    }

    let mut hash = [0_u8; MASTER_KEY_LENGTH];
    pbkdf2_hmac::<Sha256>(
        master_key.as_bytes(),
        password.as_bytes(),
        AUTHENTICATION_HASH_ITERATIONS,
        &mut hash,
    );

    let encoded = STANDARD.encode(hash);
    hash.zeroize();

    Ok(encoded)
}

/// Stretch a 32-byte master key into the 64-byte AES-CBC/HMAC key.
///
/// # Errors
///
/// Returns an error if HKDF expansion fails.
pub fn stretch_master_key(
    master_key: &MasterKey,
) -> Result<AuthenticatedSymmetricKey, KeyDerivationError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key.as_bytes()).map_err(|_| {
        KeyDerivationError::InvalidMasterKeyLength {
            actual: MASTER_KEY_LENGTH,
        }
    })?;
    let mut stretched = [0_u8; 64];

    let result = (|| {
        hkdf.expand(b"enc", &mut stretched[..32])
            .map_err(|_| KeyDerivationError::HkdfExpandFailed)?;
        hkdf.expand(b"mac", &mut stretched[32..])
            .map_err(|_| KeyDerivationError::HkdfExpandFailed)?;

        AuthenticatedSymmetricKey::try_from(stretched.as_slice()).map_err(KeyDerivationError::from)
    })();
    stretched.zeroize();

    result
}

/// Decrypt a master-key-wrapped user key with a derived master key.
///
/// # Errors
///
/// Returns an error if the stretched master key cannot decrypt a valid 64-byte
/// user key.
pub fn unwrap_user_key_with_master_key(
    master_key: &MasterKey,
    encrypted_user_key: &str,
) -> Result<AuthenticatedSymmetricKey, KeyDerivationError> {
    let wrapping_key = stretch_master_key(master_key)?;
    let encrypted = encrypted_user_key.parse::<EncryptedString>()?;
    let mut plain = encrypted.decrypt_bytes(&wrapping_key)?;
    let user_key =
        AuthenticatedSymmetricKey::try_from(plain.as_slice()).map_err(KeyDerivationError::from);
    plain.zeroize();

    user_key
}

/// Normalize the Bitwarden master-password salt.
#[must_use]
pub fn normalize_master_password_salt(salt: &str) -> String {
    salt.trim().to_lowercase()
}

/// Key derivation and unlock errors.
#[derive(Debug, Error)]
pub enum KeyDerivationError {
    /// Master password was empty.
    #[error("master password must not be empty")]
    EmptyPassword,
    /// The server provided KDF parameters below current prelogin minimums.
    #[error("KDF parameter {parameter} was {actual}, below minimum {minimum}")]
    KdfDowngrade {
        /// Parameter name.
        parameter: &'static str,
        /// Actual server-provided value.
        actual: u32,
        /// Minimum accepted value.
        minimum: u32,
    },
    /// The server provided KDF parameters above current setting maximums.
    #[error("KDF parameter {parameter} was {actual}, above maximum {maximum}")]
    KdfTooExpensive {
        /// Parameter name.
        parameter: &'static str,
        /// Actual server-provided value.
        actual: u32,
        /// Maximum accepted value.
        maximum: u32,
    },
    /// Argon2 parameters are invalid.
    #[error("invalid Argon2id parameters")]
    InvalidArgon2Parameters,
    /// Argon2 derivation failed.
    #[error("Argon2id key derivation failed")]
    Argon2Failed,
    /// Master key had an invalid byte length.
    #[error("invalid master key length {actual}, expected 32 bytes")]
    InvalidMasterKeyLength {
        /// Actual byte length.
        actual: usize,
    },
    /// HKDF expansion failed.
    #[error("HKDF expansion failed")]
    HkdfExpandFailed,
    /// Crypto failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    const SALT: &str = " User@Example.COM ";
    const MASTER_KEY_B64: &str = "Us4tM+AHp8FbPjCDxVH8/5fagwRfqAzGu70svFLG8IQ=";
    const ARGON2_MASTER_KEY_B64: &str = "Ps6Z+SOMDzbctMokT/CfLACJ1AIaJP7kX5wU0Ikj7QI=";
    const AUTH_HASH_B64: &str = "0FMeontUyfpu9Ga/DvERL9LMAXg9KB82VK6UqHdnKko=";
    const STRETCHED_B64: &str =
        "g7edjE9X8uarBORCfD/MDZve/5gSVKU1o98r0qTfhKcBYUmp65EqPZpBxLOHioM+PKyI/u+Z3EsaYlhxYRPogQ==";
    const USER_KEY_B64: &str =
        "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+vw==";
    const ENCRYPTED_USER_KEY: &str =
        "2.wMHCw8TFxsfIycrLzM3Ozw==|OzSTzQsUvGEm0sPHk/r/6/ABPF6nkeB53PGOwLcPqtRmD37wFfsUjSwOb/Xfi+k3QJ0GsB1UlWEkqd5w0TMNaZ/9nOvx3WDUj73EzDHJH4w=|7JbVebynrqWIyNMufwrk4K16dBxoXKB1PBX+CxNgOGE=";

    #[test]
    fn derives_pbkdf2_master_key() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = derive_master_key(
            PASSWORD,
            SALT,
            &KdfConfig::Pbkdf2Sha256 { iterations: 5_000 },
        )?;

        assert_eq!(STANDARD.encode(master_key.as_bytes()), MASTER_KEY_B64);
        Ok(())
    }

    #[test]
    fn derives_argon2id_master_key() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = derive_master_key(
            PASSWORD,
            SALT,
            &KdfConfig::Argon2id {
                iterations: 2,
                memory_mib: 16,
                parallelism: 1,
            },
        )?;

        assert_eq!(
            STANDARD.encode(master_key.as_bytes()),
            ARGON2_MASTER_KEY_B64
        );
        Ok(())
    }

    #[test]
    fn computes_master_password_authentication_hash() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = derive_master_key(
            PASSWORD,
            SALT,
            &KdfConfig::Pbkdf2Sha256 { iterations: 5_000 },
        )?;

        assert_eq!(
            master_password_authentication_hash(PASSWORD, &master_key)?,
            AUTH_HASH_B64
        );
        Ok(())
    }

    #[test]
    fn stretches_master_key_with_hkdf_expand() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = derive_master_key(
            PASSWORD,
            SALT,
            &KdfConfig::Pbkdf2Sha256 { iterations: 5_000 },
        )?;
        let stretched = stretch_master_key(&master_key)?;
        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(stretched.encryption_key());
        encoded.extend_from_slice(stretched.authentication_key());

        assert_eq!(STANDARD.encode(encoded), STRETCHED_B64);
        Ok(())
    }

    #[test]
    fn unwraps_user_key_from_master_password() -> Result<(), Box<dyn std::error::Error>> {
        let unlock = MasterPasswordUnlockData {
            salt: SALT.to_string(),
            kdf: KdfConfig::Pbkdf2Sha256 { iterations: 5_000 },
            master_key_wrapped_user_key: ENCRYPTED_USER_KEY.to_string(),
        };

        let user_key = unlock.unlock_user_key(PASSWORD)?;
        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(user_key.encryption_key());
        encoded.extend_from_slice(user_key.authentication_key());

        assert_eq!(STANDARD.encode(encoded), USER_KEY_B64);
        Ok(())
    }

    #[test]
    fn rejects_prelogin_downgrade() {
        let error = derive_master_key(
            PASSWORD,
            SALT,
            &KdfConfig::Pbkdf2Sha256 { iterations: 4_999 },
        )
        .err();

        assert!(matches!(
            error,
            Some(KeyDerivationError::KdfDowngrade {
                parameter: "pbkdf2_iterations",
                ..
            })
        ));
    }

    #[test]
    fn rejects_pbkdf2_resource_excess() {
        let error = KdfConfig::Pbkdf2Sha256 {
            iterations: 2_000_001,
        }
        .validate_for_prelogin()
        .err();

        assert!(matches!(
            error,
            Some(KeyDerivationError::KdfTooExpensive {
                parameter: "pbkdf2_iterations",
                ..
            })
        ));
    }

    #[test]
    fn rejects_argon2_prelogin_downgrade() {
        let error = KdfConfig::Argon2id {
            iterations: 2,
            memory_mib: 15,
            parallelism: 1,
        }
        .validate_for_prelogin()
        .err();

        assert!(matches!(
            error,
            Some(KeyDerivationError::KdfDowngrade {
                parameter: "argon2_memory_mib",
                ..
            })
        ));
    }

    #[test]
    fn rejects_argon2_resource_excess() {
        let error = KdfConfig::Argon2id {
            iterations: 2,
            memory_mib: 1025,
            parallelism: 1,
        }
        .validate_for_prelogin()
        .err();

        assert!(matches!(
            error,
            Some(KeyDerivationError::KdfTooExpensive {
                parameter: "argon2_memory_mib",
                ..
            })
        ));
    }

    #[test]
    fn accepts_prelogin_boundary_values() -> Result<(), Box<dyn std::error::Error>> {
        KdfConfig::Pbkdf2Sha256 {
            iterations: PBKDF2_PRELOGIN_ITERATIONS_MIN,
        }
        .validate_for_prelogin()?;
        KdfConfig::Pbkdf2Sha256 {
            iterations: PBKDF2_PRELOGIN_ITERATIONS_MAX,
        }
        .validate_for_prelogin()?;
        KdfConfig::Argon2id {
            iterations: ARGON2_PRELOGIN_ITERATIONS_MIN,
            memory_mib: ARGON2_PRELOGIN_MEMORY_MIB_MIN,
            parallelism: ARGON2_PRELOGIN_PARALLELISM_MIN,
        }
        .validate_for_prelogin()?;
        KdfConfig::Argon2id {
            iterations: ARGON2_PRELOGIN_ITERATIONS_MAX,
            memory_mib: ARGON2_PRELOGIN_MEMORY_MIB_MAX,
            parallelism: ARGON2_PRELOGIN_PARALLELISM_MAX,
        }
        .validate_for_prelogin()?;
        Ok(())
    }

    #[test]
    fn validates_master_key_length_boundaries() {
        let Err(short) = MasterKey::try_from([0_u8; MASTER_KEY_LENGTH - 1].as_slice()) else {
            unreachable!("short master key should fail");
        };
        assert!(matches!(
            short,
            KeyDerivationError::InvalidMasterKeyLength { actual }
            if actual == MASTER_KEY_LENGTH - 1
        ));

        let Err(long) = MasterKey::try_from([0_u8; MASTER_KEY_LENGTH + 1].as_slice()) else {
            unreachable!("long master key should fail");
        };
        assert!(matches!(
            long,
            KeyDerivationError::InvalidMasterKeyLength { actual }
            if actual == MASTER_KEY_LENGTH + 1
        ));

        let Ok(_) = MasterKey::try_from([0_u8; MASTER_KEY_LENGTH].as_slice()) else {
            unreachable!("exact master key length should be accepted");
        };
    }
}
