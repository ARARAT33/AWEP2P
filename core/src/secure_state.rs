use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io, path::Path};

const MAGIC: &[u8] = b"AWE-STATE/v1\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SecureStateError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid encrypted state envelope")]
    InvalidEnvelope,
    #[error("encryption/decryption failed")]
    Crypto,
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
}

pub fn save_json<T: Serialize>(
    path: &Path,
    value: &T,
    passphrase: &str,
) -> Result<(), SecureStateError> {
    if passphrase.is_empty() {
        return Err(SecureStateError::EmptyPassphrase);
    }

    let plaintext = serde_json::to_vec(value)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| SecureStateError::Crypto)?;
    let salt_string = SaltString::encode_b64(salt).map_err(|_| SecureStateError::Crypto)?;
    let password_hash = Argon2::default()
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|_| SecureStateError::Crypto)?;
    let digest = password_hash.hash.ok_or(SecureStateError::Crypto)?;
    let key = Key::from_slice(&digest.as_bytes()[..32]);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| SecureStateError::Crypto)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| SecureStateError::Crypto)?;

    let mut envelope = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    fs::write(path, envelope)?;
    Ok(())
}

pub fn load_json<T: DeserializeOwned>(
    path: &Path,
    passphrase: &str,
) -> Result<T, SecureStateError> {
    if passphrase.is_empty() {
        return Err(SecureStateError::EmptyPassphrase);
    }

    let envelope = fs::read(path)?;
    if envelope.len() < MAGIC.len() + SALT_LEN + NONCE_LEN || !envelope.starts_with(MAGIC) {
        return Err(SecureStateError::InvalidEnvelope);
    }

    let salt_start = MAGIC.len();
    let nonce_start = salt_start + SALT_LEN;
    let salt = &envelope[salt_start..nonce_start];
    let nonce = &envelope[nonce_start..nonce_start + NONCE_LEN];
    let salt_string = SaltString::encode_b64(salt).map_err(|_| SecureStateError::Crypto)?;
    let password_hash = Argon2::default()
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|_| SecureStateError::Crypto)?;
    let digest = password_hash.hash.ok_or(SecureStateError::Crypto)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&digest.as_bytes()[..32]));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            &envelope[nonce_start + NONCE_LEN..],
        )
        .map_err(|_| SecureStateError::Crypto)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Fixture {
        node_id: String,
        offered_bytes: u64,
    }

    #[test]
    fn round_trip_is_encrypted_and_authenticated() {
        let path = std::env::temp_dir().join(format!("awe-state-{}.bin", std::process::id()));
        let value = Fixture {
            node_id: "nid-test".into(),
            offered_bytes: 42,
        };
        save_json(&path, &value, "correct horse battery staple").unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(!raw.windows(b"nid-test".len()).any(|w| w == b"nid-test"));
        let decoded: Fixture = load_json(&path, "correct horse battery staple").unwrap();
        assert_eq!(decoded, value);
        assert!(load_json::<Fixture>(&path, "wrong").is_err());
        let _ = fs::remove_file(path);
    }
}
