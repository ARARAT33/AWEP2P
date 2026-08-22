use crate::crypto::hash;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const VAULT_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AweId([u8; 32]);
impl AweId {
    pub fn from_public_key(public_key: &[u8]) -> Self {
        Self(hash(b"AWE-ID/v1", public_key))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Username(String);
impl Username {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("invalid username");
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublic {
    pub username: Username,
    pub awe_id: AweId,
    pub public_key: [u8; 32],
}

pub struct Identity {
    signing_key: SigningKey,
    pub public: IdentityPublic,
}
impl Identity {
    pub fn generate(username: Username) -> Self {
        Self::from_signing_key(username, SigningKey::generate(&mut OsRng))
    }
    fn from_signing_key(username: Username, signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        let awe_id = AweId::from_public_key(&public_key);
        Self {
            signing_key,
            public: IdentityPublic {
                username,
                awe_id,
                public_key,
            },
        }
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(public_key)
            .ok()
            .and_then(|k| k.verify(message, &Signature::from_bytes(signature)).ok())
            .is_some()
    }
    pub fn export_secret(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
    pub fn from_secret(username: Username, secret: [u8; 32]) -> Self {
        Self::from_signing_key(username, SigningKey::from_bytes(&secret))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AweSecret {
    pub username: String,
    pub awe_id: String,
    pub secret_key: String,
    pub public_key: String,
    pub signature: String,
}

impl AweSecret {
    pub fn generate(identity: &Identity) -> Self {
        let username = identity.public.username.as_str().to_string();
        let awe_id = identity.public.awe_id.to_hex();
        let secret_key = hex::encode(identity.export_secret());
        let public_key = hex::encode(identity.public.public_key);

        let msg = format!("{}:{}:{}:{}", username, awe_id, secret_key, public_key);
        let sig_bytes = identity.sign(msg.as_bytes());
        let signature = hex::encode(sig_bytes);

        Self {
            username,
            awe_id,
            secret_key,
            public_key,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let secret: Self = serde_json::from_slice(bytes)
            .map_err(|e| format!("Invalid or corrupted .awesecret file: {e}"))?;
        secret.verify_integrity()?;
        Ok(secret)
    }

    pub fn verify_integrity(&self) -> Result<(), String> {
        let pub_bytes = hex::decode(&self.public_key)
            .map_err(|_| "Invalid public_key encoding in .awesecret".to_string())?;
        if pub_bytes.len() != 32 {
            return Err("Invalid public_key length in .awesecret".to_string());
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pub_bytes);

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| "Invalid signature encoding in .awesecret".to_string())?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length in .awesecret".to_string());
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        let calculated_id = AweId::from_public_key(&pk).to_hex();
        if calculated_id != self.awe_id {
            return Err("Tampered .awesecret: AWE-ID does not match public key".to_string());
        }

        let msg = format!(
            "{}:{}:{}:{}",
            self.username, self.awe_id, self.secret_key, self.public_key
        );

        if !Identity::verify(&pk, msg.as_bytes(), &sig) {
            return Err(
                "Tampered .awesecret: Cryptographic signature verification failed".to_string(),
            );
        }

        Ok(())
    }

    pub fn authenticate(&self) -> Result<Identity, String> {
        self.verify_integrity()?;
        let username = Username::new(&self.username).map_err(|e| e.to_string())?;
        let secret_bytes = hex::decode(&self.secret_key).map_err(|e| e.to_string())?;
        if secret_bytes.len() != 32 {
            return Err("Invalid secret key length in .awesecret".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&secret_bytes);
        let identity = Identity::from_secret(username, key);
        if identity.public.awe_id.to_hex() != self.awe_id {
            return Err("Mismatching AWE-ID in .awesecret".to_string());
        }
        if identity.public.public_key != hex::decode(&self.public_key).unwrap().as_slice() {
            return Err("Mismatching public key in .awesecret".to_string());
        }
        Ok(identity)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid vault format")]
    InvalidFormat,
    #[error("invalid password")]
    InvalidPassword,
    #[error("encryption failed")]
    Encryption,
    #[error("password hashing failed")]
    PasswordHash,
}

#[derive(Serialize, Deserialize)]
struct VaultRecord {
    version: u16,
    password_hash: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub struct LocalVault;
impl LocalVault {
    pub fn seal(identity: &Identity, password: &str) -> Result<Vec<u8>, VaultError> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| VaultError::PasswordHash)?
            .to_string();
        let parsed = PasswordHash::new(&password_hash).map_err(|_| VaultError::PasswordHash)?;
        let key_material = parsed.hash.ok_or(VaultError::PasswordHash)?;
        let key = Sha256::digest(key_material.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Encryption)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let secret = identity.export_secret();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_ref())
            .map_err(|_| VaultError::Encryption)?;
        serde_json::to_vec(&VaultRecord {
            version: VAULT_VERSION,
            password_hash,
            nonce: nonce_bytes,
            ciphertext,
        })
        .map_err(|_| VaultError::InvalidFormat)
    }
    pub fn open(data: &[u8], username: Username, password: &str) -> Result<Identity, VaultError> {
        let record: VaultRecord =
            serde_json::from_slice(data).map_err(|_| VaultError::InvalidFormat)?;
        if record.version != VAULT_VERSION {
            return Err(VaultError::InvalidFormat);
        }
        let parsed =
            PasswordHash::new(&record.password_hash).map_err(|_| VaultError::InvalidFormat)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| VaultError::InvalidPassword)?;
        let key_material = parsed.hash.ok_or(VaultError::InvalidFormat)?;
        let key = Sha256::digest(key_material.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Encryption)?;
        let mut secret = cipher
            .decrypt(Nonce::from_slice(&record.nonce), record.ciphertext.as_ref())
            .map_err(|_| VaultError::InvalidPassword)?;
        if secret.len() != 32 {
            secret.zeroize();
            return Err(VaultError::InvalidFormat);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&secret);
        secret.zeroize();
        Ok(Identity::from_secret(username, bytes))
    }
}

pub fn secure_random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0u8; N]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_sign_verify() {
        let i = Identity::generate(Username::new("ararat").unwrap());
        let m = b"awe";
        let s = i.sign(m);
        assert!(Identity::verify(&i.public.public_key, m, &s));
        assert!(!Identity::verify(&i.public.public_key, b"other", &s));
    }
    #[test]
    fn vault_roundtrip() {
        let i = Identity::generate(Username::new("ararat").unwrap());
        let v = LocalVault::seal(&i, "correct horse battery staple").unwrap();
        let r = LocalVault::open(
            &v,
            i.public.username.clone(),
            "correct horse battery staple",
        )
        .unwrap();
        assert_eq!(i.public.awe_id, r.public.awe_id);
        assert_eq!(i.export_secret(), r.export_secret());
    }
    #[test]
    fn bad_password_fails() {
        let i = Identity::generate(Username::new("ararat").unwrap());
        let v = LocalVault::seal(&i, "secret").unwrap();
        assert!(LocalVault::open(&v, i.public.username.clone(), "wrong").is_err());
    }
    #[test]
    fn awesecret_generate_and_auth() {
        let i = Identity::generate(Username::new("ararat").unwrap());
        let secret = AweSecret::generate(&i);
        let bytes = secret.to_bytes().unwrap();
        let loaded = AweSecret::from_bytes(&bytes).unwrap();
        let auth_id = loaded.authenticate().unwrap();
        assert_eq!(i.public.awe_id, auth_id.public.awe_id);
    }
    #[test]
    fn random_is_nonconstant() {
        assert_ne!(
            secure_random::<32>().as_ref(),
            secure_random::<32>().as_ref()
        );
    }
}
