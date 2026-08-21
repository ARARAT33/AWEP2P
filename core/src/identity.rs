use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
use crate::crypto::hash;

const VAULT_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AweId([u8; 32]);
impl AweId {
    pub fn from_public_key(public_key: &[u8]) -> Self { Self(hash(b"AWE-ID/v1", public_key)) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Username(String);
impl Username {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { return Err("invalid username"); }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPublic { pub username: Username, pub awe_id: AweId, pub public_key: [u8; 32] }

pub struct Identity { signing_key: SigningKey, pub public: IdentityPublic }
impl Identity {
    pub fn generate(username: Username) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let awe_id = AweId::from_public_key(&public_key);
        Self { signing_key, public: IdentityPublic { username, awe_id, public_key } }
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] { self.signing_key.sign(message).to_bytes() }
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(public_key).ok().and_then(|k| k.verify(message, &Signature::from_bytes(signature)).ok()).is_some()
    }
    pub fn export_secret(&self) -> [u8; 32] { self.signing_key.to_bytes() }
    pub fn from_secret(username: Username, secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();
        Self { signing_key, public: IdentityPublic { username, awe_id: AweId::from_public_key(&public_key), public_key } }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError { #[error("invalid vault format")] InvalidFormat, #[error("invalid password")] InvalidPassword, #[error("encryption failed")] Encryption, #[error("password hashing failed")] PasswordHash }

#[derive(Serialize, Deserialize)]
struct VaultRecord { version: u16, salt: String, nonce: [u8; 12], ciphertext: Vec<u8> }

/// Password-protected local identity vault. The plaintext secret is never serialized.
pub struct LocalVault;
impl LocalVault {
    pub fn seal(identity: &Identity, password: &str) -> Result<Vec<u8>, VaultError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon = Argon2::default();
        let hash = argon.hash_password(password.as_bytes(), &salt).map_err(|_| VaultError::PasswordHash)?;
        let key_material = hash.hash.ok_or(VaultError::PasswordHash)?;
        let key = Sha256::digest(key_material.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Encryption)?;
        let nonce_bytes: [u8; 12] = rand::random();
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), identity.export_secret().as_ref()).map_err(|_| VaultError::Encryption)?;
        let record = VaultRecord { version: VAULT_VERSION, salt: salt.to_string(), nonce: nonce_bytes, ciphertext };
        serde_json::to_vec(&record).map_err(|_| VaultError::InvalidFormat)
    }

    pub fn open(data: &[u8], username: Username, password: &str) -> Result<Identity, VaultError> {
        let record: VaultRecord = serde_json::from_slice(data).map_err(|_| VaultError::InvalidFormat)?;
        if record.version != VAULT_VERSION { return Err(VaultError::InvalidFormat); }
        let parsed = PasswordHash::new(&record.salt).map_err(|_| VaultError::InvalidFormat)?;
        Argon2::default().verify_password(password.as_bytes(), &parsed).map_err(|_| VaultError::InvalidPassword)?;
        let key_material = parsed.hash.ok_or(VaultError::InvalidFormat)?;
        let key = Sha256::digest(key_material.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Encryption)?;
        let mut secret = cipher.decrypt(Nonce::from_slice(&record.nonce), record.ciphertext.as_ref()).map_err(|_| VaultError::InvalidPassword)?;
        if secret.len() != 32 { secret.zeroize(); return Err(VaultError::InvalidFormat); }
        let mut bytes = [0u8; 32]; bytes.copy_from_slice(&secret); secret.zeroize();
        Ok(Identity::from_secret(username, bytes))
    }
}

pub fn secure_random<const N: usize>() -> Zeroizing<[u8; N]> { Zeroizing::new(rand::random()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn identity_sign_verify() { let i = Identity::generate(Username::new("ararat").unwrap()); let m = b"awe"; let s = i.sign(m); assert!(Identity::verify(&i.public.public_key, m, &s)); }
    #[test] fn vault_roundtrip() { let i = Identity::generate(Username::new("ararat").unwrap()); let v = LocalVault::seal(&i, "correct horse battery staple").unwrap(); let r = LocalVault::open(&v, i.public.username.clone(), "correct horse battery staple").unwrap(); assert_eq!(i.public.awe_id, r.public.awe_id); }
    #[test] fn bad_password_fails() { let i = Identity::generate(Username::new("ararat").unwrap()); let v = LocalVault::seal(&i, "secret").unwrap(); assert!(LocalVault::open(&v, i.public.username.clone(), "wrong").is_err()); }
}
