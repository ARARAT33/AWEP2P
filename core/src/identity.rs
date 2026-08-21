use sha2::{Digest, Sha256};

/// Stable public identifier derived from an AWE identity public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AweId([u8; 32]);

impl AweId {
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let digest = Sha256::digest(public_key);
        Self(digest.into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Human-facing username. Authentication must never rely on the username alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 64 {
            return Err("username length is invalid");
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("username contains unsupported characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
