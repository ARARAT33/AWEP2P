use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryObjectType {
    Tld,
    Domain,
    UserTld,
    DelegatedOperator,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TldKind {
    Otld,
    ThreeOtld,
    Ctld,
    Oatld,
    Octld,
    Vtld,
    Autl,
    Atld,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryStatus {
    Active,
    Warning,
    Suspended,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryRecord {
    pub object_type: RegistryObjectType,
    pub kind: Option<TldKind>,
    pub name: String,
    pub owner_public_key: Vec<u8>,
    pub parent: Option<String>,
    pub status: RegistryStatus,
    pub sequence: u64,
    pub content_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl RegistryRecord {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("registry record serialization must be infallible")
    }
    pub fn calculate_content_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"AWE-REGISTRY-V1\0");
        h.update(self.canonical_bytes());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    records: BTreeMap<String, RegistryRecord>,
}

impl Registry {
    pub fn insert(&mut self, record: RegistryRecord) -> Result<(), &'static str> {
        if record.name.is_empty() || record.sequence == 0 {
            return Err("invalid registry record");
        }
        if record.name.ends_with(".awea") && record.kind != Some(TldKind::Atld) {
            return Err("protected administrative namespace");
        }
        if let Some(old) = self.records.get(&record.name) {
            if record.sequence <= old.sequence {
                return Err("stale registry sequence");
            }
        }
        self.records.insert(record.name.clone(), record);
        Ok(())
    }
    pub fn insert_verified(&mut self, record: RegistryRecord) -> Result<(), &'static str> {
        if !record.verify_signature() {
            return Err("invalid registry record signature");
        }
        self.insert(record)
    }

    pub fn resolve(&self, name: &str) -> Option<&RegistryRecord> {
        self.records.get(name)
    }
    pub fn snapshot(&self) -> Vec<&RegistryRecord> {
        self.records.values().collect()
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_record_roundtrip() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut record = RegistryRecord {
            object_type: RegistryObjectType::Domain,
            kind: None,
            name: "portal.awe".into(),
            owner_public_key: signing.verifying_key().to_bytes().to_vec(),
            parent: Some("awe".into()),
            status: RegistryStatus::Active,
            sequence: 1,
            content_hash: [0u8; 32],
            signature: Vec::new(),
        };
        record.content_hash = record.calculate_content_hash();
        record.signature = ed25519_dalek::Signer::sign(&signing, &record.signable_bytes())
            .to_bytes()
            .to_vec();

        assert!(record.verify_signature());
        let mut registry = Registry::default();
        assert!(registry.insert_verified(record.clone()).is_ok());
        assert_eq!(registry.resolve("portal.awe"), Some(&record));
    }

    #[test]
    fn tampering_breaks_signature() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let mut record = RegistryRecord {
            object_type: RegistryObjectType::Domain,
            kind: None,
            name: "site.awe".into(),
            owner_public_key: signing.verifying_key().to_bytes().to_vec(),
            parent: Some("awe".into()),
            status: RegistryStatus::Active,
            sequence: 1,
            content_hash: [0u8; 32],
            signature: Vec::new(),
        };
        record.content_hash = record.calculate_content_hash();
        record.signature = ed25519_dalek::Signer::sign(&signing, &record.signable_bytes())
            .to_bytes()
            .to_vec();
        assert!(record.verify_signature());
        record.name = "evil.awe".into();
        assert!(!record.verify_signature());
    }
}
