use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryObjectType { Tld, Domain, UserTld, DelegatedOperator }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TldKind { Otld, ThreeOtld, Ctld, Oatld, Octld, Vtld, Autl, Atld }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryStatus { Active, Warning, Suspended, Quarantined, Revoked }

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
        let mut h = Sha256::new(); h.update(b"AWE-REGISTRY-V1\0"); h.update(self.canonical_bytes()); h.finalize().into()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    records: BTreeMap<String, RegistryRecord>,
}

impl Registry {
    pub fn insert(&mut self, record: RegistryRecord) -> Result<(), &'static str> {
        if record.name.is_empty() || record.sequence == 0 { return Err("invalid registry record"); }
        if record.name.ends_with(".awea") && record.kind != Some(TldKind::Atld) { return Err("protected administrative namespace"); }
        if let Some(old) = self.records.get(&record.name) {
            if record.sequence <= old.sequence { return Err("stale registry sequence"); }
        }
        self.records.insert(record.name.clone(), record); Ok(())
    }
    pub fn resolve(&self, name: &str) -> Option<&RegistryRecord> { self.records.get(name) }
    pub fn snapshot(&self) -> Vec<&RegistryRecord> { self.records.values().collect() }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}
