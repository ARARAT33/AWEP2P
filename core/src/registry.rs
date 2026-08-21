use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryObjectType {
    Tld,
    Domain,
    UserTld,
    DelegatedOperator,
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
    pub name: String,
    pub owner_public_key: Vec<u8>,
    pub status: RegistryStatus,
    pub sequence: u64,
    pub content_hash: [u8; 32],
}

impl RegistryRecord {
    pub fn calculate_content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "{:?}|{}|{:?}|{}",
            self.object_type, self.name, self.status, self.sequence
        ));
        hasher.update(&self.owner_public_key);
        hasher.finalize().into()
    }
}
