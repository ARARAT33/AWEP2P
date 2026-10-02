//! Distributed data-plane message types.
//! These are protocol-level objects for authenticated transports. They do not
//! claim that a live network transfer exists until a transport consumes them.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardRequest {
    pub request_id: [u8; 16],
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub total_shards: u16,
    pub expected_hash: [u8; 32],
    pub max_bytes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardResponse {
    pub request_id: [u8; 16],
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
}

impl ShardResponse {
    pub fn new(
        request_id: [u8; 16],
        file_id: [u8; 32],
        shard_index: u16,
        payload: Vec<u8>,
    ) -> Self {
        let payload_hash = *blake3::hash(&payload).as_bytes();
        Self {
            request_id,
            file_id,
            shard_index,
            payload,
            payload_hash,
        }
    }

    pub fn verify(&self, expected_hash: &[u8; 32]) -> bool {
        self.payload_hash == *blake3::hash(&self.payload).as_bytes()
            && self.payload_hash == *expected_hash
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    pub file_id: [u8; 32],
    pub filename: String,
    pub original_size: u64,
    pub shard_count: u16,
    pub replica_count: u8,
    pub shard_hashes: Vec<[u8; 32]>,
}

impl FileManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.shard_count != 1000 {
            return Err("AWEP2P file manifests require exactly 1000 shards".into());
        }
        if self.replica_count != 3 {
            return Err("AWEP2P file manifests require exactly 3 replicas per shard".into());
        }
        if self.shard_hashes.len() != 1000 {
            return Err("manifest must contain 1000 shard hashes".into());
        }
        if self.filename.is_empty() {
            return Err("filename must not be empty".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteManifest {
    pub site_id: [u8; 32],
    pub hostname: String,
    pub files: Vec<FileManifest>,
    pub version: u64,
}

impl SiteManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.hostname.is_empty() || self.hostname.len() > 253 {
            return Err("invalid site hostname".into());
        }
        if self.files.is_empty() {
            return Err("site must contain at least one file".into());
        }
        for file in &self.files {
            file.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairTask {
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub missing_replicas: u8,
    pub preferred_nodes: Vec<String>,
}

pub const STORAGE_STREAM: u32 = 200;
pub const STORAGE_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageShardRequest {
    pub version: u16,
    pub request_id: [u8; 16],
    pub requester: [u8; 32],
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub total_shards: u16,
    pub expected_hash: [u8; 32],
    pub original_size: u64,
    pub max_bytes: u32,
}

impl StorageShardRequest {
    pub fn new(
        request_id: [u8; 16],
        requester: [u8; 32],
        file_id: [u8; 32],
        shard_index: u16,
        total_shards: u16,
        expected_hash: [u8; 32],
        original_size: u64,
        max_bytes: u32,
    ) -> Self {
        Self {
            version: STORAGE_PROTOCOL_VERSION,
            request_id,
            requester,
            file_id,
            shard_index,
            total_shards,
            expected_hash,
            original_size,
            max_bytes,
        }
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.version != STORAGE_PROTOCOL_VERSION {
            return Err("unsupported storage request version".into());
        }
        if self.total_shards < 12 || self.total_shards > 1000 {
            return Err("storage request shard count out of range".into());
        }
        if self.shard_index >= self.total_shards {
            return Err("storage shard index out of range".into());
        }
        if self.max_bytes == 0 {
            return Err("storage request max_bytes must be non-zero".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageShardTransfer {
    pub version: u16,
    pub request_id: [u8; 16],
    pub sender: [u8; 32],
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub total_shards: u16,
    pub original_size: u64,
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
}

impl StorageShardTransfer {
    pub fn new(
        request_id: [u8; 16],
        sender: [u8; 32],
        file_id: [u8; 32],
        shard_index: u16,
        total_shards: u16,
        original_size: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: STORAGE_PROTOCOL_VERSION,
            request_id,
            sender,
            file_id,
            shard_index,
            total_shards,
            original_size,
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload,
        }
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.version != STORAGE_PROTOCOL_VERSION {
            return Err("unsupported storage transfer version".into());
        }
        if self.total_shards < 12 || self.total_shards > 1000 {
            return Err("storage transfer shard count out of range".into());
        }
        if self.shard_index as usize >= self.total_shards as usize {
            return Err("storage shard index out of range".into());
        }
        if self.payload_hash != *blake3::hash(&self.payload).as_bytes() {
            return Err("storage shard integrity check failed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageShardAck {
    pub version: u16,
    pub request_id: [u8; 16],
    pub file_id: [u8; 32],
    pub shard_index: u16,
    pub stored_object_id: [u8; 32],
}

impl StorageShardAck {
    pub fn new(
        request_id: [u8; 16],
        file_id: [u8; 32],
        shard_index: u16,
        stored_object_id: [u8; 32],
    ) -> Self {
        Self {
            version: STORAGE_PROTOCOL_VERSION,
            request_id,
            file_id,
            shard_index,
            stored_object_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_response_integrity_is_verified() {
        let response = ShardResponse::new([1; 16], [2; 32], 4, b"hello".to_vec());
        let hash = *blake3::hash(b"hello").as_bytes();
        assert!(response.verify(&hash));
        assert!(!response.verify(&[0; 32]));
    }

    #[test]
    fn file_manifest_requires_1000_and_three() {
        let m = FileManifest {
            file_id: [3; 32],
            filename: "index.html".into(),
            original_size: 5,
            shard_count: 1000,
            replica_count: 3,
            shard_hashes: vec![[0; 32]; 1000],
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn site_manifest_rejects_empty_sites() {
        let s = SiteManifest {
            site_id: [4; 32],
            hostname: "example.awe".into(),
            files: vec![],
            version: 1,
        };
        assert!(s.validate().is_err());
    }
}
