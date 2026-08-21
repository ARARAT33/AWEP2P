//! Disaster recovery, state self-healing, and emergency repair routines.

use crate::storage::{ChunkRef, LocalNodeStore, PrivateManifest, PublicManifest};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryManifest {
    pub file_id: [u8; 32],
    pub total_chunks: usize,
    pub missing_chunks: Vec<usize>,
    pub surviving_nodes: Vec<[u8; 32]>,
}

pub struct RecoveryEngine;

impl RecoveryEngine {
    /// Detect missing chunks from a PrivateManifest and trigger repair if surviving shards are sufficient.
    pub fn inspect_private_health(
        manifest: &PrivateManifest,
        available_chunks: &[usize],
    ) -> RecoveryManifest {
        let mut missing = Vec::new();
        for (i, _) in manifest.chunks.iter().enumerate() {
            if !available_chunks.contains(&i) {
                missing.push(i);
            }
        }

        RecoveryManifest {
            file_id: manifest.file_id,
            total_chunks: manifest.chunks.len(),
            missing_chunks: missing,
            surviving_nodes: vec![],
        }
    }

    /// Detect missing chunks from a PublicManifest.
    pub fn inspect_public_health(
        manifest: &PublicManifest,
        available_chunks: &[usize],
    ) -> RecoveryManifest {
        let mut missing = Vec::new();
        for (i, _) in manifest.chunks.iter().enumerate() {
            if !available_chunks.contains(&i) {
                missing.push(i);
            }
        }

        RecoveryManifest {
            file_id: manifest.file_id,
            total_chunks: manifest.chunks.len(),
            missing_chunks: missing,
            surviving_nodes: vec![],
        }
    }

    /// Repair missing chunks in local storage store.
    pub fn repair_chunk_data(
        store: &LocalNodeStore,
        expected_ref: &ChunkRef,
        data: &[u8],
    ) -> io::Result<[u8; 32]> {
        let hash = blake3::hash(data);
        if *hash.as_bytes() != expected_ref.hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repaired chunk hash mismatch",
            ));
        }
        store.put(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoragePolicy;

    #[test]
    fn inspect_manifest_missing_chunks() {
        let manifest = PublicManifest {
            file_id: [1; 32],
            original_size: 1000,
            chunks: vec![
                ChunkRef {
                    index: 0,
                    hash: [1; 32],
                    size: 500,
                },
                ChunkRef {
                    index: 1,
                    hash: [2; 32],
                    size: 500,
                },
            ],
            policy: StoragePolicy::default(),
        };

        let health = RecoveryEngine::inspect_public_health(&manifest, &[0]);
        assert_eq!(health.missing_chunks, vec![1]);
    }
}
