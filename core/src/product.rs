//! Unified product orchestration layer for AWEp2P.
//!
//! The existing protocol, identity, routing, storage, repair, namespace,
//! host, store and messenger modules remain the implementation building
//! blocks. This facade gives clients one stable product model.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PRODUCT_PROTOCOL: &str = "AWEP2P/1";
pub const DEFAULT_REPLICATION: u8 = 3;
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceId(pub String);

impl ResourceId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceManifest {
    pub id: ResourceId,
    pub size: u64,
    pub chunk_size: u64,
    pub chunks: u32,
    pub name: Option<String>,
    pub mime: Option<String>,
    pub encrypted: bool,
}

impl ResourceManifest {
    pub fn from_bytes(bytes: &[u8], name: Option<String>, mime: Option<String>) -> Self {
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let chunks = if bytes.is_empty() {
            0
        } else {
            bytes.len().div_ceil(chunk_size as usize) as u32
        };
        Self {
            id: ResourceId::from_bytes(bytes),
            size: bytes.len() as u64,
            chunk_size,
            chunks,
            name,
            mime,
            encrypted: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub storage_bytes: u64,
    pub reserved_bytes: u64,
    pub used_bytes: u64,
}

impl NodeCapacity {
    pub fn available_bytes(&self) -> u64 {
        self.storage_bytes
            .saturating_sub(self.reserved_bytes)
            .saturating_sub(self.used_bytes)
    }
    pub fn can_store(&self, bytes: u64) -> bool {
        self.available_bytes() >= bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub capabilities: BTreeSet<String>,
    pub last_seen_unix: u64,
    pub healthy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferState {
    Planned,
    Connecting,
    Transferring { completed: u64, total: u64 },
    Verifying,
    Complete,
    Failed { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub resource: ResourceId,
    pub peer: String,
    pub state: TransferState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicy {
    pub replicas: u8,
    pub require_distinct_nodes: bool,
    pub max_retries: u8,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            replicas: DEFAULT_REPLICATION,
            require_distinct_nodes: true,
            max_retries: 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductConfig {
    pub protocol: String,
    pub chunk_size: u64,
    pub placement: PlacementPolicy,
    pub encrypted_by_default: bool,
}

impl Default for ProductConfig {
    fn default() -> Self {
        Self {
            protocol: PRODUCT_PROTOCOL.to_owned(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            placement: PlacementPolicy::default(),
            encrypted_by_default: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductSnapshot {
    pub protocol: String,
    pub node_id: String,
    pub online: bool,
    pub peers: usize,
    pub resources: usize,
    pub active_transfers: usize,
    pub healthy_replicas: usize,
    pub target_replicas: u8,
}

#[derive(Clone, Debug, Default)]
pub struct ProductState {
    pub peers: BTreeMap<String, Peer>,
    pub resources: BTreeMap<ResourceId, ResourceManifest>,
    pub placements: BTreeMap<ResourceId, BTreeSet<String>>,
    pub transfers: BTreeMap<String, Transfer>,
}

impl ProductState {
    pub fn register_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.id.clone(), peer);
    }
    pub fn register_resource(&mut self, manifest: ResourceManifest) {
        self.resources.insert(manifest.id.clone(), manifest);
    }
    pub fn record_placement(&mut self, resource: &ResourceId, node_id: impl Into<String>) {
        self.placements
            .entry(resource.clone())
            .or_default()
            .insert(node_id.into());
    }
    pub fn replica_count(&self, resource: &ResourceId) -> usize {
        self.placements.get(resource).map_or(0, BTreeSet::len)
    }
    pub fn healthy_peers(&self) -> usize {
        self.peers.values().filter(|peer| peer.healthy).count()
    }
    pub fn active_transfers(&self) -> usize {
        self.transfers
            .values()
            .filter(|t| {
                !matches!(
                    t.state,
                    TransferState::Complete | TransferState::Failed { .. }
                )
            })
            .count()
    }
    pub fn snapshot(
        &self,
        node_id: impl Into<String>,
        online: bool,
        target_replicas: u8,
    ) -> ProductSnapshot {
        ProductSnapshot {
            protocol: PRODUCT_PROTOCOL.to_owned(),
            node_id: node_id.into(),
            online,
            peers: self.healthy_peers(),
            resources: self.resources.len(),
            active_transfers: self.active_transfers(),
            healthy_replicas: self.placements.values().map(BTreeSet::len).sum(),
            target_replicas,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resource_ids_are_content_addressed() {
        assert_eq!(
            ResourceId::from_bytes(b"hello"),
            ResourceId::from_bytes(b"hello")
        );
        assert_ne!(
            ResourceId::from_bytes(b"hello"),
            ResourceId::from_bytes(b"world")
        );
    }
    #[test]
    fn placement_is_distinct_and_counted_once() {
        let mut state = ProductState::default();
        let manifest = ResourceManifest::from_bytes(b"data", None, None);
        let id = manifest.id.clone();
        state.register_resource(manifest);
        state.record_placement(&id, "node-a");
        state.record_placement(&id, "node-a");
        state.record_placement(&id, "node-b");
        assert_eq!(state.replica_count(&id), 2);
    }
    #[test]
    fn capacity_never_underflows() {
        let c = NodeCapacity {
            storage_bytes: 10,
            reserved_bytes: 8,
            used_bytes: 8,
        };
        assert_eq!(c.available_bytes(), 0);
        assert!(!c.can_store(1));
    }
    #[test]
    fn snapshot_reports_active_work() {
        let mut state = ProductState::default();
        state.transfers.insert(
            "t1".into(),
            Transfer {
                id: "t1".into(),
                resource: ResourceId::from_bytes(b"x"),
                peer: "node-b".into(),
                state: TransferState::Transferring {
                    completed: 1,
                    total: 2,
                },
            },
        );
        assert_eq!(state.active_transfers(), 1);
    }
}
