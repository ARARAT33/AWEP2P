use crate::host::{HostHealth, HostRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostDirectory {
    records: BTreeMap<[u8; 32], HostRecord>,
}
impl HostDirectory {
    pub fn upsert(&mut self, record: HostRecord) {
        self.records.insert(record.node_id, record);
    }
    pub fn remove(&mut self, node: &[u8; 32]) {
        self.records.remove(node);
    }
    pub fn healthy(&self, domain: &str, version: u64) -> Vec<HostRecord> {
        let mut v = self
            .records
            .values()
            .filter(|r| r.domain == domain && r.version >= version && r.health.available)
            .cloned()
            .collect::<Vec<_>>();
        v.sort_by_key(|r| (r.health.consecutive_failures, r.health.latency_ms));
        v
    }
    pub fn failover(&self, domain: &str, version: u64, failed: &[u8; 32]) -> Option<HostRecord> {
        self.healthy(domain, version)
            .into_iter()
            .find(|r| &r.node_id != failed)
    }
    pub fn health_update(&mut self, node: [u8; 32], health: HostHealth) {
        if let Some(r) = self.records.get_mut(&node) {
            r.health = health;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_healthy_replica() {
        let mut d = HostDirectory::default();
        d.upsert(HostRecord {
            node_id: [1; 32],
            domain: "site.awe".into(),
            version: 1,
            manifest_hash: [2; 32],
            health: HostHealth {
                available: false,
                ..Default::default()
            },
        });
        d.upsert(HostRecord {
            node_id: [3; 32],
            domain: "site.awe".into(),
            version: 1,
            manifest_hash: [2; 32],
            health: HostHealth {
                available: true,
                latency_ms: 4,
                ..Default::default()
            },
        });
        assert_eq!(
            d.failover("site.awe", 1, &[1; 32]).unwrap().node_id,
            [3; 32]
        );
    }
}
