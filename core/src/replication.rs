//! Storage placement and replica-health primitives.
//! A file can be represented as 1000 erasure shards, with each shard assigned
//! to three distinct nodes. Placement is deterministic for a given file ID,
//! shard index and node set, but it never invents node IDs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const REQUIRED_SHARDS: usize = 1000;
pub const REQUIRED_REPLICAS: usize = 3;
pub const MAX_SHARDS_PER_NODE: usize = 100;
pub const MIN_NODES_FOR_CAPACITY_LIMIT: usize =
    (REQUIRED_SHARDS * REQUIRED_REPLICAS + MAX_SHARDS_PER_NODE - 1) / MAX_SHARDS_PER_NODE;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaPlacement {
    pub shard_index: u16,
    pub nodes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlacementPlan {
    pub file_id: [u8; 32],
    pub shards: usize,
    pub replicas_per_shard: usize,
    pub placements: Vec<ReplicaPlacement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaHealth {
    pub shard_index: u16,
    pub available_nodes: Vec<String>,
    pub missing_replicas: usize,
    pub healthy: bool,
}

pub fn select_replicas(file_id: &[u8; 32], shard_index: usize, nodes: &[String]) -> Vec<String> {
    let mut candidates: Vec<String> = nodes.iter().filter(|n| !n.is_empty()).cloned().collect();
    candidates.sort();
    candidates.dedup();
    if candidates.len() <= REQUIRED_REPLICAS {
        return candidates;
    }
    candidates.sort_by_key(|node| {
        let mut seed = Vec::with_capacity(32 + 8 + node.len());
        seed.extend_from_slice(file_id);
        seed.extend_from_slice(&(shard_index as u64).to_be_bytes());
        seed.extend_from_slice(node.as_bytes());
        *blake3::hash(&seed).as_bytes()
    });
    candidates.truncate(REQUIRED_REPLICAS);
    candidates
}

pub fn build_plan(file_id: [u8; 32], nodes: &[String]) -> Result<PlacementPlan, String> {
    build_plan_for_shards(file_id, nodes, REQUIRED_SHARDS)
}

pub fn build_plan_for_shards(
    file_id: [u8; 32],
    nodes: &[String],
    shard_count: usize,
) -> Result<PlacementPlan, String> {
    let mut unique = BTreeSet::new();
    for n in nodes {
        if !n.is_empty() {
            unique.insert(n.clone());
        }
    }
    if unique.len() < REQUIRED_REPLICAS {
        return Err("at least three distinct storage nodes are required".into());
    }
    let shard_count = shard_count.clamp(12, REQUIRED_SHARDS);
    let candidates: Vec<String> = unique.into_iter().collect();
    let placements = (0..shard_count)
        .map(|i| ReplicaPlacement {
            shard_index: i as u16,
            nodes: select_replicas(&file_id, i, &candidates),
        })
        .collect();
    Ok(PlacementPlan {
        file_id,
        shards: shard_count,
        replicas_per_shard: REQUIRED_REPLICAS,
        placements,
    })
}

pub fn assess(plan: &PlacementPlan, online_nodes: &BTreeSet<String>) -> Vec<ReplicaHealth> {
    plan.placements
        .iter()
        .map(|p| {
            let available_nodes: Vec<_> = p
                .nodes
                .iter()
                .filter(|n| online_nodes.contains(*n))
                .cloned()
                .collect();
            let missing_replicas = REQUIRED_REPLICAS.saturating_sub(available_nodes.len());
            ReplicaHealth {
                shard_index: p.shard_index,
                available_nodes,
                missing_replicas,
                healthy: missing_replicas == 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_has_exactly_1000_shards_and_three_replicas() {
        let nodes: Vec<_> = (0..12).map(|i| format!("node-{i}")).collect();
        let plan = build_plan([7; 32], &nodes).unwrap();
        assert_eq!(plan.shards, 1000);
        assert_eq!(plan.placements.len(), 1000);
        assert!(plan.placements.iter().all(|p| p.nodes.len() == 3));
    }

    #[test]
    fn placement_is_deterministic() {
        let nodes: Vec<_> = (0..8).map(|i| format!("node-{i}")).collect();
        let a = build_plan([8; 32], &nodes).unwrap();
        let b = build_plan([8; 32], &nodes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn health_detects_missing_replicas() {
        let nodes: Vec<_> = (0..4).map(|i| format!("node-{i}")).collect();
        let plan = build_plan([9; 32], &nodes).unwrap();
        let online = BTreeSet::from([plan.placements[0].nodes[0].clone()]);
        let h = assess(&plan, &online);
        assert_eq!(h[0].available_nodes.len(), 1);
        assert_eq!(h[0].missing_replicas, 2);
        assert!(!h[0].healthy);
    }
}

pub fn build_capacity_limited_plan(
    file_id: [u8; 32],
    nodes: &[String],
) -> Result<PlacementPlan, String> {
    let mut unique: Vec<String> = nodes.iter().filter(|n| !n.is_empty()).cloned().collect();
    unique.sort();
    unique.dedup();
    if unique.len() < MIN_NODES_FOR_CAPACITY_LIMIT {
        return Err(format!(
            "at least {MIN_NODES_FOR_CAPACITY_LIMIT} distinct storage nodes are required"
        ));
    }
    let mut loads = vec![0usize; unique.len()];
    let mut placements = Vec::with_capacity(REQUIRED_SHARDS);
    for shard_index in 0..REQUIRED_SHARDS {
        let mut ranked: Vec<(usize, [u8; 32])> = unique
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let mut seed = Vec::with_capacity(64 + node.len());
                seed.extend_from_slice(b"AWE/PLACEMENT/v1");
                seed.extend_from_slice(&file_id);
                seed.extend_from_slice(&(shard_index as u64).to_be_bytes());
                seed.extend_from_slice(node.as_bytes());
                (i, *blake3::hash(&seed).as_bytes())
            })
            .filter(|(i, _)| loads[*i] < MAX_SHARDS_PER_NODE)
            .collect();
        ranked.sort_by_key(|(i, score)| (loads[*i], *score, unique[*i].clone()));
        if ranked.len() < REQUIRED_REPLICAS {
            return Err(format!(
                "capacity exhausted while placing shard {shard_index}"
            ));
        }
        let selected = ranked
            .iter()
            .take(REQUIRED_REPLICAS)
            .map(|(i, _)| {
                loads[*i] += 1;
                unique[*i].clone()
            })
            .collect();
        placements.push(ReplicaPlacement {
            shard_index: shard_index as u16,
            nodes: selected,
        });
    }
    Ok(PlacementPlan {
        file_id,
        shards: REQUIRED_SHARDS,
        replicas_per_shard: REQUIRED_REPLICAS,
        placements,
    })
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    #[test]
    fn capacity_limit_is_100_per_node() {
        let nodes: Vec<_> = (0..30).map(|i| format!("node-{i:02}")).collect();
        let plan = build_capacity_limited_plan([11; 32], &nodes).unwrap();
        let mut loads = std::collections::BTreeMap::<String, usize>::new();
        for p in &plan.placements {
            assert_eq!(p.nodes.len(), 3);
            assert_eq!(
                p.nodes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                3
            );
            for n in &p.nodes {
                *loads.entry(n.clone()).or_default() += 1;
            }
        }
        assert_eq!(loads.len(), 30);
        assert!(loads.values().all(|v| *v <= MAX_SHARDS_PER_NODE));
        assert_eq!(loads.values().sum::<usize>(), 3000);
    }
    #[test]
    fn rejects_29_nodes() {
        let nodes: Vec<_> = (0..29).map(|i| format!("node-{i:02}")).collect();
        assert!(build_capacity_limited_plan([12; 32], &nodes).is_err());
    }
}
