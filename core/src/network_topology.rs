use std::collections::{HashMap, HashSet, VecDeque};

pub type NodeId = String;
pub type DataCentreId = String;
pub type DataGroupId = String;
pub type CentreGroupId = String;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CentreLinkMode {
    FullMesh,
    Relay { relay_node: NodeId },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerMetrics {
    pub rtt_ms: u32,
    pub throughput_kbps: u64,
    pub load_percent: u8,
    pub reliability_percent: u8,
    pub last_seen_unix: u64,
}

impl PeerMetrics {
    pub fn score(&self) -> u64 {
        let rtt = self.rtt_ms.max(1) as u64;
        let load = self.load_percent.min(100) as u64;
        let reliability = self.reliability_percent.min(100) as u64;
        rtt.saturating_mul(4) + load.saturating_mul(10) + (100 - reliability).saturating_mul(20)
    }
    pub fn is_healthy(&self, now_unix: u64, max_age: u64) -> bool {
        self.last_seen_unix > 0
            && now_unix.saturating_sub(self.last_seen_unix) <= max_age
            && self.reliability_percent >= 50
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: NodeId,
    pub peers: HashSet<NodeId>,
    pub alive: bool,
    pub metrics: PeerMetrics,
}

impl Node {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            peers: HashSet::new(),
            alive: true,
            metrics: PeerMetrics::default(),
        }
    }
    pub fn set_health(&mut self, alive: bool) {
        self.alive = alive;
    }
    pub fn update_metrics(&mut self, metrics: PeerMetrics) {
        self.metrics = metrics;
    }
}

#[derive(Clone, Debug)]
pub struct CentreLink {
    pub mode: CentreLinkMode,
    pub relays: Vec<NodeId>,
    pub healthy: bool,
}

#[derive(Clone, Debug)]
pub struct DataCentre {
    pub id: DataCentreId,
    pub nodes: HashMap<NodeId, Node>,
    pub links: HashSet<DataCentreId>,
    pub link_state: HashMap<DataCentreId, CentreLink>,
}

#[derive(Clone, Debug)]
pub struct DataGroup {
    pub id: DataGroupId,
    pub centres: HashSet<DataCentreId>,
}
#[derive(Clone, Debug)]
pub struct CentreGroup {
    pub id: CentreGroupId,
    pub groups: HashSet<DataGroupId>,
}

impl DataGroup {
    pub fn new(
        id: impl Into<String>,
        centres: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let id = id.into();
        let centre_list = centres.into_iter().collect::<Vec<_>>();
        let unique = centre_list.iter().cloned().collect::<HashSet<_>>();
        if unique.len() != centre_list.len() {
            return Err("data group contains duplicate centre IDs".into());
        }
        if unique.len() < 3 {
            return Err("data group must contain at least three distinct centres".into());
        }
        Ok(Self {
            id,
            centres: unique,
        })
    }
}

impl CentreGroup {
    pub fn new(
        id: impl Into<String>,
        groups: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let id = id.into();
        let group_list = groups.into_iter().collect::<Vec<_>>();
        let unique = group_list.iter().cloned().collect::<HashSet<_>>();
        if unique.len() != group_list.len() {
            return Err("centre group contains duplicate data-group IDs".into());
        }
        if unique.len() < 2 {
            return Err("centre group must contain at least two distinct data groups".into());
        }
        Ok(Self { id, groups: unique })
    }
}

#[derive(Default, Debug)]
pub struct AweNet {
    pub centres: HashMap<DataCentreId, DataCentre>,
    pub data_groups: HashMap<DataGroupId, DataGroup>,
    pub centre_groups: HashMap<CentreGroupId, CentreGroup>,
}

impl DataCentre {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            nodes: HashMap::new(),
            links: HashSet::new(),
            link_state: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, n: Node) {
        if n.alive {
            if let Some(peer) = self.nearest(&n.id) {
                if let Some(existing) = self.nodes.get_mut(&peer) {
                    existing.peers.insert(n.id.clone());
                }
            }
        }
        self.nodes.insert(n.id.clone(), n);
    }

    pub fn full_mesh(&mut self) {
        // Use the map keys as stable node IDs. Public Node values can be
        // mutated after insertion, so relying on node.id here can panic.
        let ids: Vec<_> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.alive)
            .map(|(id, _)| id.clone())
            .collect();
        for a in &ids {
            for b in &ids {
                if a != b {
                    if let Some(node) = self.nodes.get_mut(a) {
                        node.peers.insert(b.clone());
                    }
                }
            }
        }
    }

    pub fn nearest(&self, from: &NodeId) -> Option<NodeId> {
        self.nodes
            .iter()
            .filter(|(id, node)| node.alive && *id != from)
            .min_by_key(|(id, node)| (node.metrics.score(), node.peers.len() as u64, (*id).clone()))
            .map(|(id, _)| id.clone())
    }

    pub fn mark_node(&mut self, id: &NodeId, alive: bool) -> Result<(), String> {
        self.nodes
            .get_mut(id)
            .map(|node| node.alive = alive)
            .ok_or_else(|| "node not found".into())
    }
}

impl AweNet {
    pub fn add_centre(&mut self, d: DataCentre) -> Result<(), String> {
        if self.centres.contains_key(&d.id) {
            return Err("data centre ID already exists".into());
        }
        for existing in self.centres.values() {
            if d.nodes.keys().any(|id| existing.nodes.contains_key(id)) {
                return Err("node IDs must be globally unique across data centres".into());
            }
        }
        self.centres.insert(d.id.clone(), d);
        Ok(())
    }

    pub fn add_data_group(&mut self, group: DataGroup) -> Result<(), String> {
        if self.data_groups.contains_key(&group.id) {
            return Err(format!("duplicate data-group ID: {}", group.id));
        }
        if group.centres.len() < 3 {
            return Err("data group must contain at least three distinct centres".into());
        }
        if group
            .centres
            .iter()
            .any(|id| !self.centres.contains_key(id))
        {
            return Err("data group references an unknown centre".into());
        }
        self.data_groups.insert(group.id.clone(), group);
        Ok(())
    }

    pub fn add_centre_group(&mut self, group: CentreGroup) -> Result<(), String> {
        if self.centre_groups.contains_key(&group.id) {
            return Err(format!("duplicate centre-group ID: {}", group.id));
        }
        if group.groups.len() < 2 {
            return Err("centre group must contain at least two distinct data groups".into());
        }
        if group
            .groups
            .iter()
            .any(|id| !self.data_groups.contains_key(id))
        {
            return Err("centre group references an unknown data group".into());
        }
        self.centre_groups.insert(group.id.clone(), group);
        Ok(())
    }

    pub fn connect_centres(
        &mut self,
        a: &str,
        b: &str,
        mode: CentreLinkMode,
    ) -> Result<(), String> {
        if a == b || !self.centres.contains_key(a) || !self.centres.contains_key(b) {
            return Err("invalid data-centre pair".into());
        }
        let left: Vec<_> = self
            .centres
            .get(a)
            .ok_or("source centre not found")?
            .nodes
            .iter()
            .filter(|(_, node)| node.alive)
            .map(|(id, _)| id.clone())
            .collect();
        let right: Vec<_> = self
            .centres
            .get(b)
            .ok_or("target centre not found")?
            .nodes
            .iter()
            .filter(|(_, node)| node.alive)
            .map(|(id, _)| id.clone())
            .collect();
        if left.is_empty() || right.is_empty() {
            return Err("both centres must contain live nodes".into());
        }

        let (relays, stored_mode) = match mode {
            CentreLinkMode::FullMesh => {
                for x in &left {
                    for y in &right {
                        self.centres
                            .get_mut(a)
                            .and_then(|centre| centre.nodes.get_mut(x))
                            .ok_or("source node changed while connecting centres")?
                            .peers
                            .insert(y.clone());
                        self.centres
                            .get_mut(b)
                            .and_then(|centre| centre.nodes.get_mut(y))
                            .ok_or("target node changed while connecting centres")?
                            .peers
                            .insert(x.clone());
                    }
                }
                (left.clone(), CentreLinkMode::FullMesh)
            }
            CentreLinkMode::Relay { relay_node } => {
                if !left.contains(&relay_node) {
                    return Err("relay node missing or offline".into());
                }
                let target = right
                    .iter()
                    .filter_map(|id| {
                        self.centres
                            .get(b)
                            .and_then(|centre| centre.nodes.get(id))
                            .map(|node| (node.metrics.score(), id.clone()))
                    })
                    .min_by_key(|(score, id)| (*score, id.clone()))
                    .map(|(_, id)| id)
                    .ok_or("target centre has no live nodes")?;
                self.centres
                    .get_mut(a)
                    .and_then(|centre| centre.nodes.get_mut(&relay_node))
                    .ok_or("relay node not found")?
                    .peers
                    .insert(target.clone());
                self.centres
                    .get_mut(b)
                    .and_then(|centre| centre.nodes.get_mut(&target))
                    .ok_or("target node not found")?
                    .peers
                    .insert(relay_node.clone());
                (
                    vec![relay_node.clone()],
                    CentreLinkMode::Relay { relay_node },
                )
            }
        };

        let source = self.centres.get_mut(a).ok_or("source centre not found")?;
        source.links.insert(b.into());
        source.link_state.insert(
            b.into(),
            CentreLink {
                mode: stored_mode.clone(),
                relays: relays.clone(),
                healthy: true,
            },
        );
        let target = self.centres.get_mut(b).ok_or("target centre not found")?;
        target.links.insert(a.into());
        target.link_state.insert(
            a.into(),
            CentreLink {
                mode: stored_mode,
                relays,
                healthy: true,
            },
        );
        Ok(())
    }

    pub fn failover_relay(&mut self, a: &str, b: &str) -> Result<NodeId, String> {
        let state = self
            .centres
            .get(a)
            .and_then(|centre| centre.link_state.get(b))
            .cloned()
            .ok_or("link not found")?;
        let reciprocal_state = self
            .centres
            .get(b)
            .and_then(|centre| centre.link_state.get(a))
            .cloned()
            .ok_or("reciprocal link not found")?;
        if state.relays != reciprocal_state.relays {
            return Err("data-centre link relay state is inconsistent".into());
        }
        let candidate = self
            .centres
            .get(a)
            .ok_or("source centre not found")?
            .nodes
            .iter()
            .filter(|(id, node)| node.alive && !state.relays.contains(id))
            .min_by_key(|(id, node)| (node.metrics.score(), (*id).clone()))
            .map(|(id, _)| id.clone())
            .ok_or("no healthy relay available")?;
        let target = self
            .centres
            .get(b)
            .ok_or("target centre not found")?
            .nodes
            .iter()
            .filter(|(_, node)| node.alive)
            .min_by_key(|(id, node)| (node.metrics.score(), (*id).clone()))
            .map(|(id, _)| id.clone())
            .ok_or("target centre has no live nodes")?;

        self.centres
            .get_mut(a)
            .and_then(|centre| centre.nodes.get_mut(&candidate))
            .ok_or("selected relay node disappeared")?
            .peers
            .insert(target.clone());
        self.centres
            .get_mut(b)
            .and_then(|centre| centre.nodes.get_mut(&target))
            .ok_or("target node disappeared")?
            .peers
            .insert(candidate.clone());
        self.centres
            .get_mut(a)
            .and_then(|centre| centre.link_state.get_mut(b))
            .ok_or("source link state disappeared")?
            .relays
            .push(candidate.clone());
        self.centres
            .get_mut(b)
            .and_then(|centre| centre.link_state.get_mut(a))
            .ok_or("reciprocal link state disappeared")?
            .relays
            .push(candidate.clone());
        Ok(candidate)
    }

    pub fn validate(&self) -> Result<(), String> {
        for (id, centre) in &self.centres {
            if centre.id != *id {
                return Err(format!("centre map key does not match centre ID: {id}"));
            }
            for (node_id, node) in &centre.nodes {
                if node.id != *node_id {
                    return Err(format!(
                        "node map key does not match node ID in centre {id}: {node_id}"
                    ));
                }
                for peer in &node.peers {
                    if !self
                        .centres
                        .values()
                        .any(|other| other.nodes.contains_key(peer))
                    {
                        return Err(format!("node {node_id} references unknown peer {peer}"));
                    }
                }
            }
            for linked_id in &centre.links {
                let Some(linked) = self.centres.get(linked_id) else {
                    return Err(format!("centre {id} references unknown link {linked_id}"));
                };
                if !centre.link_state.contains_key(linked_id)
                    || !linked.links.contains(id)
                    || !linked.link_state.contains_key(id)
                {
                    return Err(format!(
                        "centre link between {id} and {linked_id} is not reciprocal"
                    ));
                }
            }
        }
        for (id, group) in &self.data_groups {
            if group.id != *id
                || group.centres.len() < 3
                || !group
                    .centres
                    .iter()
                    .all(|centre| self.centres.contains_key(centre))
            {
                return Err(format!("invalid data group: {id}"));
            }
        }
        for (id, group) in &self.centre_groups {
            if group.id != *id
                || group.groups.len() < 2
                || !group
                    .groups
                    .iter()
                    .all(|group_id| self.data_groups.contains_key(group_id))
            {
                return Err(format!("invalid centre group: {id}"));
            }
        }
        Ok(())
    }

    pub fn route(&self, src: &NodeId, dst: &NodeId) -> Option<Vec<NodeId>> {
        let is_live_node = |id: &NodeId| {
            self.centres
                .values()
                .any(|centre| centre.nodes.get(id).is_some_and(|node| node.alive))
        };
        if !is_live_node(src) || !is_live_node(dst) {
            return None;
        }
        if src == dst {
            return Some(vec![src.clone()]);
        }

        // Map keys are the canonical node IDs; Node values are public and may
        // have been modified since insertion, so route from the keys.
        let mut adjacency: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for centre in self.centres.values() {
            for (node_id, node) in centre.nodes.iter().filter(|(_, node)| node.alive) {
                let neighbours = node
                    .peers
                    .iter()
                    .filter(|peer| is_live_node(peer))
                    .cloned()
                    .collect::<Vec<_>>();
                adjacency.insert(node_id.clone(), neighbours);
            }
        }

        let mut queue = VecDeque::from([src.clone()]);
        let mut previous: HashMap<NodeId, Option<NodeId>> = HashMap::from([(src.clone(), None)]);
        while let Some(current) = queue.pop_front() {
            if &current == dst {
                break;
            }
            for peer in adjacency.get(&current).into_iter().flatten() {
                if !previous.contains_key(peer) {
                    previous.insert(peer.clone(), Some(current.clone()));
                    queue.push_back(peer.clone());
                }
            }
        }
        if !previous.contains_key(dst) {
            return None;
        }

        let mut route = Vec::new();
        let mut current = dst.clone();
        loop {
            route.push(current.clone());
            match previous.get(&current).cloned().flatten() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        route.reverse();
        Some(route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mesh_ignores_dead_nodes() {
        let mut c = DataCentre::new("dc");
        c.add_node(Node::new("a"));
        let mut b = Node::new("b");
        b.alive = false;
        c.add_node(b);
        c.full_mesh();
        assert!(c.nodes["a"].peers.is_empty());
    }
    #[test]
    fn duplicate_node_ids_are_rejected() {
        let mut n = AweNet::default();
        let mut a = DataCentre::new("a");
        a.add_node(Node::new("same"));
        let mut b = DataCentre::new("b");
        b.add_node(Node::new("same"));
        assert!(n.add_centre(a).is_ok());
        assert!(n.add_centre(b).is_err());
    }
    #[test]
    fn duplicate_data_centre_ids_are_rejected() {
        let mut network = AweNet::default();
        assert!(network.add_centre(DataCentre::new("same")).is_ok());
        assert!(network.add_centre(DataCentre::new("same")).is_err());
        assert_eq!(network.centres.len(), 1);
    }

    #[test]
    fn groups_require_distinct_members_and_ids_cannot_overwrite() {
        assert!(DataGroup::new("g", ["a".to_string(), "a".to_string(), "b".to_string()]).is_err());
        assert!(CentreGroup::new("cg", ["g".to_string(), "g".to_string()]).is_err());

        let mut network = AweNet::default();
        for id in ["a", "b", "c"] {
            network.add_centre(DataCentre::new(id)).unwrap();
        }
        let group = DataGroup::new("group", ["a".into(), "b".into(), "c".into()]).unwrap();
        assert!(network.add_data_group(group.clone()).is_ok());
        assert!(network.add_data_group(group).is_err());
        assert_eq!(network.data_groups.len(), 1);
    }

    #[test]
    fn routes_require_known_live_endpoints_and_use_canonical_keys() {
        let mut network = AweNet::default();
        let mut centre = DataCentre::new("centre");
        centre.add_node(Node::new("a"));
        centre.add_node(Node::new("b"));
        let mut dead = Node::new("dead");
        dead.alive = false;
        centre.add_node(dead);
        centre.nodes.get_mut("a").unwrap().peers.insert("b".into());
        centre.nodes.get_mut("b").unwrap().peers.insert("a".into());
        network.add_centre(centre).unwrap();

        let a = "a".to_string();
        let b = "b".to_string();
        let dead = "dead".to_string();
        let missing = "missing".to_string();

        assert_eq!(network.route(&a, &b), Some(vec![a.clone(), b.clone()]));
        assert_eq!(network.route(&a, &a), Some(vec![a.clone()]));
        assert_eq!(network.route(&missing, &b), None);
        assert_eq!(network.route(&a, &dead), None);
    }

    #[test]
    fn relay_failover_adds_backup() {
        let mut n = AweNet::default();
        let mut a = DataCentre::new("a");
        a.add_node(Node::new("a1"));
        a.add_node(Node::new("a2"));
        let mut b = DataCentre::new("b");
        b.add_node(Node::new("b1"));
        n.add_centre(a).unwrap();
        n.add_centre(b).unwrap();
        n.connect_centres(
            "a",
            "b",
            CentreLinkMode::Relay {
                relay_node: "a1".into(),
            },
        )
        .unwrap();
        assert!(n.failover_relay("a", "b").is_ok());
    }
}
