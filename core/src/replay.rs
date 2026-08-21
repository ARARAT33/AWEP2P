use std::collections::BTreeMap;

/// Bounded replay window keyed by authenticated peer identifier.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    highest: BTreeMap<[u8; 32], u64>,
}

impl ReplayGuard {
    pub fn accept(&mut self, peer: [u8; 32], sequence: u64) -> bool {
        match self.highest.get(&peer) {
            Some(&current) if sequence <= current => false,
            _ => {
                self.highest.insert(peer, sequence);
                true
            }
        }
    }
}
