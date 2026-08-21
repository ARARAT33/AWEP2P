//! Node reputation system (0 to 1000 score).
//! Reputation is earned through uptime, successful storage transfers, and integrity.
//! Note: Reputation alone NEVER grants administrative/root authority.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeReputation {
    pub node_id: [u8; 32],
    score: u32,
    pub uptime_events: u64,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub abuse_penalties: u32,
}

impl NodeReputation {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            score: 500, // neutral starting score
            uptime_events: 0,
            successful_transfers: 0,
            failed_transfers: 0,
            abuse_penalties: 0,
        }
    }

    pub fn record_transfer_success(&mut self) {
        self.successful_transfers += 1;
        self.recalculate();
    }

    pub fn record_transfer_failure(&mut self) {
        self.failed_transfers += 1;
        self.recalculate();
    }

    pub fn record_uptime_heartbeat(&mut self) {
        self.uptime_events += 1;
        self.recalculate();
    }

    pub fn apply_abuse_penalty(&mut self, penalty: u32) {
        self.abuse_penalties += penalty;
        self.recalculate();
    }

    fn recalculate(&mut self) {
        let base: i64 = 500;
        let uptime_bonus = (self.uptime_events / 10) as i64;
        let success_bonus = (self.successful_transfers / 5) as i64;
        let failure_penalty = (self.failed_transfers * 10) as i64;
        let abuse_penalty = (self.abuse_penalties * 50) as i64;

        let total = base + uptime_bonus + success_bonus - failure_penalty - abuse_penalty;
        self.score = total.clamp(0, 1000) as u32;
    }

    pub fn score(&self) -> u32 {
        self.score
    }

    pub fn is_trusted_peer(&self) -> bool {
        self.score >= 700
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_calculation() {
        let mut rep = NodeReputation::new([1u8; 32]);
        assert_eq!(rep.score(), 500);

        for _ in 0..50 {
            rep.record_transfer_success();
        }
        assert!(rep.score() > 500);

        rep.apply_abuse_penalty(10);
        assert!(rep.score() < 500);
    }
}
