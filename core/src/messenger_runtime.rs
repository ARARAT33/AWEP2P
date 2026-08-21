//! AWEp2P messenger runtime contracts shared by Windows, Linux and Android clients.
//! The transport remains peer-to-peer; this module contains no account server.

use crate::replay::ReplayGuard;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ContactId(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryState { Queued, Sent, Delivered, Read, Failed }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaKind { Text, EncryptedFile, VoiceMessage, CallOffer, CallAnswer, IceCandidate, Hangup }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub message_id: [u8; 16],
    pub sender: ContactId,
    pub recipient: ContactId,
    pub session_epoch: u64,
    pub sequence: u64,
    pub kind: MediaKind,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEpoch { pub group_id: [u8; 32], pub epoch: u64, pub members: Vec<ContactId> }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHop { pub node_id: [u8; 32], pub expires_at_unix: u64 }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyRoute { pub hops: Vec<RelayHop> }

#[derive(Default)]
pub struct OfflineQueue { queue: VecDeque<Envelope> }
impl OfflineQueue {
    pub fn push(&mut self, e: Envelope) { self.queue.push_back(e); }
    pub fn pop(&mut self) -> Option<Envelope> { self.queue.pop_front() }
    pub fn len(&self) -> usize { self.queue.len() }
}

pub struct MessengerState { pub delivery: HashMap<[u8;16], DeliveryState>, pub replay: ReplayGuard, pub offline: OfflineQueue }
impl Default for MessengerState { fn default() -> Self { Self { delivery: HashMap::new(), replay: ReplayGuard::default(), offline: OfflineQueue::default() } } }

impl MessengerState {
    pub fn queue(&mut self, e: Envelope) { self.delivery.insert(e.message_id, DeliveryState::Queued); self.offline.push(e); }
    pub fn mark(&mut self, id: [u8;16], state: DeliveryState) { self.delivery.insert(id, state); }
}

/// Privacy routing reduces direct peer metadata exposure but is not an anonymity guarantee.
pub fn validate_route(route: &PrivacyRoute, now_unix: u64) -> bool {
    !route.hops.is_empty() && route.hops.len() <= 8 && route.hops.iter().all(|h| h.expires_at_unix > now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn offline_queue_survives_disconnect_state() {
        let mut s=MessengerState::default();
        let e=Envelope{message_id:[1;16],sender:ContactId([2;32]),recipient:ContactId([3;32]),session_epoch:1,sequence:1,kind:MediaKind::Text,ciphertext:vec![9,8,7]};
        s.queue(e.clone()); assert_eq!(s.offline.len(),1); assert_eq!(s.offline.pop().unwrap(),e);
    }
    #[test] fn relay_expiry_is_checked() {
        let r=PrivacyRoute{hops:vec![RelayHop{node_id:[1;32],expires_at_unix:20}]}; assert!(validate_route(&r,10)); assert!(!validate_route(&r,20));
    }
}
