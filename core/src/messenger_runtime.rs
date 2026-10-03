//! Durable messenger runtime contracts shared by Windows, Linux and Android clients.
//! The wire transport remains peer-to-peer. This module owns delivery state,
//! retry/backoff, duplicate suppression, bounded offline storage and relay-route
//! validation so the UI never has to guess whether a message was delivered.

use crate::replay::ReplayGuard;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

pub const MAX_OFFLINE_MESSAGES: usize = 10_000;
pub const MAX_ENCRYPTED_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ATTACHMENT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_RETRY_ATTEMPTS: u32 = 8;
pub const RETRY_BASE_SECONDS: u64 = 2;
pub const RETRY_MAX_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ContactId(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryState {
    Queued,
    Sent,
    Delivered,
    Read,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaKind {
    Text,
    EncryptedFile,
    VoiceMessage,
    CallOffer,
    CallAnswer,
    IceCandidate,
    Hangup,
}

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

impl Envelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_ENCRYPTED_MESSAGE_BYTES {
            return Err("encrypted message exceeds runtime bounds");
        }
        if matches!(self.kind, MediaKind::EncryptedFile | MediaKind::VoiceMessage)
            && self.ciphertext.len() > MAX_ATTACHMENT_BYTES
        {
            return Err("encrypted attachment exceeds runtime bounds");
        }
        Ok(())
    }

    pub fn is_attachment(&self) -> bool {
        matches!(self.kind, MediaKind::EncryptedFile | MediaKind::VoiceMessage)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub state: DeliveryState,
    pub attempts: u32,
    pub next_retry_unix: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEpoch {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub members: Vec<ContactId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHop {
    pub node_id: [u8; 32],
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyRoute {
    pub hops: Vec<RelayHop>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryEnvelope {
    pub envelope: Envelope,
    pub record: DeliveryRecord,
}

#[derive(Default, Serialize, Deserialize)]
pub struct OfflineQueue {
    queue: VecDeque<Envelope>,
}

impl OfflineQueue {
    pub fn push(&mut self, e: Envelope) -> Result<(), &'static str> {
        e.validate()?;
        if self.queue.len() >= MAX_OFFLINE_MESSAGES {
            return Err("offline queue is full");
        }
        if self.queue.iter().any(|x| x.message_id == e.message_id) {
            return Ok(());
        }
        self.queue.push_back(e);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Envelope> {
        self.queue.pop_front()
    }

    pub fn remove(&mut self, id: &[u8; 16]) -> Option<Envelope> {
        let index = self.queue.iter().position(|x| &x.message_id == id)?;
        self.queue.remove(index)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

pub struct MessengerState {
    pub delivery: HashMap<[u8; 16], DeliveryRecord>,
    pub replay: ReplayGuard,
    pub offline: OfflineQueue,
    next_sequence: u64,
}

impl Default for MessengerState {
    fn default() -> Self {
        Self {
            delivery: HashMap::new(),
            replay: ReplayGuard::default(),
            offline: OfflineQueue::default(),
            next_sequence: 0,
        }
    }
}

impl MessengerState {
    pub fn allocate_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    pub fn queue(&mut self, e: Envelope, now_unix: u64) -> Result<(), &'static str> {
        e.validate()?;
        self.delivery.entry(e.message_id).or_insert(DeliveryRecord {
            state: DeliveryState::Queued,
            attempts: 0,
            next_retry_unix: now_unix,
            last_error: None,
        });
        self.offline.push(e)
    }

    /// A message is not Delivered until the remote peer sends an application ACK.
    pub fn mark_sent(&mut self, id: [u8; 16], now_unix: u64) -> Result<(), &'static str> {
        let record = self.delivery.get_mut(&id).ok_or("unknown message id")?;
        record.state = DeliveryState::Sent;
        record.attempts = record.attempts.saturating_add(1);
        record.next_retry_unix = now_unix.saturating_add(retry_delay(record.attempts));
        Ok(())
    }

    pub fn mark_delivered(&mut self, id: [u8; 16]) -> Result<(), &'static str> {
        let record = self.delivery.get_mut(&id).ok_or("unknown message id")?;
        record.state = DeliveryState::Delivered;
        record.last_error = None;
        let _ = self.offline.remove(&id);
        Ok(())
    }

    pub fn mark_read(&mut self, id: [u8; 16]) -> Result<(), &'static str> {
        let record = self.delivery.get_mut(&id).ok_or("unknown message id")?;
        if matches!(record.state, DeliveryState::Delivered | DeliveryState::Read) {
            record.state = DeliveryState::Read;
            Ok(())
        } else {
            Err("message must be delivered before read acknowledgement")
        }
    }

    pub fn mark_failed(&mut self, id: [u8; 16], error: impl Into<String>, now_unix: u64) -> Result<(), &'static str> {
        let record = self.delivery.get_mut(&id).ok_or("unknown message id")?;
        record.last_error = Some(error.into());
        if record.attempts >= MAX_RETRY_ATTEMPTS {
            record.state = DeliveryState::Failed;
        } else {
            record.state = DeliveryState::Queued;
            record.next_retry_unix = now_unix.saturating_add(retry_delay(record.attempts.max(1)));
        }
        Ok(())
    }

    pub fn due_retries(&self, now_unix: u64) -> Vec<RetryEnvelope> {
        self.delivery
            .iter()
            .filter_map(|(id, record)| {
                if !matches!(record.state, DeliveryState::Queued | DeliveryState::Sent)
                    || record.next_retry_unix > now_unix
                    || record.attempts >= MAX_RETRY_ATTEMPTS
                {
                    return None;
                }
                self.offline
                    .queue
                    .iter()
                    .find(|e| &e.message_id == id)
                    .cloned()
                    .map(|envelope| RetryEnvelope {
                        envelope,
                        record: record.clone(),
                    })
            })
            .collect()
    }
}

pub fn retry_delay(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(10);
    RETRY_BASE_SECONDS
        .saturating_mul(1u64 << shift)
        .min(RETRY_MAX_SECONDS)
}

/// Privacy routing reduces direct peer metadata exposure but is not an anonymity guarantee.
pub fn validate_route(route: &PrivacyRoute, now_unix: u64) -> bool {
    !route.hops.is_empty()
        && route.hops.len() <= 8
        && route.hops.windows(2).all(|w| w[0].node_id != w[1].node_id)
        && route.hops.iter().all(|h| h.expires_at_unix > now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: u8) -> Envelope {
        Envelope {
            message_id: [id; 16],
            sender: ContactId([2; 32]),
            recipient: ContactId([3; 32]),
            session_epoch: 1,
            sequence: id as u64,
            kind: MediaKind::Text,
            ciphertext: vec![9, 8, 7],
        }
    }

    #[test]
    fn offline_queue_deduplicates_and_bounds_messages() {
        let mut q = OfflineQueue::default();
        q.push(envelope(1)).unwrap();
        q.push(envelope(1)).unwrap();
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn delivery_requires_remote_ack() {
        let mut s = MessengerState::default();
        s.queue(envelope(1), 10).unwrap();
        s.mark_sent([1; 16], 10).unwrap();
        assert_eq!(s.delivery[&[1; 16]].state, DeliveryState::Sent);
        s.mark_delivered([1; 16]).unwrap();
        assert_eq!(s.delivery[&[1; 16]].state, DeliveryState::Delivered);
    }

    #[test]
    fn retries_back_off_and_eventually_fail() {
        let mut s = MessengerState::default();
        s.queue(envelope(2), 0).unwrap();
        for attempt in 0..MAX_RETRY_ATTEMPTS {
            s.mark_sent([2; 16], attempt as u64).unwrap();
            s.mark_failed([2; 16], "offline", u64::MAX).unwrap();
        }
        assert_eq!(s.delivery[&[2; 16]].state, DeliveryState::Failed);
        assert!(retry_delay(MAX_RETRY_ATTEMPTS) <= RETRY_MAX_SECONDS);
    }

    #[test]
    fn relay_route_rejects_duplicate_adjacent_hops() {
        let r = PrivacyRoute {
            hops: vec![
                RelayHop { node_id: [1; 32], expires_at_unix: 20 },
                RelayHop { node_id: [1; 32], expires_at_unix: 20 },
            ],
        };
        assert!(!validate_route(&r, 10));
    }
}
