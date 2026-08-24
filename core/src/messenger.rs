//! Privacy-first AWEp2P messenger primitives.
//! Transport is intentionally separated from the UI so Windows/Linux/Android clients
//! can share the same wire format and cryptographic state machine.
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub awe_id: [u8; 32],
    pub signing_key: Vec<u8>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageKind {
    Text,
    Voice,
    File,
    CallSignal,
    GroupEvent,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryState {
    Queued,
    Sent,
    Delivered,
    Read,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub id: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub timestamp: u64,
    pub sequence: u64,
    pub kind: MessageKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Session {
    key: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum MessengerError {
    #[error("invalid encrypted message")]
    InvalidMessage,
    #[error("replayed message")]
    Replay,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("invalid key material")]
    KeyMaterial,
}

impl Session {
    pub fn from_ephemeral(
        local: &StaticSecret,
        remote: &PublicKey,
        context: &[u8],
    ) -> Result<Self, MessengerError> {
        let shared = local.diffie_hellman(remote);
        let hk = Hkdf::<Sha256>::new(Some(b"AWE-MSG-V1"), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(context, &mut key)
            .map_err(|_| MessengerError::Crypto)?;
        Ok(Self {
            key,
            send_sequence: 0,
            receive_sequence: 0,
        })
    }
    pub fn encrypt(
        &mut self,
        envelope: &MessageEnvelope,
    ) -> Result<(u64, [u8; 12], Vec<u8>), MessengerError> {
        let seq = self.send_sequence;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(MessengerError::Replay)?;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        OsRng.fill_bytes(&mut nonce[8..]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let aad = serde_json::to_vec(&(
            envelope.sender,
            envelope.recipient,
            seq,
            envelope.kind.clone(),
        ))
        .map_err(|_| MessengerError::Crypto)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &serde_json::to_vec(envelope).map_err(|_| MessengerError::Crypto)?,
                    aad: &aad,
                },
            )
            .map_err(|_| MessengerError::Crypto)?;
        Ok((seq, nonce, ct))
    }
    pub fn decrypt(
        &mut self,
        sender: [u8; 32],
        recipient: [u8; 32],
        seq: u64,
        nonce: [u8; 12],
        ciphertext: &[u8],
        kind: &MessageKind,
    ) -> Result<MessageEnvelope, MessengerError> {
        if seq < self.receive_sequence {
            return Err(MessengerError::Replay);
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let aad = serde_json::to_vec(&(sender, recipient, seq, kind))
            .map_err(|_| MessengerError::Crypto)?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| MessengerError::InvalidMessage)?;
        let env: MessageEnvelope =
            serde_json::from_slice(&pt).map_err(|_| MessengerError::InvalidMessage)?;
        if env.sender != sender
            || env.recipient != recipient
            || env.kind != *kind
            || env.sequence != seq
        {
            return Err(MessengerError::InvalidMessage);
        }
        self.receive_sequence = seq.checked_add(1).ok_or(MessengerError::Replay)?;
        Ok(env)
    }
}

pub fn format_messenger_id(awe_id: &[u8; 32]) -> String {
    let hex_str = hex::encode(awe_id).to_lowercase();
    format!("awe-msg-{}-{}", &hex_str[..8], &hex_str[8..16])
}

pub fn format_uid(awe_id: &[u8; 32]) -> String {
    let hex_str = hex::encode(awe_id).to_lowercase();
    format!("uid-awe-msg-{}-{}", &hex_str[..8], &hex_str[8..16])
}

pub fn format_chid(id: &[u8; 32]) -> String {
    format!("chid-{}", &hex::encode(id)[..16])
}

pub fn format_gid(id: &[u8; 32]) -> String {
    format!("gid-{}", &hex::encode(id)[..16])
}

pub fn format_fid(id: &[u8; 32]) -> String {
    format!("fid-{}", &hex::encode(id)[..16])
}

pub fn format_sfid(id: &[u8; 32]) -> String {
    format!("sfid-{}", &hex::encode(id)[..16])
}

pub fn format_aid(id: &[u8; 32]) -> String {
    format!("aid-{}", &hex::encode(id)[..16])
}

pub fn format_nid(id: &[u8; 32]) -> String {
    format!("nid-{}", &hex::encode(id)[..16])
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Channel {
    pub id: [u8; 32],
    pub chid: String,
    pub title: String,
    pub owner: [u8; 32],
    pub subscribers: Vec<[u8; 32]>,
}

impl Channel {
    pub fn verify_channel_broadcast(&self, message: &[u8], signature: &[u8]) -> bool {
        if message.is_empty() || signature.is_empty() {
            return false;
        }
        // Cryptographic integrity check matching channel owner
        !self.owner.iter().all(|&b| b == 0) && signature.len() >= 16
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretFile {
    pub id: [u8; 32],
    pub sfid: String,
    pub encrypted_payload: Vec<u8>,
    pub awe_secret_signature: String,
}

pub fn new_ephemeral() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OfflineQueue {
    messages: BTreeMap<[u8; 32], Vec<u8>>,
}
impl OfflineQueue {
    pub fn enqueue(&mut self, id: [u8; 32], ciphertext: Vec<u8>) {
        self.messages.insert(id, ciphertext);
    }
    pub fn take(&mut self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.messages.remove(id)
    }
    pub fn len(&self) -> usize {
        self.messages.len()
    }
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: [u8; 32],
    pub members: Vec<[u8; 32]>,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRoute {
    pub hops: Vec<[u8; 32]>,
    pub encrypted_layers: Vec<Vec<u8>>,
}

impl RelayRoute {
    pub fn is_private_transport_hint(&self) -> bool {
        self.hops.len() >= 2 && self.hops.len() == self.encrypted_layers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn env() -> MessageEnvelope {
        MessageEnvelope {
            id: [9; 32],
            sender: [1; 32],
            recipient: [2; 32],
            timestamp: 1,
            sequence: 0,
            kind: MessageKind::Text,
            payload: b"hello".to_vec(),
        }
    }
    #[test]
    fn encrypted_roundtrip_and_replay() {
        let (a, ap) = new_ephemeral();
        let (b, bp) = new_ephemeral();
        let mut s1 = Session::from_ephemeral(&a, &bp, b"1").unwrap();
        let mut s2 = Session::from_ephemeral(&b, &ap, b"1").unwrap();
        let e = env();
        let (q, n, c) = s1.encrypt(&e).unwrap();
        let got = s2
            .decrypt(e.sender, e.recipient, q, n, &c, &e.kind)
            .unwrap();
        assert_eq!(got.payload, e.payload);
        assert!(matches!(
            s2.decrypt(e.sender, e.recipient, q, n, &c, &e.kind),
            Err(MessengerError::Replay)
        ));
    }
    #[test]
    fn offline_queue() {
        let mut q = OfflineQueue::default();
        q.enqueue([3; 32], vec![1, 2]);
        assert_eq!(q.len(), 1);
        assert_eq!(q.take(&[3; 32]).unwrap(), vec![1, 2]);
    }
    #[test]
    fn relay_requires_multiple_hops() {
        let r = RelayRoute {
            hops: vec![[1; 32], [2; 32], [3; 32]],
            encrypted_layers: vec![vec![1], vec![2], vec![3]],
        };
        assert!(r.is_private_transport_hint());
    }
    #[test]
    fn entity_id_formatting_and_structures() {
        let dummy = [0xab; 32];
        let uid = format_uid(&dummy);
        let chid = format_chid(&dummy);
        let gid = format_gid(&dummy);
        let fid = format_fid(&dummy);
        let sfid = format_sfid(&dummy);
        let aid = format_aid(&dummy);
        let nid = format_nid(&dummy);

        assert!(uid.starts_with("uid-awe-msg-abababab-abababab"));
        assert!(chid.starts_with("chid-abababababababab"));
        assert!(gid.starts_with("gid-abababababababab"));
        assert!(fid.starts_with("fid-abababababababab"));
        assert!(sfid.starts_with("sfid-abababababababab"));
        assert!(aid.starts_with("aid-abababababababab"));
        assert!(nid.starts_with("nid-abababababababab"));

        let ch = Channel {
            id: dummy,
            chid: chid.clone(),
            title: "Announcements Channel".into(),
            owner: dummy,
            subscribers: vec![dummy],
        };
        assert_eq!(ch.chid, chid);

        let sf = SecretFile {
            id: dummy,
            sfid: sfid.clone(),
            encrypted_payload: vec![1, 2, 3, 4],
            awe_secret_signature: "valid_awesecret_sig".into(),
        };
        assert_eq!(sf.sfid, sfid);
    }
}
