use crate::{
    crypto::hash,
    defense::{DefenseDecision, PeerDefense},
    identity::Identity,
    limits::{IpAdmission, PeerAdmission},
    replay::ReplayGuard,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinSet,
    time::timeout,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const VERSION: u16 = 1;
const MAX_FRAME: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const MAX_PEERS_PER_RESPONSE: usize = 64;
const MAX_ADDRESSES_PER_PEER: usize = 16;
const MAX_NODE_RECORDS: usize = 64;
const MAX_ROUTING_RECORDS: usize = 8192;
const MAX_PEER_RECORDS: usize = 8192;
const MAX_ACTIVE_CONNECTIONS: usize = 512;
const MAX_OUTBOUND_CONCURRENCY: usize = 256;
const MAX_INBOX_MESSAGES: usize = 4096;
const MAX_INBOX_BYTES: usize = 64 * 1024 * 1024;
const DISCOVERY_ROUNDS: usize = 4;
const DISCOVERY_ALPHA: usize = 3;
const PEER_RATE_CAPACITY: u64 = 256;
const PEER_RATE_REFILL_PER_SECOND: u64 = 128;
const PREAUTH_MAX_IPS: usize = 1024;
const PREAUTH_RATE_CAPACITY: u64 = 32;
const PREAUTH_RATE_REFILL_PER_SECOND: u64 = 16;
const FRAME_PAD_MIN: usize = 256;
const FRAME_LENGTH_PREFIX: usize = 4;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication failed")]
    Authentication,
    #[error("encryption failed")]
    Encryption,
    #[error("connection timeout")]
    Timeout,
    #[error("frame too large")]
    FrameTooLarge,
    #[error("node is under backpressure")]
    Backpressure,
}

pub const A2P2_PROTOCOL_SCHEME: &str = "a2p2://";
pub const A2P2_FIXED_PACKET_SIZE: usize = 1280;
pub const A2P2_NONCE_SIZE: usize = 12;
pub const A2P2_HEADER_SIZE: usize = A2P2_NONCE_SIZE;
pub const A2P2_CIPHERTEXT_SIZE: usize = A2P2_FIXED_PACKET_SIZE - A2P2_HEADER_SIZE;
pub const A2P2_PLAINTEXT_SIZE: usize = A2P2_CIPHERTEXT_SIZE - 16;
pub const A2P2_MAX_PAYLOAD: usize = A2P2_PLAINTEXT_SIZE - 2;

/// A2P2 encrypted fixed-size wire packet.
///
/// Unlike the legacy padding helper below, this format keeps the payload length
/// and contents inside ChaCha20-Poly1305. A passive observer therefore sees a
/// constant 1280-byte record rather than a cleartext length field.
pub fn a2p2_seal(
    payload: &[u8],
    key: &[u8; 32],
) -> Result<[u8; A2P2_FIXED_PACKET_SIZE], NetworkError> {
    if payload.len() > A2P2_MAX_PAYLOAD {
        return Err(NetworkError::FrameTooLarge);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NetworkError::Encryption)?;
    let mut nonce = [0u8; A2P2_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    // The entire plaintext is padded BEFORE AEAD, so the wire length never
    // reveals the application payload length.
    let mut inner = vec![0u8; A2P2_PLAINTEXT_SIZE];
    inner[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    inner[2..2 + payload.len()].copy_from_slice(payload);
    OsRng.fill_bytes(&mut inner[2 + payload.len()..]);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), inner.as_ref())
        .map_err(|_| NetworkError::Encryption)?;
    debug_assert_eq!(ciphertext.len(), A2P2_CIPHERTEXT_SIZE);

    let mut out = [0u8; A2P2_FIXED_PACKET_SIZE];
    out[..A2P2_HEADER_SIZE].copy_from_slice(&nonce);
    out[A2P2_HEADER_SIZE..].copy_from_slice(&ciphertext);
    Ok(out)
}

pub fn a2p2_open(packet: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, NetworkError> {
    if packet.len() != A2P2_FIXED_PACKET_SIZE {
        return Err(NetworkError::Protocol("invalid a2p2 packet size".into()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NetworkError::Encryption)?;
    let mut nonce = [0u8; A2P2_NONCE_SIZE];
    nonce.copy_from_slice(&packet[..A2P2_HEADER_SIZE]);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), &packet[A2P2_HEADER_SIZE..])
        .map_err(|_| NetworkError::Authentication)?;
    if plaintext.len() != A2P2_PLAINTEXT_SIZE || plaintext.len() < 2 {
        return Err(NetworkError::Protocol("invalid a2p2 plaintext".into()));
    }
    let payload_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if payload_len > A2P2_MAX_PAYLOAD {
        return Err(NetworkError::Protocol("invalid a2p2 payload length".into()));
    }
    Ok(plaintext[2..2 + payload_len].to_vec())
}

/// Fixed-size A2P2 datagram facade backed by the authenticated encrypted wire format.
/// The legacy cleartext-length layout is intentionally not used here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct A2P2Datagram {
    pub payload: Vec<u8>,
}

impl A2P2Datagram {
    /// Encrypt a datagram with the caller's session key.
    ///
    /// A fixed or public key must never be used for real network traffic.
    pub fn pack(payload: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, NetworkError> {
        Ok(a2p2_seal(payload, key)?.to_vec())
    }

    /// Decrypt a datagram with the same authenticated session key used by the sender.
    pub fn unpack(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, NetworkError> {
        a2p2_open(data, key)
    }
}

const MAX_ONION_LAYER: usize = MAX_FRAME;
const MAX_ONION_SERVICE_NAME: usize = 256;
const MAX_ONION_PAYLOAD: usize = 8 * 1024 * 1024;

/// Encrypt one onion layer with an ephemeral X25519 key and ChaCha20-Poly1305.
pub fn encrypt_layer(payload: &[u8], recipient_pk: &[u8; 32]) -> Result<Vec<u8>, NetworkError> {
    if payload.len() > MAX_ONION_PAYLOAD {
        return Err(NetworkError::FrameTooLarge);
    }
    let secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = XPublic::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&XPublic::from(*recipient_pk));
    let hk = Hkdf::<Sha256>::new(Some(b"AWE/A2P2/ONION-SALT/v1"), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"AWE/A2P2/ONION-KEY/v1", &mut key)
        .map_err(|_| NetworkError::Encryption)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| NetworkError::Encryption)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| NetworkError::Encryption)?;
    let total = 32usize
        .checked_add(12)
        .and_then(|n| n.checked_add(ciphertext.len()))
        .ok_or(NetworkError::FrameTooLarge)?;
    if total > MAX_ONION_LAYER {
        return Err(NetworkError::FrameTooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&ephemeral_pk);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt one onion layer using the recipient's X25519 secret.
pub fn decrypt_layer(
    layer_bytes: &[u8],
    node_secret: &StaticSecret,
) -> Result<Vec<u8>, NetworkError> {
    if layer_bytes.len() < 32 + 12 + 16 || layer_bytes.len() > MAX_ONION_LAYER {
        return Err(NetworkError::Protocol("invalid onion layer size".into()));
    }
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&layer_bytes[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&layer_bytes[32..44]);
    let shared = node_secret.diffie_hellman(&XPublic::from(ephemeral_pk));
    let hk = Hkdf::<Sha256>::new(Some(b"AWE/A2P2/ONION-SALT/v1"), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"AWE/A2P2/ONION-KEY/v1", &mut key)
        .map_err(|_| NetworkError::Encryption)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| NetworkError::Encryption)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), &layer_bytes[44..])
        .map_err(|_| NetworkError::Authentication)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripleBlindOnionPacket {
    pub ingress_layer: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngressUnwrapped {
    pub next_hop: [u8; 32],
    pub relay_layer: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayUnwrapped {
    pub next_hop: [u8; 32],
    pub egress_layer: Vec<u8>,
    pub mixnet_delay_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressUnwrapped {
    pub service_y: String,
    pub request_payload: Vec<u8>,
}

impl TripleBlindOnionPacket {
    pub fn build(
        request_payload: &[u8],
        service_y: &str,
        node_a_pk: &[u8; 32],
        node_b_pk: &[u8; 32],
        node_c_pk: &[u8; 32],
    ) -> Result<Self, NetworkError> {
        // Layer 3 (Node C / Egress -> Service Y)
        if request_payload.len() > MAX_ONION_PAYLOAD || service_y.len() > MAX_ONION_SERVICE_NAME {
            return Err(NetworkError::FrameTooLarge);
        }
        let egress_unwrapped = EgressUnwrapped {
            service_y: service_y.to_string(),
            request_payload: request_payload.to_vec(),
        };
        let layer3_payload = serde_json::to_vec(&egress_unwrapped)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;
        let layer3_ct = encrypt_layer(&layer3_payload, node_c_pk)?;

        // Layer 2 (Node B / Relay -> Node C)
        let delay_ms = (OsRng.next_u32() % 45 + 5) as u64; // 5-50ms mixnet timing delay
        let relay_unwrapped = RelayUnwrapped {
            next_hop: *node_c_pk,
            egress_layer: layer3_ct,
            mixnet_delay_ms: delay_ms,
        };
        let layer2_payload = serde_json::to_vec(&relay_unwrapped)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;
        let layer2_ct = encrypt_layer(&layer2_payload, node_b_pk)?;

        // Layer 1 (Node A / Ingress -> Node B)
        let ingress_unwrapped = IngressUnwrapped {
            next_hop: *node_b_pk,
            relay_layer: layer2_ct,
        };
        let layer1_payload = serde_json::to_vec(&ingress_unwrapped)
            .map_err(|e| NetworkError::Protocol(e.to_string()))?;
        let layer1_ct = encrypt_layer(&layer1_payload, node_a_pk)?;

        Ok(Self {
            ingress_layer: layer1_ct,
        })
    }

    /// Node A (Ingress) unwrap: knows Sender X and Node B, but NOT Layer 2/3 or Service Y.
    pub fn unwrap_ingress(
        &self,
        node_a_secret: &StaticSecret,
    ) -> Result<IngressUnwrapped, NetworkError> {
        let pt = decrypt_layer(&self.ingress_layer, node_a_secret)?;
        serde_json::from_slice(&pt).map_err(|e| NetworkError::Protocol(e.to_string()))
    }

    /// Node B (Relay/Mixnet) unwrap: knows Node A and Node C, but NOT Sender X or Service Y.
    pub fn unwrap_relay(
        relay_layer: &[u8],
        node_b_secret: &StaticSecret,
    ) -> Result<RelayUnwrapped, NetworkError> {
        let pt = decrypt_layer(relay_layer, node_b_secret)?;
        serde_json::from_slice(&pt).map_err(|e| NetworkError::Protocol(e.to_string()))
    }

    /// Node C (Egress) unwrap: knows Service Y and request payload, but NOT Sender X.
    pub fn unwrap_egress(
        egress_layer: &[u8],
        node_c_secret: &StaticSecret,
    ) -> Result<EgressUnwrapped, NetworkError> {
        let pt = decrypt_layer(egress_layer, node_c_secret)?;
        serde_json::from_slice(&pt).map_err(|e| NetworkError::Protocol(e.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub awe_id: [u8; 32],
    pub public_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
    pub protocol_version: u16,
    pub last_seen_unix: u64,
}

pub fn format_node_descriptor(awe_id: &[u8; 32]) -> String {
    let hex_str = hex::encode(awe_id).to_uppercase();
    format!(
        "ND-{}-{}-{}-{}",
        &hex_str[0..4],
        &hex_str[4..8],
        &hex_str[8..12],
        &hex_str[12..16]
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Control {
    Hello {
        version: u16,
        awe_id: [u8; 32],
        public_key: [u8; 32],
        ephemeral: [u8; 32],
        nonce: [u8; 32],
        signature: Vec<u8>,
        advertised_addr: SocketAddr,
    },
    Ping {
        sequence: u64,
    },
    Pong {
        sequence: u64,
    },
    Data {
        stream: u32,
        payload: Vec<u8>,
    },
    DataAck {
        stream: u32,
        bytes: u32,
    },
    FindNode {
        target: [u8; 32],
    },
    Nodes {
        records: Vec<PeerRecord>,
    },
}

fn encode(v: &Control) -> Result<Vec<u8>, NetworkError> {
    serde_json::to_vec(v).map_err(|e| NetworkError::Protocol(e.to_string()))
}
fn decode(v: &[u8]) -> Result<Control, NetworkError> {
    if v.len() > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    let message: Control =
        serde_json::from_slice(v).map_err(|e| NetworkError::Protocol(e.to_string()))?;
    match &message {
        Control::Hello { signature, .. } if signature.len() != 64 => {
            return Err(NetworkError::Authentication);
        }
        Control::Data { payload, .. } if payload.len() > MAX_FRAME / 2 => {
            return Err(NetworkError::FrameTooLarge);
        }
        Control::Nodes { records } if records.len() > MAX_NODE_RECORDS => {
            return Err(NetworkError::Protocol("too many peer records".into()));
        }
        Control::Nodes { records } => {
            for record in records {
                if record.protocol_version != VERSION
                    || record.addresses.len() > MAX_ADDRESSES_PER_PEER
                {
                    return Err(NetworkError::Protocol("invalid peer record".into()));
                }
            }
        }
        _ => {}
    }
    Ok(message)
}
async fn write_frame(s: &mut TcpStream, b: &[u8]) -> Result<(), NetworkError> {
    if b.is_empty() || b.len() > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    s.write_u32(b.len() as u32).await?;
    s.write_all(b).await?;
    // TcpStream writes are buffered by the OS; flushing every frame adds latency
    // and system-call overhead without improving TCP delivery semantics.
    Ok(())
}
async fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>, NetworkError> {
    let n = s.read_u32().await? as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    let mut b = vec![0; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}
/// Bind the claimed network identity to the public key that verifies the handshake.
fn peer_id_matches_public_key(id: &[u8; 32], public_key: &[u8; 32]) -> bool {
    crate::identity::AweId::from_public_key(public_key).as_bytes() == id
}

fn hello_bytes(
    v: u16,
    id: &[u8; 32],
    pk: &[u8; 32],
    e: &[u8; 32],
    n: &[u8; 32],
    advertised_addr: SocketAddr,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(170);
    b.extend_from_slice(b"AWE/HELLO/v1");
    b.extend_from_slice(&v.to_be_bytes());
    b.extend_from_slice(id);
    b.extend_from_slice(pk);
    b.extend_from_slice(e);
    b.extend_from_slice(n);
    b.extend_from_slice(advertised_addr.to_string().as_bytes());
    b
}

async fn handshake(
    mut stream: TcpStream,
    identity: Arc<Identity>,
    advertised_addr: SocketAddr,
    initiator: bool,
) -> Result<SecureConnection, NetworkError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral = XPublic::from(&secret).to_bytes();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let id = *identity.public.awe_id.as_bytes();
    let pk = identity.public.public_key;
    let sig = identity.sign(&hello_bytes(
        VERSION,
        &id,
        &pk,
        &ephemeral,
        &nonce,
        advertised_addr,
    ));
    let hello = Control::Hello {
        version: VERSION,
        awe_id: id,
        public_key: pk,
        ephemeral,
        nonce,
        signature: sig.to_vec(),
        advertised_addr,
    };
    let remote = if initiator {
        write_frame(&mut stream, &encode(&hello)?).await?;
        decode(
            &timeout(HELLO_TIMEOUT, read_frame(&mut stream))
                .await
                .map_err(|_| NetworkError::Timeout)??,
        )?
    } else {
        let r = decode(
            &timeout(HELLO_TIMEOUT, read_frame(&mut stream))
                .await
                .map_err(|_| NetworkError::Timeout)??,
        )?;
        write_frame(&mut stream, &encode(&hello)?).await?;
        r
    };
    let (rid, rpk, re, rnonce, rsig, version, remote_addr) = match remote {
        Control::Hello {
            version,
            awe_id,
            public_key,
            ephemeral,
            nonce,
            signature,
            advertised_addr,
        } => (
            awe_id,
            public_key,
            ephemeral,
            nonce,
            signature,
            version,
            advertised_addr,
        ),
        _ => return Err(NetworkError::Protocol("expected hello".into())),
    };
    if version != VERSION {
        return Err(NetworkError::Protocol(format!(
            "unsupported protocol version {version}"
        )));
    }
    if rid == id {
        return Err(NetworkError::Protocol("self connection".into()));
    }
    // A valid signature alone does not prove that the claimed AWE-ID belongs to
    // the signing key. Enforce the protocol's public-key-derived identity binding.
    if !peer_id_matches_public_key(&rid, &rpk) {
        return Err(NetworkError::Authentication);
    }
    let rsig: [u8; 64] = rsig
        .as_slice()
        .try_into()
        .map_err(|_| NetworkError::Authentication)?;
    if !Identity::verify(
        &rpk,
        &hello_bytes(version, &rid, &rpk, &re, &rnonce, remote_addr),
        &rsig,
    ) {
        return Err(NetworkError::Authentication);
    }
    let shared = secret.diffie_hellman(&XPublic::from(re));
    let (lo_id, hi_id, lo_nonce, hi_nonce) = if id < rid {
        (id, rid, nonce, rnonce)
    } else {
        (rid, id, rnonce, nonce)
    };
    let mut salt_input = Vec::with_capacity(128);
    salt_input.extend_from_slice(&lo_id);
    salt_input.extend_from_slice(&hi_id);
    salt_input.extend_from_slice(&lo_nonce);
    salt_input.extend_from_slice(&hi_nonce);
    let salt = hash(b"AWE/SESSION-SALT/v1", &salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut keys = [0u8; 64];
    hk.expand(b"AWE/SESSION/v1", &mut keys)
        .map_err(|_| NetworkError::Encryption)?;
    let (tx, rx) = if initiator {
        (&keys[..32], &keys[32..])
    } else {
        (&keys[32..], &keys[..32])
    };
    Ok(SecureConnection {
        stream,
        remote_id: rid,
        remote_public_key: rpk,
        remote_address: remote_addr,
        tx: ChaCha20Poly1305::new_from_slice(tx).map_err(|_| NetworkError::Encryption)?,
        rx: ChaCha20Poly1305::new_from_slice(rx).map_err(|_| NetworkError::Encryption)?,
        tx_seq: 0,
        replay: ReplayGuard::default(),
        last_activity: Instant::now(),
    })
}

pub struct SecureConnection {
    stream: TcpStream,
    pub remote_id: [u8; 32],
    pub remote_public_key: [u8; 32],
    pub remote_address: SocketAddr,
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_seq: u64,
    replay: ReplayGuard,
    last_activity: Instant,
}
impl SecureConnection {
    fn nonce(s: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&s.to_be_bytes());
        n
    }
    async fn send(&mut self, c: &Control) -> Result<(), NetworkError> {
        let p = encode(c)?;
        if p.len() > MAX_FRAME.saturating_sub(FRAME_LENGTH_PREFIX + 16) {
            return Err(NetworkError::FrameTooLarge);
        }

        // AWE/WIRE-v1: put the real plaintext length inside an encrypted,
        // power-of-two-sized bucket. The TCP frame therefore reveals only a
        // coarse size class, not the exact application payload length.
        let needed = p.len().saturating_add(FRAME_LENGTH_PREFIX);
        let bucket = needed
            .max(FRAME_PAD_MIN)
            .checked_next_power_of_two()
            .ok_or(NetworkError::FrameTooLarge)?;
        if bucket.saturating_add(16) > MAX_FRAME {
            return Err(NetworkError::FrameTooLarge);
        }
        let mut padded = vec![0u8; bucket];
        padded[..FRAME_LENGTH_PREFIX].copy_from_slice(&(p.len() as u32).to_be_bytes());
        padded[FRAME_LENGTH_PREFIX..FRAME_LENGTH_PREFIX + p.len()].copy_from_slice(&p);

        let s = self.tx_seq;
        self.tx_seq = s
            .checked_add(1)
            .ok_or_else(|| NetworkError::Protocol("sequence exhausted".into()))?;
        let aad = s.to_be_bytes();
        let e = self
            .tx
            .encrypt(
                Nonce::from_slice(&Self::nonce(s)),
                Payload {
                    msg: &padded,
                    aad: &aad,
                },
            )
            .map_err(|_| NetworkError::Encryption)?;
        let mut f = Vec::with_capacity(8 + e.len());
        f.extend_from_slice(&aad);
        f.extend_from_slice(&e);
        write_frame(&mut self.stream, &f).await?;
        self.last_activity = Instant::now();
        Ok(())
    }
    async fn recv(&mut self) -> Result<Control, NetworkError> {
        let f = read_frame(&mut self.stream).await?;
        if f.len() < 8 {
            return Err(NetworkError::Protocol("short encrypted frame".into()));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&f[..8]);
        let s = u64::from_be_bytes(b);
        if !self.replay.accept(self.remote_id, s) {
            return Err(NetworkError::Protocol("replayed frame".into()));
        }
        let p = self
            .rx
            .decrypt(
                Nonce::from_slice(&Self::nonce(s)),
                Payload {
                    msg: &f[8..],
                    aad: &b,
                },
            )
            .map_err(|_| NetworkError::Authentication)?;

        if p.len() < FRAME_LENGTH_PREFIX {
            return Err(NetworkError::Protocol("short padded frame".into()));
        }
        let mut len = [0u8; FRAME_LENGTH_PREFIX];
        len.copy_from_slice(&p[..FRAME_LENGTH_PREFIX]);
        let payload_len = u32::from_be_bytes(len) as usize;
        if payload_len > p.len().saturating_sub(FRAME_LENGTH_PREFIX) {
            return Err(NetworkError::Protocol("invalid padded frame length".into()));
        }
        self.last_activity = Instant::now();
        decode(&p[FRAME_LENGTH_PREFIX..FRAME_LENGTH_PREFIX + payload_len])
    }
    pub async fn send_data(&mut self, stream: u32, payload: Vec<u8>) -> Result<(), NetworkError> {
        if payload.len() > MAX_FRAME / 2 {
            return Err(NetworkError::FrameTooLarge);
        }
        self.send(&Control::Data { stream, payload }).await
    }
    pub async fn ping(&mut self, sequence: u64) -> Result<(), NetworkError> {
        self.send(&Control::Ping { sequence }).await
    }

    /// Send a heartbeat and wait for the matching authenticated Pong.
    /// This is useful for operational probes and real node-to-node tests.
    pub async fn ping_roundtrip(&mut self, sequence: u64) -> Result<Duration, NetworkError> {
        let started = Instant::now();
        self.ping(sequence).await?;
        loop {
            match timeout(HELLO_TIMEOUT, self.recv()).await {
                Ok(Ok(Control::Pong { sequence: echoed })) if echoed == sequence => {
                    return Ok(started.elapsed());
                }
                Ok(Ok(Control::Ping { sequence: incoming })) => {
                    self.send(&Control::Pong { sequence: incoming }).await?;
                }
                Ok(Ok(Control::Data { .. } | Control::Nodes { .. })) => {}
                Ok(Ok(Control::Pong { .. } | Control::DataAck { .. })) => {}
                Ok(Ok(Control::FindNode { .. } | Control::Hello { .. })) => {
                    return Err(NetworkError::Protocol(
                        "unexpected control message during ping".into(),
                    ));
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(NetworkError::Timeout),
            }
        }
    }

    /// Send application data and wait for the authenticated peer acknowledgement.
    /// This proves the encrypted data plane is carrying bytes end-to-end, not just heartbeats.
    pub async fn send_data_roundtrip(
        &mut self,
        stream: u32,
        payload: Vec<u8>,
    ) -> Result<Duration, NetworkError> {
        if payload.len() > MAX_FRAME / 2 {
            return Err(NetworkError::FrameTooLarge);
        }
        let expected = payload.len() as u32;
        let started = Instant::now();
        self.send(&Control::Data { stream, payload }).await?;
        loop {
            match timeout(HELLO_TIMEOUT, self.recv()).await {
                Ok(Ok(Control::DataAck {
                    stream: echoed,
                    bytes,
                })) if echoed == stream && bytes == expected => {
                    return Ok(started.elapsed());
                }
                Ok(Ok(Control::Ping { sequence })) => {
                    self.send(&Control::Pong { sequence }).await?;
                }
                Ok(Ok(Control::Pong { .. } | Control::Nodes { .. })) => {}
                Ok(Ok(Control::Data {
                    stream: incoming,
                    payload,
                })) => {
                    self.send(&Control::DataAck {
                        stream: incoming,
                        bytes: payload.len() as u32,
                    })
                    .await?;
                }
                Ok(Ok(Control::DataAck { .. })) => {}
                Ok(Ok(Control::FindNode { .. } | Control::Hello { .. })) => {
                    return Err(NetworkError::Protocol(
                        "unexpected control message during data probe".into(),
                    ));
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(NetworkError::Timeout),
            }
        }
    }

    pub async fn recv_data(&mut self) -> Result<Option<(u32, Vec<u8>)>, NetworkError> {
        match self.recv().await? {
            Control::Data { stream, payload } => Ok(Some((stream, payload))),
            Control::Ping { sequence } => {
                self.send(&Control::Pong { sequence }).await?;
                Ok(None)
            }
            Control::Pong { .. } | Control::DataAck { .. } | Control::Nodes { .. } => Ok(None),
            Control::FindNode { .. } | Control::Hello { .. } => {
                Err(NetworkError::Protocol("unexpected control message".into()))
            }
        }
    }
    pub fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > IDLE_TIMEOUT
    }
}

#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    peers: BTreeMap<[u8; 32], PeerRecord>,
}
impl RoutingTable {
    pub fn insert(&mut self, p: PeerRecord) {
        self.peers.insert(p.awe_id, p);
        if self.peers.len() > MAX_ROUTING_RECORDS {
            if let Some(evict) = self
                .peers
                .iter()
                .min_by_key(|(_, r)| r.last_seen_unix)
                .map(|(id, _)| *id)
            {
                self.peers.remove(&evict);
            }
        }
    }
    pub fn remove(&mut self, id: &[u8; 32]) {
        self.peers.remove(id);
    }
    pub fn closest(&self, target: &[u8; 32], limit: usize) -> Vec<PeerRecord> {
        if limit == 0 || self.peers.is_empty() {
            return Vec::new();
        }
        let mut v: Vec<_> = self.peers.values().cloned().collect();
        let take = limit.min(v.len());
        if take < v.len() {
            let nth = take - 1;
            v.select_nth_unstable_by_key(nth, |p| xor_distance(&p.awe_id, target));
            v.truncate(take);
        }
        v.sort_unstable_by_key(|p| xor_distance(&p.awe_id, target));
        v
    }
    pub fn all(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }
}
fn insert_peer_bounded(peers: &mut HashMap<[u8; 32], PeerRecord>, mut record: PeerRecord) {
    if let Some(existing) = peers.get_mut(&record.awe_id) {
        // A routing advertisement with no endpoints must not erase the last
        // authenticated endpoint learned from a direct connection.
        for address in existing.addresses.iter().copied() {
            if record.addresses.len() >= MAX_ADDRESSES_PER_PEER {
                break;
            }
            if !record.addresses.contains(&address) {
                record.addresses.push(address);
            }
        }
        record.last_seen_unix = record.last_seen_unix.max(existing.last_seen_unix);
        *existing = record;
        return;
    }
    if peers.len() >= MAX_PEER_RECORDS {
        if let Some(evict) = peers
            .values()
            .min_by_key(|p| p.last_seen_unix)
            .map(|p| p.awe_id)
        {
            peers.remove(&evict);
        }
    }
    peers.insert(record.awe_id, record);
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i]
    }
    d
}

type ActiveConnections = Arc<RwLock<HashMap<[u8; 32], Arc<tokio::sync::Mutex<SecureConnection>>>>>;
type InboxQueue = Arc<Mutex<Vec<([u8; 32], u32, Vec<u8>)>>>;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct Node {
    pub identity: Arc<Identity>,
    pub listen_addr: SocketAddr,
    routing: Arc<RwLock<RoutingTable>>,
    peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>,
    admission: Arc<Mutex<PeerAdmission>>,
    preauth: Arc<Mutex<IpAdmission>>,
    defense: Arc<Mutex<PeerDefense>>,
    active: ActiveConnections,
    inbox: InboxQueue,
    inbox_bytes: Arc<Mutex<usize>>,
    outbound_limit: Arc<tokio::sync::Semaphore>,
}
impl Node {
    pub fn new(identity: Identity, listen_addr: SocketAddr) -> Self {
        Self {
            identity: Arc::new(identity),
            listen_addr,
            routing: Arc::new(RwLock::new(RoutingTable::default())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            admission: Arc::new(Mutex::new(PeerAdmission::new(
                MAX_CONCURRENT_CONNECTIONS,
                PEER_RATE_CAPACITY,
                PEER_RATE_REFILL_PER_SECOND,
            ))),
            preauth: Arc::new(Mutex::new(IpAdmission::new(
                PREAUTH_MAX_IPS,
                PREAUTH_RATE_CAPACITY,
                PREAUTH_RATE_REFILL_PER_SECOND,
            ))),
            defense: Arc::new(Mutex::new(PeerDefense::default())),
            active: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(Mutex::new(Vec::new())),
            inbox_bytes: Arc::new(Mutex::new(0)),
            outbound_limit: Arc::new(tokio::sync::Semaphore::new(MAX_OUTBOUND_CONCURRENCY)),
        }
    }
    pub fn node_descriptor(&self) -> String {
        format_node_descriptor(self.identity.public.awe_id.as_bytes())
    }
    async fn handle(
        stream: TcpStream,
        address: SocketAddr,
        listen_addr: SocketAddr,
        identity: Arc<Identity>,
        routing: Arc<RwLock<RoutingTable>>,
        peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>,
        admission: Arc<Mutex<PeerAdmission>>,
        defense: Arc<Mutex<PeerDefense>>,
        inbox: InboxQueue,
        inbox_bytes: Arc<Mutex<usize>>,
    ) {
        let Ok(mut c) = handshake(stream, identity, listen_addr, false).await else {
            return;
        };
        if !admission
            .lock()
            .expect("admission lock poisoned")
            .allow(c.remote_id, 1, now())
        {
            let _ = defense
                .lock()
                .expect("defense lock poisoned")
                .strike(c.remote_id, now());
            return;
        }
        if matches!(
            defense
                .lock()
                .expect("defense lock poisoned")
                .check(c.remote_id, now()),
            DefenseDecision::Banned | DefenseDecision::Quarantined
        ) {
            return;
        }
        let r = PeerRecord {
            awe_id: c.remote_id,
            public_key: c.remote_public_key,
            addresses: vec![if c.remote_address.ip().is_unspecified() {
                SocketAddr::new(address.ip(), c.remote_address.port())
            } else {
                c.remote_address
            }],
            protocol_version: VERSION,
            last_seen_unix: now(),
        };
        routing.write().await.insert(r.clone());
        {
            let mut peers = peers.write().await;
            insert_peer_bounded(&mut peers, r);
        }
        let mut seq = 0u64;
        loop {
            match timeout(HEARTBEAT, c.recv()).await {
                Ok(Ok(message)) => {
                    let cost = match &message {
                        Control::Ping { .. } | Control::Pong { .. } => 1,
                        Control::FindNode { .. } => 4,
                        Control::Nodes { records } => 4 + records.len() as u64,
                        Control::Data { payload, .. } => 1 + (payload.len() as u64 / 4096),
                        Control::DataAck { .. } => 1,
                        Control::Hello { .. } => PEER_RATE_CAPACITY + 1,
                    };
                    if !admission.lock().expect("admission lock poisoned").allow(
                        c.remote_id,
                        cost,
                        now(),
                    ) {
                        let _ = defense
                            .lock()
                            .expect("defense lock poisoned")
                            .strike(c.remote_id, now());
                        break;
                    }
                    match message {
                        Control::Ping { sequence } => {
                            if c.send(&Control::Pong { sequence }).await.is_err() {
                                break;
                            }
                        }
                        Control::Pong { .. } => {}
                        Control::FindNode { target } => {
                            let records = routing
                                .read()
                                .await
                                .closest(&target, MAX_PEERS_PER_RESPONSE);
                            if c.send(&Control::Nodes { records }).await.is_err() {
                                break;
                            }
                        }
                        Control::Data { stream, payload } => {
                            let accepted = if let Ok(mut bytes) = inbox_bytes.lock() {
                                let message_bytes = payload.len();
                                if message_bytes > MAX_INBOX_BYTES
                                    || *bytes > MAX_INBOX_BYTES.saturating_sub(message_bytes)
                                {
                                    false
                                } else if let Ok(mut queue) = inbox.lock() {
                                    if queue.len() >= MAX_INBOX_MESSAGES {
                                        false
                                    } else {
                                        queue.push((c.remote_id, stream, payload.clone()));
                                        *bytes += message_bytes;
                                        true
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                            if !accepted {
                                break;
                            }
                            if c.send(&Control::DataAck {
                                stream,
                                bytes: payload.len() as u32,
                            })
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                        Control::DataAck { .. } => {}
                        Control::Nodes { .. } | Control::Hello { .. } => break,
                    }
                }
                Ok(Err(_)) => {
                    let _ = defense
                        .lock()
                        .expect("defense lock poisoned")
                        .strike(c.remote_id, now());
                    break;
                }
                Err(_) => {
                    if c.is_idle() || c.ping(seq).await.is_err() {
                        break;
                    }
                    seq = seq.wrapping_add(1)
                }
            }
        }
        // Keep the last authenticated peer record after disconnect. Removing it
        // here prevents reconnect attempts precisely when a connection drops.
        if let Ok(mut known_peers) = peers.try_write() {
            if let Some(record) = known_peers.get_mut(&c.remote_id) {
                record.last_seen_unix = now();
            }
        }
        if let Ok(mut known_routes) = routing.try_write() {
            if let Some(record) = known_routes.peers.get_mut(&c.remote_id) {
                record.last_seen_unix = now();
            }
        }
    }
    pub async fn listen(&self) -> Result<(), NetworkError> {
        let l = TcpListener::bind(self.listen_addr).await?;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        loop {
            let (s, a) = l.accept().await?;
            let _ = s.set_nodelay(true);
            let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                // Bounded admission: do not spawn unlimited tasks under connection floods.
                drop(s);
                continue;
            };
            let ip_allowed = self
                .preauth
                .lock()
                .expect("preauth lock poisoned")
                .allow(a.ip(), now());
            if !ip_allowed {
                drop(s);
                drop(permit);
                continue;
            }
            let identity = Arc::clone(&self.identity);
            let routing = Arc::clone(&self.routing);
            let peers = Arc::clone(&self.peers);
            let admission = Arc::clone(&self.admission);
            let defense = Arc::clone(&self.defense);
            let inbox = Arc::clone(&self.inbox);
            let inbox_bytes = Arc::clone(&self.inbox_bytes);
            let listen_addr = self.listen_addr;
            tokio::spawn(async move {
                Self::handle(
                    s,
                    a,
                    listen_addr,
                    identity,
                    routing,
                    peers,
                    admission,
                    defense,
                    inbox,
                    inbox_bytes,
                )
                .await;
                drop(permit);
            });
        }
    }
    pub async fn connect(&self, address: SocketAddr) -> Result<SecureConnection, NetworkError> {
        let s = timeout(HELLO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| NetworkError::Timeout)??;
        let _ = s.set_nodelay(true);
        handshake(s, Arc::clone(&self.identity), self.listen_addr, true).await
    }
    pub async fn bootstrap(&self, addresses: &[SocketAddr]) -> Result<usize, NetworkError> {
        // Multi-source bootstrap: no single seed is a dependency.
        let seeds = addresses.iter().copied().take(64).collect::<Vec<_>>();
        let mut jobs = JoinSet::new();
        for address in seeds {
            let node = self.clone();
            jobs.spawn(async move {
                let Ok(mut c) = node.connect(address).await else {
                    return 0usize;
                };
                let remote_id = c.remote_id;
                let remote = PeerRecord {
                    awe_id: c.remote_id,
                    public_key: c.remote_public_key,
                    addresses: vec![if c.remote_address.ip().is_unspecified() {
                        SocketAddr::new(address.ip(), c.remote_address.port())
                    } else {
                        c.remote_address
                    }],
                    protocol_version: VERSION,
                    last_seen_unix: now(),
                };
                node.routing.write().await.insert(remote.clone());
                {
                    let mut peers = node.peers.write().await;
                    insert_peer_bounded(&mut peers, remote);
                }

                let _ = c
                    .send(&Control::FindNode {
                        target: *node.identity.public.awe_id.as_bytes(),
                    })
                    .await;
                let mut discovered = 0usize;
                if let Ok(Ok(Control::Nodes { records })) = timeout(HELLO_TIMEOUT, c.recv()).await {
                    let mut routing = node.routing.write().await;
                    let mut peers = node.peers.write().await;
                    for x in records {
                        if x.awe_id == *node.identity.public.awe_id.as_bytes() {
                            continue;
                        }
                        routing.insert(x.clone());
                        insert_peer_bounded(&mut peers, x);
                        discovered += 1;
                    }
                }
                let shared = Arc::new(tokio::sync::Mutex::new(c));
                let cached = {
                    let mut active = node.active.write().await;
                    if active.len() < MAX_ACTIVE_CONNECTIONS {
                        active.insert(remote_id, shared.clone());
                        true
                    } else {
                        false
                    }
                };
                if !cached {
                    return discovered;
                }
                let active = Arc::clone(&node.active);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(HEARTBEAT).await;
                        let Ok(mut connection) = shared.try_lock() else {
                            continue;
                        };
                        if connection.ping_roundtrip(now()).await.is_err() {
                            drop(connection);
                            active.write().await.remove(&remote_id);
                            break;
                        }
                    }
                });
                discovered
            });
        }
        let mut found = 0usize;
        while let Some(result) = jobs.join_next().await {
            found += result
                .map_err(|e| NetworkError::Protocol(format!("bootstrap task failed: {e}")))?;
        }

        // Expand beyond the initial seeds. This is bounded Kademlia-style
        // discovery rather than a single-hop bootstrap response.
        let target = *self.identity.public.awe_id.as_bytes();
        let discovered = self
            .find_nodes_iterative(&target, DISCOVERY_ALPHA, DISCOVERY_ROUNDS)
            .await?;
        Ok(found.saturating_add(discovered.len()))
    }

    /// Continuously refreshes discovery so nodes recover from partitions and
    /// do not become permanently dependent on their original bootstrap peers.
    pub fn spawn_discovery_loop(&self, seeds: Vec<SocketAddr>) {
        let node = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let mut candidates = seeds.clone();
                candidates.extend(
                    node.peers()
                        .await
                        .into_iter()
                        .flat_map(|p| p.addresses)
                        .take(32),
                );
                candidates.sort_unstable();
                candidates.dedup();
                if !candidates.is_empty() {
                    let _ = node.bootstrap(&candidates).await;
                }
            }
        });
    }

    pub async fn send_to_peer(
        &self,
        peer_id: &[u8; 32],
        stream: u32,
        payload: Vec<u8>,
    ) -> Result<std::time::Duration, NetworkError> {
        let _outbound_permit = self
            .outbound_limit
            .acquire()
            .await
            .map_err(|_| NetworkError::Protocol("outbound limiter closed".into()))?;
        let connection = if let Some(connection) = self.active.read().await.get(peer_id).cloned() {
            connection
        } else {
            let address = self
                .peers
                .read()
                .await
                .get(peer_id)
                .and_then(|peer| peer.addresses.first().copied())
                .ok_or_else(|| NetworkError::Protocol("peer address is unknown".into()))?;
            let connection = Arc::new(tokio::sync::Mutex::new(self.connect(address).await?));
            let mut active = self.active.write().await;
            if active.len() < MAX_ACTIVE_CONNECTIONS {
                active.insert(*peer_id, connection.clone());
            }
            connection
        };
        let mut connection = connection.lock().await;
        let started = Instant::now();
        let result = connection
            .send_data(stream, payload)
            .await
            .map(|_| started.elapsed());
        if result.is_err() {
            self.active.write().await.remove(peer_id);
        }
        result
    }

    /// Send application data over a fresh authenticated connection and wait for
    /// the receiver's network-level DataAck. This is used for application-level
    /// acknowledgements so a stale cached callback connection cannot be reused.
    pub async fn send_to_peer_confirmed(
        &self,
        peer_id: &[u8; 32],
        stream: u32,
        payload: Vec<u8>,
    ) -> Result<std::time::Duration, NetworkError> {
        let _outbound_permit = self
            .outbound_limit
            .acquire()
            .await
            .map_err(|_| NetworkError::Protocol("outbound limiter closed".into()))?;
        let address = self
            .peers
            .read()
            .await
            .get(peer_id)
            .and_then(|peer| peer.addresses.first().copied())
            .ok_or_else(|| NetworkError::Protocol("peer address is unknown".into()))?;
        let mut connection = self.connect(address).await?;
        connection.send_data_roundtrip(stream, payload).await
    }

    pub fn take_inbox(&self) -> Vec<([u8; 32], u32, Vec<u8>)> {
        let queue = self
            .inbox
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default();
        if let Ok(mut bytes) = self.inbox_bytes.lock() {
            *bytes = 0;
        }
        queue
    }

    pub async fn active_peers(&self) -> Vec<[u8; 32]> {
        self.active.read().await.keys().copied().collect()
    }

    pub async fn active_peer_count(&self) -> usize {
        self.active.read().await.len()
    }

    pub async fn ping_peer(&self, peer_id: &[u8; 32]) -> Result<std::time::Duration, NetworkError> {
        let connection = self
            .active
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| NetworkError::Protocol("peer is not actively connected".into()))?;
        let mut connection = connection.lock().await;
        connection.ping_roundtrip(now()).await
    }

    /// Iteratively query discovered peers for closer peers instead of relying on
    /// a single bootstrap response. This is the lookup phase of a Kademlia-style DHT.
    pub async fn find_nodes_iterative(
        &self,
        target: &[u8; 32],
        alpha: usize,
        max_rounds: usize,
    ) -> Result<Vec<PeerRecord>, NetworkError> {
        let alpha = alpha.clamp(1, 8);
        let max_rounds = max_rounds.clamp(1, 16);
        let mut queried = BTreeMap::<[u8; 32], bool>::new();

        for _ in 0..max_rounds {
            let candidates = self.closest_peers(target, alpha.saturating_mul(4)).await;
            let batch = candidates
                .into_iter()
                .filter(|peer| !queried.contains_key(&peer.awe_id) && !peer.addresses.is_empty())
                .take(alpha)
                .collect::<Vec<_>>();

            if batch.is_empty() {
                break;
            }

            // Query up to alpha peers concurrently. The old implementation
            // serialized every connection, making lookup latency roughly the
            // sum of peer RTTs instead of being bounded by the slowest peer.
            let mut jobs: JoinSet<Result<Vec<PeerRecord>, NetworkError>> = JoinSet::new();
            for peer in batch {
                queried.insert(peer.awe_id, true);
                let node = self.clone();
                let target = *target;
                jobs.spawn(async move {
                    for address in peer.addresses.iter().copied() {
                        let Ok(mut connection) = node.connect(address).await else {
                            continue;
                        };
                        if connection
                            .send(&Control::FindNode { target })
                            .await
                            .is_err()
                        {
                            continue;
                        }
                        if let Ok(Control::Nodes { records }) = connection.recv().await {
                            return Ok(records);
                        }
                    }
                    Ok(Vec::new())
                });
            }

            let mut discovered = false;
            while let Some(result) = jobs.join_next().await {
                let records = result
                    .map_err(|e| NetworkError::Protocol(format!("lookup task failed: {e}")))??;
                for record in records {
                    if record.awe_id == *self.identity.public.awe_id.as_bytes() {
                        continue;
                    }
                    if !self.peers.read().await.contains_key(&record.awe_id) {
                        discovered = true;
                    }
                    self.routing.write().await.insert(record.clone());
                    {
                        let mut peers = self.peers.write().await;
                        insert_peer_bounded(&mut peers, record);
                    }
                }
            }

            if !discovered {
                break;
            }
        }

        Ok(self.closest_peers(target, alpha.saturating_mul(8)).await)
    }

    pub async fn peers(&self) -> Vec<PeerRecord> {
        self.peers.read().await.values().cloned().collect()
    }
    pub async fn closest_peers(&self, target: &[u8; 32], limit: usize) -> Vec<PeerRecord> {
        self.routing.read().await.closest(target, limit)
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;
    #[test]
    fn transport_bucket_hides_exact_payload_length() {
        // These constants define the AWE/WIRE-v1 framing contract.
        assert_eq!(FRAME_PAD_MIN, 256);
        assert_eq!(FRAME_LENGTH_PREFIX, 4);
    }

    #[test]
    fn routing_uses_xor_distance() {
        let mut r = RoutingTable::default();
        r.insert(PeerRecord {
            awe_id: [1; 32],
            public_key: [2; 32],
            addresses: vec![],
            protocol_version: VERSION,
            last_seen_unix: 0,
        });
        r.insert(PeerRecord {
            awe_id: [255; 32],
            public_key: [3; 32],
            addresses: vec![],
            protocol_version: VERSION,
            last_seen_unix: 0,
        });
        assert_eq!(r.closest(&[0; 32], 1)[0].awe_id, [1; 32]);
    }
    #[test]
    fn peer_refresh_preserves_last_known_endpoint() {
        let id = [9u8; 32];
        let address: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let mut peers = HashMap::new();
        insert_peer_bounded(
            &mut peers,
            PeerRecord {
                awe_id: id,
                public_key: [8; 32],
                addresses: vec![address],
                protocol_version: VERSION,
                last_seen_unix: 1,
            },
        );
        insert_peer_bounded(
            &mut peers,
            PeerRecord {
                awe_id: id,
                public_key: [8; 32],
                addresses: vec![],
                protocol_version: VERSION,
                last_seen_unix: 2,
            },
        );
        assert_eq!(peers.get(&id).unwrap().addresses, vec![address]);
        assert_eq!(peers.get(&id).unwrap().last_seen_unix, 2);
    }

    #[tokio::test]
    async fn authenticated_encrypted_transport() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let si = Arc::new(Identity::generate(Username::new("server").unwrap()));
        let ci = Arc::new(Identity::generate(Username::new("client").unwrap()));
        let t = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut c = handshake(s, si, a, false).await.unwrap();
            c.recv_data().await.unwrap()
        });
        let s = TcpStream::connect(a).await.unwrap();
        let mut c = handshake(s, ci, a, true).await.unwrap();
        c.send_data(1, b"awep2p".to_vec()).await.unwrap();
        assert_eq!(t.await.unwrap(), Some((1, b"awep2p".to_vec())));
    }
    #[tokio::test]
    async fn encrypted_data_plane_roundtrip_is_acknowledged() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let si = Arc::new(Identity::generate(
            Username::new("roundtrip-server").unwrap(),
        ));
        let ci = Arc::new(Identity::generate(
            Username::new("roundtrip-client").unwrap(),
        ));
        let t = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut server = handshake(s, si, a, false).await.unwrap();
            loop {
                match server.recv().await.unwrap() {
                    Control::Data { stream, payload } => {
                        server
                            .send(&Control::DataAck {
                                stream,
                                bytes: payload.len() as u32,
                            })
                            .await
                            .unwrap();
                        break;
                    }
                    Control::Ping { sequence } => {
                        server.send(&Control::Pong { sequence }).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        let s = TcpStream::connect(a).await.unwrap();
        let mut client = handshake(s, ci, a, true).await.unwrap();
        let elapsed = client
            .send_data_roundtrip(42, b"AWE-NET-END-TO-END-DATA".to_vec())
            .await
            .unwrap();
        assert!(elapsed < HELLO_TIMEOUT);
        t.await.unwrap();
    }

    #[tokio::test]
    async fn distinct_sessions_have_working_key_agreement() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let si = Arc::new(Identity::generate(Username::new("server2").unwrap()));
        let ci = Arc::new(Identity::generate(Username::new("client2").unwrap()));
        let t = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            handshake(s, si, a, false).await.unwrap()
        });
        let s = TcpStream::connect(a).await.unwrap();
        let mut c = handshake(s, ci, a, true).await.unwrap();
        let mut server = t.await.unwrap();
        server.send_data(7, b"ok".to_vec()).await.unwrap();
        assert_eq!(c.recv_data().await.unwrap(), Some((7, b"ok".to_vec())));
    }

    #[test]
    fn decoder_rejects_invalid_hello_signature() {
        let hello = Control::Hello {
            version: VERSION,
            awe_id: [1; 32],
            public_key: [2; 32],
            ephemeral: [3; 32],
            nonce: [4; 32],
            signature: vec![0; 63],
            advertised_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let encoded = encode(&hello).unwrap();
        assert!(matches!(
            decode(&encoded),
            Err(NetworkError::Authentication)
        ));
    }

    #[test]
    fn decoder_rejects_excess_peer_records() {
        let record = PeerRecord {
            awe_id: [1; 32],
            public_key: [2; 32],
            addresses: vec![],
            protocol_version: VERSION,
            last_seen_unix: 0,
        };
        let message = Control::Nodes {
            records: vec![record; MAX_NODE_RECORDS + 1],
        };
        let encoded = encode(&message).unwrap();
        assert!(matches!(decode(&encoded), Err(NetworkError::Protocol(_))));
    }

    #[test]
    fn decoder_rejects_excess_peer_addresses() {
        let record = PeerRecord {
            awe_id: [1; 32],
            public_key: [2; 32],
            addresses: (0..=MAX_ADDRESSES_PER_PEER)
                .map(|_| "127.0.0.1:4000".parse().unwrap())
                .collect(),
            protocol_version: VERSION,
            last_seen_unix: 0,
        };
        let encoded = encode(&Control::Nodes {
            records: vec![record],
        })
        .unwrap();
        assert!(matches!(decode(&encoded), Err(NetworkError::Protocol(_))));
    }

    #[test]
    fn decoder_rejects_wrong_peer_protocol_version() {
        let record = PeerRecord {
            awe_id: [1; 32],
            public_key: [2; 32],
            addresses: vec![],
            protocol_version: VERSION + 1,
            last_seen_unix: 0,
        };
        let encoded = encode(&Control::Nodes {
            records: vec![record],
        })
        .unwrap();
        assert!(matches!(decode(&encoded), Err(NetworkError::Protocol(_))));
    }

    #[test]
    fn decoder_rejects_oversized_data_payload() {
        let message = Control::Data {
            stream: 1,
            payload: vec![0; MAX_FRAME / 2 + 1],
        };
        let encoded = encode(&message).unwrap();
        assert!(matches!(decode(&encoded), Err(NetworkError::FrameTooLarge)));
    }

    #[test]
    fn a2p2_encrypted_wire_packet_hides_payload_and_roundtrips() {
        let key = [9u8; 32];
        let payload = b"secret over the wire";
        let packet = a2p2_seal(payload, &key).unwrap();
        assert_eq!(packet.len(), A2P2_FIXED_PACKET_SIZE);
        assert_eq!(a2p2_open(&packet, &key).unwrap(), payload);
        assert!(a2p2_open(&packet, &[8u8; 32]).is_err());
    }

    #[test]
    fn a2p2_rejects_oversized_payloads() {
        let key = [3u8; 32];
        let payload = vec![0u8; A2P2_MAX_PAYLOAD + 1];
        assert!(a2p2_seal(&payload, &key).is_err());
    }

    #[test]
    fn claimed_peer_id_must_match_signing_public_key() {
        let identity = Identity::generate(crate::identity::Username::new("peer-test").unwrap());
        let id = *identity.public.awe_id.as_bytes();
        assert!(peer_id_matches_public_key(&id, &identity.public.public_key));

        let mut forged_id = id;
        forged_id[0] ^= 0x80;
        assert!(!peer_id_matches_public_key(&forged_id, &identity.public.public_key));
    }

    #[test]
    fn a2p2_datagram_obfuscation_and_padding() {
        let payload = b"GET a2p2://site.awe/index.html HTTP/1.1";
        let key = [0x5Au8; 32];
        let packed = A2P2Datagram::pack(payload, &key).unwrap();
        assert_eq!(packed.len(), A2P2_FIXED_PACKET_SIZE);

        let unpacked = A2P2Datagram::unpack(&packed, &key).unwrap();
        assert_eq!(unpacked, payload);
        assert!(A2P2Datagram::unpack(&packed, &[0xA5u8; 32]).is_err());
    }

    #[test]
    fn triple_blind_onion_routing_3_hops() {
        let secret_a = StaticSecret::random_from_rng(OsRng);
        let pk_a = XPublic::from(&secret_a).to_bytes();

        let secret_b = StaticSecret::random_from_rng(OsRng);
        let pk_b = XPublic::from(&secret_b).to_bytes();

        let secret_c = StaticSecret::random_from_rng(OsRng);
        let pk_c = XPublic::from(&secret_c).to_bytes();

        let req_data = b"POST /api/v1/data HTTP/1.1";
        let target_service = "service.awe";

        let onion_packet =
            TripleBlindOnionPacket::build(req_data, target_service, &pk_a, &pk_b, &pk_c).unwrap();

        // Node A (Ingress) unwraps Layer 1
        let ingress_res = onion_packet.unwrap_ingress(&secret_a).unwrap();
        assert_eq!(ingress_res.next_hop, pk_b);

        // Node B (Relay/Mixnet) unwraps Layer 2
        let relay_res =
            TripleBlindOnionPacket::unwrap_relay(&ingress_res.relay_layer, &secret_b).unwrap();
        assert_eq!(relay_res.next_hop, pk_c);
        assert!(relay_res.mixnet_delay_ms >= 5 && relay_res.mixnet_delay_ms <= 50);

        // Node C (Egress) unwraps Layer 3
        let egress_res =
            TripleBlindOnionPacket::unwrap_egress(&relay_res.egress_layer, &secret_c).unwrap();
        assert_eq!(egress_res.service_y, target_service);
        assert_eq!(egress_res.request_payload, req_data);
    }
}
#[test]
fn peer_store_is_bounded_and_evicts_oldest() {
    let mut peers = HashMap::new();
    for i in 0..=MAX_PEER_RECORDS {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        insert_peer_bounded(
            &mut peers,
            PeerRecord {
                awe_id: id,
                public_key: id,
                addresses: vec![],
                protocol_version: VERSION,
                last_seen_unix: i as u64,
            },
        );
    }
    assert_eq!(peers.len(), MAX_PEER_RECORDS);
    let mut oldest = [0u8; 32];
    oldest[..8].copy_from_slice(&0u64.to_be_bytes());
    assert!(!peers.contains_key(&oldest));
}

#[test]
fn inbox_limits_are_finite() {
    const {
        assert!(MAX_INBOX_MESSAGES < 10_000);
        assert!(MAX_INBOX_BYTES <= 64 * 1024 * 1024);
    }
}
