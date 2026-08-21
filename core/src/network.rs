use crate::{crypto::hash, identity::Identity, replay::ReplayGuard};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::{BTreeMap, HashMap}, net::SocketAddr, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use thiserror::Error;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::RwLock, time::timeout};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME: usize = 16 * 1024 * 1024;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub awe_id: [u8; 32],
    pub public_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
    pub protocol_version: u16,
    pub last_seen_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Control {
    Hello { version: u16, awe_id: [u8; 32], public_key: [u8; 32], ephemeral: [u8; 32], nonce: [u8; 32], signature: [u8; 64] },
    Ping { sequence: u64 },
    Pong { sequence: u64 },
    Data { stream: u32, payload: Vec<u8> },
    FindNode { target: [u8; 32] },
    Nodes { records: Vec<PeerRecord> },
}

fn encode(value: &Control) -> Result<Vec<u8>, NetworkError> { serde_json::to_vec(value).map_err(|e| NetworkError::Protocol(e.to_string())) }
fn decode(value: &[u8]) -> Result<Control, NetworkError> { serde_json::from_slice(value).map_err(|e| NetworkError::Protocol(e.to_string())) }

async fn write_raw(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), NetworkError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME { return Err(NetworkError::FrameTooLarge); }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_raw(stream: &mut TcpStream) -> Result<Vec<u8>, NetworkError> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME { return Err(NetworkError::FrameTooLarge); }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn hello_bytes(version: u16, awe_id: &[u8; 32], public_key: &[u8; 32], ephemeral: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(146);
    bytes.extend_from_slice(b"AWE/HELLO/v1");
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(awe_id);
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(ephemeral);
    bytes.extend_from_slice(nonce);
    bytes
}

async fn handshake(mut stream: TcpStream, identity: Arc<Identity>, initiator: bool) -> Result<SecureConnection, NetworkError> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = XPublic::from(&ephemeral_secret).to_bytes();
    let mut local_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut local_nonce);
    let local_id = *identity.public.awe_id.as_bytes();
    let local_public_key = identity.public.public_key;
    let local_signature = identity.sign(&hello_bytes(PROTOCOL_VERSION, &local_id, &local_public_key, &ephemeral_public, &local_nonce));
    let local_hello = Control::Hello { version: PROTOCOL_VERSION, awe_id: local_id, public_key: local_public_key, ephemeral: ephemeral_public, nonce: local_nonce, signature: local_signature };

    let remote = if initiator {
        write_raw(&mut stream, &encode(&local_hello)?).await?;
        decode(&timeout(HELLO_TIMEOUT, read_raw(&mut stream)).await.map_err(|_| NetworkError::Timeout)??)?
    } else {
        let remote = decode(&timeout(HELLO_TIMEOUT, read_raw(&mut stream)).await.map_err(|_| NetworkError::Timeout)??)?;
        write_raw(&mut stream, &encode(&local_hello)?).await?;
        remote
    };

    let (remote_id, remote_public_key, remote_ephemeral, remote_nonce, remote_signature, version) = match remote {
        Control::Hello { version, awe_id, public_key, ephemeral, nonce, signature } => (awe_id, public_key, ephemeral, nonce, signature, version),
        _ => return Err(NetworkError::Protocol("expected hello".into())),
    };
    if version != PROTOCOL_VERSION { return Err(NetworkError::Protocol(format!("unsupported protocol version {version}"))); }
    if remote_id == local_id { return Err(NetworkError::Protocol("self connection".into())); }
    if !Identity::verify(&remote_public_key, &hello_bytes(version, &remote_id, &remote_public_key, &remote_ephemeral, &remote_nonce), &remote_signature) { return Err(NetworkError::Authentication); }

    let shared_secret = ephemeral_secret.diffie_hellman(&XPublic::from(remote_ephemeral));
    let (low_id, high_id, low_nonce, high_nonce) = if local_id < remote_id { (local_id, remote_id, local_nonce, remote_nonce) } else { (remote_id, local_id, remote_nonce, local_nonce) };
    let mut salt_input = Vec::with_capacity(128);
    salt_input.extend_from_slice(&low_id);
    salt_input.extend_from_slice(&high_id);
    salt_input.extend_from_slice(&low_nonce);
    salt_input.extend_from_slice(&high_nonce);
    let salt = hash(b"AWE/SESSION-SALT/v1", &salt_input);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut key_material = [0u8; 64];
    hkdf.expand(b"AWE/SESSION/v1", &mut key_material).map_err(|_| NetworkError::Encryption)?;
    let (tx_key, rx_key) = if initiator { (&key_material[..32], &key_material[32..]) } else { (&key_material[32..], &key_material[..32]) };
    Ok(SecureConnection { stream, remote_id, remote_public_key, tx: ChaCha20Poly1305::new_from_slice(tx_key).map_err(|_| NetworkError::Encryption)?, rx: ChaCha20Poly1305::new_from_slice(rx_key).map_err(|_| NetworkError::Encryption)?, tx_seq: 0, replay: ReplayGuard::default(), last_activity: Instant::now() })
}

pub struct SecureConnection {
    stream: TcpStream,
    pub remote_id: [u8; 32],
    pub remote_public_key: [u8; 32],
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_seq: u64,
    replay: ReplayGuard,
    last_activity: Instant,
}

impl SecureConnection {
    fn nonce(sequence: u64) -> [u8; 12] { let mut nonce = [0u8; 12]; nonce[4..].copy_from_slice(&sequence.to_be_bytes()); nonce }
    async fn send(&mut self, control: &Control) -> Result<(), NetworkError> {
        let plaintext = encode(control)?;
        let sequence = self.tx_seq;
        self.tx_seq = sequence.checked_add(1).ok_or_else(|| NetworkError::Protocol("sequence exhausted".into()))?;
        let aad = sequence.to_be_bytes();
        let ciphertext = self.tx.encrypt(Nonce::from_slice(&Self::nonce(sequence)), Payload { msg: &plaintext, aad: &aad }).map_err(|_| NetworkError::Encryption)?;
        let mut frame = Vec::with_capacity(aad.len() + ciphertext.len());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ciphertext);
        write_raw(&mut self.stream, &frame).await?;
        self.last_activity = Instant::now();
        Ok(())
    }
    async fn recv(&mut self) -> Result<Control, NetworkError> {
        let frame = read_raw(&mut self.stream).await?;
        if frame.len() < 8 { return Err(NetworkError::Protocol("short encrypted frame".into())); }
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&frame[..8]);
        let sequence = u64::from_be_bytes(sequence_bytes);
        if !self.replay.accept(self.remote_id, sequence) { return Err(NetworkError::Protocol("replayed frame".into())); }
        let plaintext = self.rx.decrypt(Nonce::from_slice(&Self::nonce(sequence)), Payload { msg: &frame[8..], aad: &sequence_bytes }).map_err(|_| NetworkError::Authentication)?;
        self.last_activity = Instant::now();
        decode(&plaintext)
    }
    pub async fn send_data(&mut self, stream: u32, payload: Vec<u8>) -> Result<(), NetworkError> {
        if payload.len() > MAX_FRAME / 2 { return Err(NetworkError::FrameTooLarge); }
        self.send(&Control::Data { stream, payload }).await
    }
    pub async fn ping(&mut self, sequence: u64) -> Result<(), NetworkError> { self.send(&Control::Ping { sequence }).await }
    pub async fn recv_data(&mut self) -> Result<Option<(u32, Vec<u8>)>, NetworkError> {
        match self.recv().await? {
            Control::Data { stream, payload } => Ok(Some((stream, payload))),
            Control::Ping { sequence } => { self.send(&Control::Pong { sequence }).await?; Ok(None) }
            Control::Pong { .. } | Control::Nodes { .. } => Ok(None),
            Control::FindNode { .. } | Control::Hello { .. } => Err(NetworkError::Protocol("unexpected control message".into())),
        }
    }
    pub fn is_idle(&self) -> bool { self.last_activity.elapsed() > IDLE_TIMEOUT }
}

#[derive(Clone, Debug, Default)]
pub struct RoutingTable { peers: BTreeMap<[u8; 32], PeerRecord> }
impl RoutingTable {
    pub fn insert(&mut self, peer: PeerRecord) { self.peers.insert(peer.awe_id, peer); }
    pub fn remove(&mut self, id: &[u8; 32]) { self.peers.remove(id); }
    pub fn closest(&self, target: &[u8; 32], limit: usize) -> Vec<PeerRecord> { let mut peers: Vec<_> = self.peers.values().cloned().collect(); peers.sort_by_key(|peer| xor_distance(&peer.awe_id, target)); peers.truncate(limit); peers }
    pub fn all(&self) -> Vec<PeerRecord> { self.peers.values().cloned().collect() }
}
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] { let mut distance = [0u8; 32]; for index in 0..32 { distance[index] = a[index] ^ b[index]; } distance }

#[derive(Clone)]
pub struct Node {
    pub identity: Arc<Identity>,
    pub listen_addr: SocketAddr,
    routing: Arc<RwLock<RoutingTable>>,
    peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>,
}
impl Node {
    pub fn new(identity: Identity, listen_addr: SocketAddr) -> Self { Self { identity: Arc::new(identity), listen_addr, routing: Arc::new(RwLock::new(RoutingTable::default())), peers: Arc::new(RwLock::new(HashMap::new())) } }
    async fn handle_connection(stream: TcpStream, address: SocketAddr, identity: Arc<Identity>, routing: Arc<RwLock<RoutingTable>>, peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>) {
        let Ok(mut connection) = handshake(stream, identity, false).await else { return; };
        let record = PeerRecord { awe_id: connection.remote_id, public_key: connection.remote_public_key, addresses: vec![address], protocol_version: PROTOCOL_VERSION, last_seen_unix: now() };
        routing.write().await.insert(record.clone());
        peers.write().await.insert(record.awe_id, record);
        let mut heartbeat_sequence = 0u64;
        loop {
            match timeout(HEARTBEAT_INTERVAL, connection.recv()).await {
                Ok(Ok(Control::Ping { sequence })) => { if connection.send(&Control::Pong { sequence }).await.is_err() { break; } }
                Ok(Ok(Control::Pong { .. })) => {}
                Ok(Ok(Control::FindNode { target })) => { let records = routing.read().await.closest(&target, 20); if connection.send(&Control::Nodes { records }).await.is_err() { break; } }
                Ok(Ok(Control::Data { .. })) => {}
                Ok(Ok(Control::Nodes { .. }) | Ok(Control::Hello { .. })) => break,
                Ok(Err(_)) => break,
                Err(_) => { if connection.is_idle() || connection.ping(heartbeat_sequence).await.is_err() { break; } heartbeat_sequence = heartbeat_sequence.wrapping_add(1); }
            }
        }
        routing.write().await.remove(&connection.remote_id);
        peers.write().await.remove(&connection.remote_id);
    }
    pub async fn listen(&self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        loop {
            let (stream, address) = listener.accept().await?;
            tokio::spawn(Self::handle_connection(stream, address, Arc::clone(&self.identity), Arc::clone(&self.routing), Arc::clone(&self.peers)));
        }
    }
    pub async fn connect(&self, address: SocketAddr) -> Result<SecureConnection, NetworkError> {
        let stream = timeout(HELLO_TIMEOUT, TcpStream::connect(address)).await.map_err(|_| NetworkError::Timeout)??;
        handshake(stream, Arc::clone(&self.identity), true).await
    }
    pub async fn bootstrap(&self, addresses: &[SocketAddr]) -> Result<usize, NetworkError> {
        let mut discovered = 0usize;
        for &address in addresses {
            let Ok(mut connection) = self.connect(address).await else { continue; };
            connection.send(&Control::FindNode { target: *self.identity.public.awe_id.as_bytes() }).await?;
            if let Ok(Control::Nodes { records }) = connection.recv().await {
                let mut routing = self.routing.write().await;
                let mut peers = self.peers.write().await;
                for record in records {
                    if record.awe_id == *self.identity.public.awe_id.as_bytes() { continue; }
                    routing.insert(record.clone());
                    peers.insert(record.awe_id, record);
                    discovered += 1;
                }
            }
        }
        Ok(discovered)
    }
    pub async fn peers(&self) -> Vec<PeerRecord> { self.peers.read().await.values().cloned().collect() }
    pub async fn closest_peers(&self, target: &[u8; 32], limit: usize) -> Vec<PeerRecord> { self.routing.read().await.closest(target, limit) }
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;

    #[test]
    fn routing_uses_xor_distance() {
        let mut routing = RoutingTable::default();
        routing.insert(PeerRecord { awe_id: [1; 32], public_key: [2; 32], addresses: vec![], protocol_version: PROTOCOL_VERSION, last_seen_unix: 0 });
        routing.insert(PeerRecord { awe_id: [255; 32], public_key: [3; 32], addresses: vec![], protocol_version: PROTOCOL_VERSION, last_seen_unix: 0 });
        assert_eq!(routing.closest(&[0; 32], 1)[0].awe_id, [1; 32]);
    }

    #[tokio::test]
    async fn authenticated_encrypted_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_identity = Arc::new(Identity::generate(Username::new("server").unwrap()));
        let client_identity = Arc::new(Identity::generate(Username::new("client").unwrap()));
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = handshake(stream, server_identity, false).await.unwrap();
            connection.recv_data().await.unwrap()
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let mut client = handshake(stream, client_identity, true).await.unwrap();
        client.send_data(1, b"awep2p".to_vec()).await.unwrap();
        assert_eq!(server_task.await.unwrap(), Some((1, b"awep2p".to_vec())));
    }

    #[tokio::test]
    async fn node_can_accept_real_loopback_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_identity = Arc::new(Identity::generate(Username::new("server").unwrap()));
        let client_identity = Arc::new(Identity::generate(Username::new("client").unwrap()));
        let server_routing = Arc::new(RwLock::new(RoutingTable::default()));
        let server_peers = Arc::new(RwLock::new(HashMap::new()));
        let server_task = tokio::spawn(async move {
            let (stream, peer_address) = listener.accept().await.unwrap();
            Node::handle_connection(stream, peer_address, server_identity, server_routing.clone(), server_peers.clone()).await;
            server_peers.read().await.len()
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let _client = handshake(stream, client_identity, true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        server_task.abort();
    }
}
