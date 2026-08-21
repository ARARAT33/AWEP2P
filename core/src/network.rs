use crate::{crypto::hash, identity::Identity, replay::ReplayGuard};
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
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    time::timeout,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const VERSION: u16 = 1;
const MAX_FRAME: usize = 16 * 1024 * 1024;
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
    Hello {
        version: u16,
        awe_id: [u8; 32],
        public_key: [u8; 32],
        ephemeral: [u8; 32],
        nonce: [u8; 32],
        signature: Vec<u8>,
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
    serde_json::from_slice(v).map_err(|e| NetworkError::Protocol(e.to_string()))
}
async fn write_frame(s: &mut TcpStream, b: &[u8]) -> Result<(), NetworkError> {
    if b.is_empty() || b.len() > MAX_FRAME {
        return Err(NetworkError::FrameTooLarge);
    }
    s.write_u32(b.len() as u32).await?;
    s.write_all(b).await?;
    s.flush().await?;
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
fn hello_bytes(v: u16, id: &[u8; 32], pk: &[u8; 32], e: &[u8; 32], n: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(146);
    b.extend_from_slice(b"AWE/HELLO/v1");
    b.extend_from_slice(&v.to_be_bytes());
    b.extend_from_slice(id);
    b.extend_from_slice(pk);
    b.extend_from_slice(e);
    b.extend_from_slice(n);
    b
}

async fn handshake(
    mut stream: TcpStream,
    identity: Arc<Identity>,
    initiator: bool,
) -> Result<SecureConnection, NetworkError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral = XPublic::from(&secret).to_bytes();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let id = *identity.public.awe_id.as_bytes();
    let pk = identity.public.public_key;
    let sig = identity.sign(&hello_bytes(VERSION, &id, &pk, &ephemeral, &nonce));
    let hello = Control::Hello {
        version: VERSION,
        awe_id: id,
        public_key: pk,
        ephemeral,
        nonce,
        signature: sig.to_vec(),
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
    let (rid, rpk, re, rnonce, rsig, version) = match remote {
        Control::Hello {
            version,
            awe_id,
            public_key,
            ephemeral,
            nonce,
            signature,
        } => (awe_id, public_key, ephemeral, nonce, signature, version),
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
    let rsig: [u8; 64] = rsig
        .as_slice()
        .try_into()
        .map_err(|_| NetworkError::Authentication)?;
    if !Identity::verify(
        &rpk,
        &hello_bytes(version, &rid, &rpk, &re, &rnonce),
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
        let s = self.tx_seq;
        self.tx_seq = s
            .checked_add(1)
            .ok_or_else(|| NetworkError::Protocol("sequence exhausted".into()))?;
        let aad = s.to_be_bytes();
        let e = self
            .tx
            .encrypt(
                Nonce::from_slice(&Self::nonce(s)),
                Payload { msg: &p, aad: &aad },
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
        self.last_activity = Instant::now();
        decode(&p)
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
    pub async fn recv_data(&mut self) -> Result<Option<(u32, Vec<u8>)>, NetworkError> {
        match self.recv().await? {
            Control::Data { stream, payload } => Ok(Some((stream, payload))),
            Control::Ping { sequence } => {
                self.send(&Control::Pong { sequence }).await?;
                Ok(None)
            }
            Control::Pong { .. } | Control::Nodes { .. } => Ok(None),
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
    }
    pub fn remove(&mut self, id: &[u8; 32]) {
        self.peers.remove(id);
    }
    pub fn closest(&self, target: &[u8; 32], limit: usize) -> Vec<PeerRecord> {
        let mut v: Vec<_> = self.peers.values().cloned().collect();
        v.sort_by_key(|p| xor_distance(&p.awe_id, target));
        v.truncate(limit);
        v
    }
    pub fn all(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }
}
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i]
    }
    d
}

#[derive(Clone)]
pub struct Node {
    pub identity: Arc<Identity>,
    pub listen_addr: SocketAddr,
    routing: Arc<RwLock<RoutingTable>>,
    peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>,
}
impl Node {
    pub fn new(identity: Identity, listen_addr: SocketAddr) -> Self {
        Self {
            identity: Arc::new(identity),
            listen_addr,
            routing: Arc::new(RwLock::new(RoutingTable::default())),
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    async fn handle(
        stream: TcpStream,
        address: SocketAddr,
        identity: Arc<Identity>,
        routing: Arc<RwLock<RoutingTable>>,
        peers: Arc<RwLock<HashMap<[u8; 32], PeerRecord>>>,
    ) {
        let Ok(mut c) = handshake(stream, identity, false).await else {
            return;
        };
        let r = PeerRecord {
            awe_id: c.remote_id,
            public_key: c.remote_public_key,
            addresses: vec![address],
            protocol_version: VERSION,
            last_seen_unix: now(),
        };
        routing.write().await.insert(r.clone());
        peers.write().await.insert(r.awe_id, r);
        let mut seq = 0u64;
        loop {
            match timeout(HEARTBEAT, c.recv()).await {
                Ok(Ok(Control::Ping { sequence })) => {
                    if c.send(&Control::Pong { sequence }).await.is_err() {
                        break;
                    }
                }
                Ok(Ok(Control::Pong { .. })) => {}
                Ok(Ok(Control::FindNode { target })) => {
                    let records = routing.read().await.closest(&target, 20);
                    if c.send(&Control::Nodes { records }).await.is_err() {
                        break;
                    }
                }
                Ok(Ok(Control::Data { .. })) => {}
                Ok(Ok(Control::Nodes { .. } | Control::Hello { .. })) => break,
                Ok(Err(_)) => break,
                Err(_) => {
                    if c.is_idle() || c.ping(seq).await.is_err() {
                        break;
                    }
                    seq = seq.wrapping_add(1)
                }
            }
        }
        routing.write().await.remove(&c.remote_id);
        peers.write().await.remove(&c.remote_id);
    }
    pub async fn listen(&self) -> Result<(), NetworkError> {
        let l = TcpListener::bind(self.listen_addr).await?;
        loop {
            let (s, a) = l.accept().await?;
            tokio::spawn(Self::handle(
                s,
                a,
                Arc::clone(&self.identity),
                Arc::clone(&self.routing),
                Arc::clone(&self.peers),
            ));
        }
    }
    pub async fn connect(&self, address: SocketAddr) -> Result<SecureConnection, NetworkError> {
        let s = timeout(HELLO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| NetworkError::Timeout)??;
        handshake(s, Arc::clone(&self.identity), true).await
    }
    pub async fn bootstrap(&self, addresses: &[SocketAddr]) -> Result<usize, NetworkError> {
        let mut found = 0;
        for &a in addresses {
            let Ok(mut c) = self.connect(a).await else {
                continue;
            };
            c.send(&Control::FindNode {
                target: *self.identity.public.awe_id.as_bytes(),
            })
            .await?;
            if let Ok(Control::Nodes { records }) = c.recv().await {
                let mut r = self.routing.write().await;
                let mut p = self.peers.write().await;
                for x in records {
                    if x.awe_id == *self.identity.public.awe_id.as_bytes() {
                        continue;
                    }
                    r.insert(x.clone());
                    p.insert(x.awe_id, x);
                    found += 1
                }
            }
        }
        Ok(found)
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
    #[tokio::test]
    async fn authenticated_encrypted_transport() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let si = Arc::new(Identity::generate(Username::new("server").unwrap()));
        let ci = Arc::new(Identity::generate(Username::new("client").unwrap()));
        let t = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut c = handshake(s, si, false).await.unwrap();
            c.recv_data().await.unwrap()
        });
        let s = TcpStream::connect(a).await.unwrap();
        let mut c = handshake(s, ci, true).await.unwrap();
        c.send_data(1, b"awep2p".to_vec()).await.unwrap();
        assert_eq!(t.await.unwrap(), Some((1, b"awep2p".to_vec())));
    }
    #[tokio::test]
    async fn distinct_sessions_have_working_key_agreement() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let si = Arc::new(Identity::generate(Username::new("server2").unwrap()));
        let ci = Arc::new(Identity::generate(Username::new("client2").unwrap()));
        let t = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            handshake(s, si, false).await.unwrap()
        });
        let s = TcpStream::connect(a).await.unwrap();
        let mut c = handshake(s, ci, true).await.unwrap();
        let mut server = t.await.unwrap();
        server.send_data(7, b"ok".to_vec()).await.unwrap();
        assert_eq!(c.recv_data().await.unwrap(), Some((7, b"ok".to_vec())));
    }
}
