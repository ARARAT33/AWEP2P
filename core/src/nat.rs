//! UDP endpoint discovery and hole-punching primitives.
//! This is deliberately transport-level: it does not assume a public STUN
//! service. A coordinator can exchange signed candidate addresses and both
//! peers can then perform bounded simultaneous probes.

use blake3::Hasher;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

pub const NAT_PROBE_MAGIC: &[u8] = b"AWE/NAT/v1";
pub const MAX_CANDIDATES: usize = 16;
pub const PROBE_ATTEMPTS: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointCandidate {
    pub address: SocketAddr,
    pub priority: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatChallenge {
    pub token: [u8; 32],
    pub expires_at_unix: u64,
}

impl NatChallenge {
    pub fn derive(session_id: &[u8; 32], local: &SocketAddr, remote: &SocketAddr, now_unix: u64) -> Self {
        let mut h = Hasher::new();
        h.update(NAT_PROBE_MAGIC);
        h.update(session_id);
        h.update(local.to_string().as_bytes());
        h.update(remote.to_string().as_bytes());
        h.update(&now_unix.to_be_bytes());
        Self {
            token: *h.finalize().as_bytes(),
            expires_at_unix: now_unix.saturating_add(30),
        }
    }

    pub fn valid(&self, token: &[u8], now_unix: u64) -> bool {
        now_unix <= self.expires_at_unix && token == self.token
    }
}

pub fn rank_candidates(mut candidates: Vec<EndpointCandidate>) -> Vec<EndpointCandidate> {
    candidates.sort_by_key(|c| (c.priority, c.address));
    candidates.dedup_by_key(|c| c.address);
    candidates.truncate(MAX_CANDIDATES);
    candidates
}

pub async fn punch(
    socket: &UdpSocket,
    local_candidates: &[EndpointCandidate],
    remote_candidates: &[EndpointCandidate],
    session_id: &[u8; 32],
    timeout_duration: Duration,
) -> Option<SocketAddr> {
    let local = socket.local_addr().ok()?;
    let started = Instant::now();
    let peers = rank_candidates(remote_candidates.to_vec());
    if peers.is_empty() || local_candidates.is_empty() {
        return None;
    }

    for attempt in 0..PROBE_ATTEMPTS {
        if started.elapsed() >= timeout_duration {
            return None;
        }
        for peer in &peers {
            let challenge = NatChallenge::derive(session_id, &local, &peer.address, attempt as u64);
            let mut packet = Vec::with_capacity(NAT_PROBE_MAGIC.len() + 32);
            packet.extend_from_slice(NAT_PROBE_MAGIC);
            packet.extend_from_slice(&challenge.token);
            if socket.send_to(&packet, peer.address).await.is_err() {
                continue;
            }

            let remaining = timeout_duration.saturating_sub(started.elapsed());
            let wait = remaining.min(Duration::from_millis(250));
            let mut buf = [0u8; 256];
            if let Ok(Ok((n, from))) = timeout(wait, socket.recv_from(&mut buf)).await {
                if n == NAT_PROBE_MAGIC.len() + 32
                    && &buf[..NAT_PROBE_MAGIC.len()] == NAT_PROBE_MAGIC
                    && from == peer.address
                {
                    return Some(from);
                }
            }
        }
    }
    None
}

pub fn build_response(challenge: &NatChallenge, now_unix: u64) -> Option<Vec<u8>> {
    if challenge.expires_at_unix < now_unix {
        return None;
    }
    let mut out = Vec::with_capacity(NAT_PROBE_MAGIC.len() + 32);
    out.extend_from_slice(NAT_PROBE_MAGIC);
    out.extend_from_slice(&challenge.token);
    Some(out)
}
