//! Local Area Network (LAN) Mesh peer discovery and broadcast/multicast protocol.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const AWE_LAN_MULTICAST_ADDR: &str = "239.255.42.99:9999";
pub const LAN_MAGIC: &[u8] = b"AWEMESH1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanPeerBeacon {
    pub magic: Vec<u8>,
    pub node_id: [u8; 32],
    pub listen_addr: SocketAddr,
    pub is_gateway: bool,
    pub capabilities: Vec<String>,
}

impl LanPeerBeacon {
    pub fn new(node_id: [u8; 32], listen_addr: SocketAddr, is_gateway: bool) -> Self {
        Self {
            magic: LAN_MAGIC.to_vec(),
            node_id,
            listen_addr,
            is_gateway,
            capabilities: vec!["storage".into(), "dht".into(), "mesh".into()],
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(self).map_err(|_| "serialization error")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let beacon: Self = serde_json::from_slice(bytes).map_err(|_| "deserialization error")?;
        if beacon.magic != LAN_MAGIC {
            return Err("invalid LAN magic prefix");
        }
        Ok(beacon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_beacon_roundtrip() {
        let addr: SocketAddr = "192.168.1.50:9000".parse().unwrap();
        let beacon = LanPeerBeacon::new([7u8; 32], addr, true);
        let encoded = beacon.encode().unwrap();
        let decoded = LanPeerBeacon::decode(&encoded).unwrap();
        assert_eq!(decoded.node_id, [7u8; 32]);
        assert_eq!(decoded.listen_addr, addr);
        assert!(decoded.is_gateway);
    }
}
