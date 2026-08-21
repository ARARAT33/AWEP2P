//! Native AWEOS subsystem boundary.
//! Shares the same Rust core, identity model, P2P protocol, and capability security.

use awep2p_core::identity::Identity;
use awep2p_core::network::Node;
use std::net::SocketAddr;

pub struct AweosNodeRuntime {
    pub node: Node,
    pub aweos_fs_root: String,
}

impl AweosNodeRuntime {
    pub fn new(identity: Identity, listen: SocketAddr, aweos_fs_root: String) -> Self {
        let node = Node::new(identity, listen);
        Self {
            node,
            aweos_fs_root,
        }
    }

    pub fn system_subsystem_name() -> &'static str {
        "AWEOS AWEp2P Subsystem"
    }
}
