//! AWEp2P platform-independent core and real peer-to-peer transport.
//! Platform clients build on the same identity, protocol, security, networking,
//! and decentralized namespace primitives.

pub mod canonical;
pub mod crypto;
pub mod identity;
pub mod namespace;
pub mod network;
pub mod permissions;
pub mod protocol;
pub mod registry;
pub mod replay;
