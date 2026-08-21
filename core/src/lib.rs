//! AWEp2P platform-independent core and real peer-to-peer transport.
//! Platform clients share identity, security, networking, namespace, storage,
//! hosting and privacy-first messaging primitives.

pub mod canonical;
pub mod crypto;
pub mod host;
pub mod host_directory;
pub mod identity;
pub mod messenger;
pub mod namespace;
pub mod network;
pub mod permissions;
pub mod protocol;
pub mod registry;
pub mod replay;
pub mod storage;
