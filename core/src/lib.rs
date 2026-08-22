//! AWEp2P platform-independent core and real peer-to-peer transport.
//! Platform clients share identity, security, networking, namespace, storage,
//! hosting, privacy-first messaging, diagnostics, governance, and application store primitives.

pub mod canonical;
pub mod crypto;
pub mod diagnostics;
pub mod governance;
pub mod host;
pub mod host_directory;
pub mod identity;
pub mod lan_mesh;
pub mod messenger;
pub mod namespace;
pub mod network;
pub mod node;
pub mod permissions;
pub mod protocol;
pub mod recovery;
pub mod registry;
pub mod replay;
pub mod reputation;
pub mod sandbox;
pub mod storage;
pub mod store;
