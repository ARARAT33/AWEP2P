//! AWEp2P platform-independent core and real peer-to-peer transport.
//! Platform clients share identity, security, networking, namespace, storage,
//! hosting, privacy-first messaging and decentralized application-store primitives.

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
pub mod store;
