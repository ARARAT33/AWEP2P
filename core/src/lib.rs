//! AWEp2P core primitives.
//!
//! This crate intentionally starts with deterministic, platform-independent
//! protocol building blocks. Networking, storage, and UI layers will depend on
//! these primitives rather than defining their own incompatible identities.

pub mod identity;
pub mod protocol;
pub mod registry;
