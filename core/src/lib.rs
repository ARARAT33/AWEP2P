//! AWEp2P platform-independent security and protocol core.
//! Platform clients must build on these primitives rather than creating
//! incompatible identity or authorization implementations.

pub mod crypto;
pub mod identity;
pub mod permissions;
pub mod protocol;
pub mod registry;
pub mod replay;
