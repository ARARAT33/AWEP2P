//! Windows AWEp2P service integration boundary.
//! The actual long-lived node is provided by the shared Rust core.

#[cfg(windows)]
pub fn service_name() -> &'static str { "AWEp2P Node Service" }

pub fn platform_target() -> &'static str { "windows" }

pub struct WindowsNodeService {
    pub autostart: bool,
    pub local_ipc_only: bool,
}

impl Default for WindowsNodeService {
    fn default() -> Self { Self { autostart: true, local_ipc_only: true } }
}
