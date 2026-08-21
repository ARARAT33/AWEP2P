//! Linux daemon/CLI integration boundary.

use std::path::PathBuf;

pub struct LinuxNodeDaemon { pub state_dir: PathBuf, pub unix_socket: PathBuf }
impl LinuxNodeDaemon {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir=state_dir.into();
        Self { unix_socket: state_dir.join("awep2p.sock"), state_dir }
    }
    pub fn platform_target(&self) -> &'static str { "linux" }
}
