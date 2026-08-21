//! Linux daemon/systemd service integration boundary.

use std::path::PathBuf;

pub struct LinuxNodeDaemon {
    pub state_dir: PathBuf,
    pub unix_socket: PathBuf,
}

impl LinuxNodeDaemon {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            unix_socket: state_dir.join("awep2p.sock"),
            state_dir,
        }
    }

    pub fn platform_target(&self) -> &'static str {
        "linux"
    }

    /// Generates systemd unit file contents for AWEp2P daemon.
    pub fn systemd_unit(&self, exec_path: &str) -> String {
        format!(
            r#"[Unit]
Description=AWEp2P Sovereign Node Daemon
After=network.target

[Service]
Type=simple
User=awep2p
ExecStart={} run --daemon
Restart=always
RestartSec=5
WorkingDirectory={}

[Install]
WantedBy=multi-user.target
"#,
            exec_path,
            self.state_dir.display()
        )
    }
}
