//! Windows AWEp2P service integration boundary.
//! Long-lived background node service management on Windows.

use std::path::PathBuf;

#[cfg(windows)]
pub fn service_name() -> &'static str {
    "AWEp2P Node Service"
}

pub fn platform_target() -> &'static str {
    "windows"
}

pub struct WindowsNodeService {
    pub autostart: bool,
    pub local_ipc_only: bool,
    pub data_dir: PathBuf,
}

impl Default for WindowsNodeService {
    fn default() -> Self {
        let data_dir = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("AWEp2P");

        Self {
            autostart: true,
            local_ipc_only: true,
            data_dir,
        }
    }
}

impl WindowsNodeService {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            autostart: true,
            local_ipc_only: true,
            data_dir,
        }
    }

    /// Generates Windows Service installation command.
    pub fn service_install_cmd(&self, binary_path: &str) -> String {
        format!(
            "sc create \"AWEp2P\" binPath= \"{}\" start= auto displayname= \"AWEp2P Node Service\"",
            binary_path
        )
    }
}
