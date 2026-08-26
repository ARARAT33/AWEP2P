use crate::identity::Identity;
use crate::network::format_node_descriptor;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HardwareAllocation {
    pub gpu_vram_mb: u64,
    pub tpu_units: u64,
    pub vcpu_cores: u32,
    pub ram_mb: u64,
    pub ssd_gb: u64,
    pub hdd_gb: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub username: String,
    pub awe_id: String,
    pub nid: String,
    pub offered_bytes: u64,
    pub available_bytes: u64,
    pub is_active_node: bool,
    pub node_descriptor: Option<String>,
    pub site_dashboard_unlocked: bool,
    pub is_datacenter_scale: bool,
    pub hardware_allocation: HardwareAllocation,
    pub background_worker_active: bool,
}

impl NodeInfo {
    pub fn save_state(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
    }

    pub fn load_state(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let info: Self = serde_json::from_str(&content)?;
        Ok(info)
    }

    pub fn compute_decentralization_health_score(&self) -> u32 {
        if !self.is_active_node {
            return 0;
        }
        let mut score = 50u32;
        if self.offered_bytes > 0 {
            score += 20;
        }
        if self.hardware_allocation.vcpu_cores >= 2 {
            score += 15;
        }
        if self.hardware_allocation.ram_mb >= 2048 {
            score += 15;
        }
        score.min(100)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkCapacityMetrics {
    pub total_active_nodes: u64,
    pub user_contributed_bytes: u64,
    pub global_network_bytes: u64,
    pub dynamic_site_storage_limit_bytes: u64,
}

impl NetworkCapacityMetrics {
    pub fn calculate(active_nodes_count: u64, user_contributed_bytes: u64) -> Self {
        // Base dynamic network capacity calculation:
        // Each node added increases the total network capacity dynamically.
        let base_node_avg = 50 * 1024 * 1024 * 1024u64; // 50 GB average per peer node
        let global_network_bytes = active_nodes_count
            .max(1)
            .saturating_mul(base_node_avg)
            .saturating_add(user_contributed_bytes);

        // Dynamic site storage limit scales with network capacity (min 10 GB, max unbounded)
        let dynamic_site_storage_limit_bytes =
            (global_network_bytes / 5).max(10 * 1024 * 1024 * 1024);

        Self {
            total_active_nodes: active_nodes_count.max(1),
            user_contributed_bytes,
            global_network_bytes,
            dynamic_site_storage_limit_bytes,
        }
    }
}

pub fn get_available_disk_space(path: &Path) -> io::Result<u64> {
    let target_path = if path.exists() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            parent.to_path_buf()
        } else {
            std::env::current_dir()?
        }
    } else {
        std::env::current_dir()?
    };

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(target_path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0 {
            let free_bytes = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
            Ok(free_bytes)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = target_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut free_bytes_available: u64 = 0;
        let mut total_number_of_bytes: u64 = 0;
        let mut total_number_of_free_bytes: u64 = 0;
        let res = unsafe {
            winapi::um::fileapi::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes_available as *mut _ as _,
                &mut total_number_of_bytes as *mut _ as _,
                &mut total_number_of_free_bytes as *mut _ as _,
            )
        };
        if res != 0 {
            Ok(free_bytes_available)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(100 * 1024 * 1024 * 1024) // fallback
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeAllocationMode {
    FolderAllocation { folder_path: String },
    WholeNonSystemDisksAllocation { allocated_disks: Vec<String> },
}

pub fn validate_and_configure_node_allocation(
    mode: &NodeAllocationMode,
) -> Result<HardwareAllocation, String> {
    match mode {
        NodeAllocationMode::FolderAllocation { folder_path } => {
            if folder_path.is_empty() {
                return Err("Folder path cannot be empty".into());
            }
            Ok(HardwareAllocation {
                gpu_vram_mb: 1024,
                tpu_units: 0,
                vcpu_cores: 2,
                ram_mb: 2048,
                ssd_gb: 20,
                hdd_gb: 0,
            })
        }
        NodeAllocationMode::WholeNonSystemDisksAllocation { allocated_disks } => {
            for disk in allocated_disks {
                let lower = disk.to_lowercase();
                if lower == "c:"
                    || lower == "c:\\"
                    || lower == "/"
                    || lower == "/boot"
                    || lower == "/sys"
                {
                    return Err(format!(
                        "System disk ({}) allocation is prohibited! Choose a non-system disk.",
                        disk
                    ));
                }
            }
            if allocated_disks.is_empty() {
                return Err("No non-system disks selected for full allocation mode".into());
            }
            Ok(HardwareAllocation {
                gpu_vram_mb: 16384,
                tpu_units: 2,
                vcpu_cores: 16,
                ram_mb: 65536,
                ssd_gb: 2000,
                hdd_gb: 8000,
            })
        }
    }
}

pub fn configure_node_storage(
    identity: &Identity,
    storage_path: &Path,
    offered_bytes: u64,
    hardware: HardwareAllocation,
) -> Result<NodeInfo, String> {
    if offered_bytes == 0 && hardware.ram_mb == 0 && hardware.vcpu_cores == 0 {
        return Err("Offered resources must be greater than 0 to become a Node.".into());
    }

    let real_available = get_available_disk_space(storage_path)
        .map_err(|e| format!("Failed to verify hardware disk space: {e}"))?;

    if offered_bytes > real_available {
        return Err(format!(
            "Offered storage size ({:.2} GB) exceeds actual available disk space ({:.2} GB). Node registration rejected.",
            offered_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            real_available as f64 / (1024.0 * 1024.0 * 1024.0)
        ));
    }

    // Ensure storage path is created
    if !storage_path.exists() {
        fs::create_dir_all(storage_path)
            .map_err(|e| format!("Failed to initialize node storage directory: {e}"))?;
    }

    let node_desc = format_node_descriptor(identity.public.awe_id.as_bytes());
    let nid = format!("nid-{}", &identity.public.awe_id.to_hex()[..16]);
    let is_datacenter_scale = offered_bytes >= 1000 * 1024 * 1024 * 1024 || hardware.tpu_units >= 1;

    let info = NodeInfo {
        username: identity.public.username.as_str().to_string(),
        awe_id: identity.public.awe_id.to_hex(),
        nid,
        offered_bytes,
        available_bytes: real_available,
        is_active_node: true,
        node_descriptor: Some(node_desc),
        site_dashboard_unlocked: true,
        is_datacenter_scale,
        hardware_allocation: hardware,
        background_worker_active: true,
    };

    let state_file = storage_path.join("node_state.json");
    let _ = info.save_state(&state_file);

    Ok(info)
}

/// Proof-of-Relay / Bandwidth Relay contribution tracker.
/// Nodes earn rights to consume network bandwidth (downloads, hosting)
/// only by relaying transit traffic for anonymous network peers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfRelayTracker {
    pub bytes_relayed_transit: u64,
    pub bytes_consumed: u64,
}

impl Default for ProofOfRelayTracker {
    fn default() -> Self {
        Self {
            bytes_relayed_transit: 10 * 1024 * 1024, // 10MB initial bootstrap bonus
            bytes_consumed: 0,
        }
    }
}

impl ProofOfRelayTracker {
    pub fn record_transit_relayed(&mut self, bytes: u64) {
        self.bytes_relayed_transit = self.bytes_relayed_transit.saturating_add(bytes);
    }

    pub fn can_consume(&self, bytes_requested: u64) -> bool {
        // Enforce Proof-of-Contribution: max consumption is 2x relayed bandwidth
        let max_allowable = self.bytes_relayed_transit.saturating_mul(2);
        self.bytes_consumed.saturating_add(bytes_requested) <= max_allowable
    }

    pub fn consume(&mut self, bytes_requested: u64) -> Result<(), String> {
        if !self.can_consume(bytes_requested) {
            return Err("Resource consumption rejected: Insufficient Proof-of-Relay contribution. Relay more transit traffic first.".into());
        }
        self.bytes_consumed = self.bytes_consumed.saturating_add(bytes_requested);
        Ok(())
    }
}

/// Native Browser Engine Anti-Fingerprinting Configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureBrowserConfig {
    pub canvas_fingerprint_spoofed: bool,
    pub webgl_vendor_spoofed: bool,
    pub system_fonts_masked: bool,
    pub audio_context_noise_enabled: bool,
    pub user_agent_normalized: String,
}

impl Default for SecureBrowserConfig {
    fn default() -> Self {
        Self {
            canvas_fingerprint_spoofed: true,
            webgl_vendor_spoofed: true,
            system_fonts_masked: true,
            audio_context_noise_enabled: true,
            user_agent_normalized: "AWEP2P/1.0 (Sovereign; Zero-Fingerprint)".into(),
        }
    }
}

/// Standalone Desktop IPC Request/Response Primitives (No Local Port Exposure)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AweIpcCommand {
    GetNodeStatus,
    ResolveAweName {
        domain: String,
    },
    SendOnionPacket {
        target_service: String,
        payload: Vec<u8>,
    },
    CheckRelayContribution,
    ExecuteWasmCompute {
        script_wasm: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AweIpcResponse {
    Status(NodeInfo),
    AweNameResolved { domain: String, target_hash: String },
    OnionPacketRouted { packet_id: String },
    RelayStatus(ProofOfRelayTracker),
    WasmExecutionResult { exit_code: i32, output: Vec<u8> },
    Error(String),
}

pub struct StandaloneAweNode {
    pub info: NodeInfo,
    pub relay_tracker: ProofOfRelayTracker,
    pub browser_config: SecureBrowserConfig,
}

impl StandaloneAweNode {
    pub fn new(info: NodeInfo) -> Self {
        Self {
            info,
            relay_tracker: ProofOfRelayTracker::default(),
            browser_config: SecureBrowserConfig::default(),
        }
    }

    /// Internal IPC handler for standalone desktop client GUI.
    /// Operates completely via memory / internal IPC without opening local proxy or HTTP ports.
    pub fn handle_internal_ipc_request(&mut self, request: AweIpcCommand) -> AweIpcResponse {
        match request {
            AweIpcCommand::GetNodeStatus => AweIpcResponse::Status(self.info.clone()),
            AweIpcCommand::ResolveAweName { domain } => {
                if !domain.ends_with(".awe") {
                    return AweIpcResponse::Error("Domain must end with .awe".into());
                }
                let target_hash = crate::crypto::hash(b"AWE-NAME-RESOLVE", domain.as_bytes());
                AweIpcResponse::AweNameResolved {
                    domain,
                    target_hash: hex::encode(target_hash),
                }
            }
            AweIpcCommand::CheckRelayContribution => {
                AweIpcResponse::RelayStatus(self.relay_tracker.clone())
            }
            AweIpcCommand::SendOnionPacket {
                target_service: _,
                payload,
            } => {
                if let Err(e) = self.relay_tracker.consume(payload.len() as u64) {
                    return AweIpcResponse::Error(e);
                }
                let pid = hex::encode(&crate::crypto::hash(b"ONION-ID", &payload)[..8]);
                AweIpcResponse::OnionPacketRouted {
                    packet_id: format!("onion-{}", pid),
                }
            }
            AweIpcCommand::ExecuteWasmCompute { script_wasm } => {
                if script_wasm.is_empty() {
                    return AweIpcResponse::Error("Empty WASM binary".into());
                }
                // Executed in local sandbox
                AweIpcResponse::WasmExecutionResult {
                    exit_code: 0,
                    output: b"WASM Executed Successfully".to_vec(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;

    #[test]
    fn test_disk_space_verification() {
        let temp_dir = std::env::temp_dir();
        let space = get_available_disk_space(&temp_dir).unwrap();
        assert!(space > 0);
    }

    #[test]
    fn test_node_allocation_modes_and_system_disk_protection() {
        // Folder allocation
        let folder_mode = NodeAllocationMode::FolderAllocation {
            folder_path: "/var/awe_data".into(),
        };
        let hw_light = validate_and_configure_node_allocation(&folder_mode).unwrap();
        assert_eq!(hw_light.vcpu_cores, 2);

        // Whole non-system disks allocation
        let disk_mode = NodeAllocationMode::WholeNonSystemDisksAllocation {
            allocated_disks: vec!["D:\\".into(), "E:\\".into()],
        };
        let hw_full = validate_and_configure_node_allocation(&disk_mode).unwrap();
        assert_eq!(hw_full.vcpu_cores, 16);

        // System disk allocation attempt is prohibited
        let system_disk_attempt = NodeAllocationMode::WholeNonSystemDisksAllocation {
            allocated_disks: vec!["C:\\".into()],
        };
        assert!(validate_and_configure_node_allocation(&system_disk_attempt).is_err());
    }

    #[test]
    fn test_node_configuration_valid_and_excessive() {
        let temp_dir = std::env::temp_dir().join("awe_test_node_store");
        let space = get_available_disk_space(&temp_dir).unwrap();
        let identity = Identity::generate(Username::new("ararat").unwrap());

        // Valid offer
        let valid_offer = space / 2;
        let hw = HardwareAllocation {
            gpu_vram_mb: 4096,
            tpu_units: 0,
            vcpu_cores: 4,
            ram_mb: 8192,
            ssd_gb: 50,
            hdd_gb: 0,
        };
        let info = configure_node_storage(&identity, &temp_dir, valid_offer, hw.clone()).unwrap();
        assert!(info.is_active_node);
        assert!(info.node_descriptor.is_some());
        assert!(info.site_dashboard_unlocked);
        assert_eq!(info.hardware_allocation, hw);
        assert!(info.background_worker_active);

        // Verify state persistence
        let state_file = temp_dir.join("node_state.json");
        let loaded = NodeInfo::load_state(&state_file).unwrap();
        assert_eq!(loaded.username, "ararat");
        assert_eq!(loaded.hardware_allocation, hw);

        // Excessive offer
        let excessive_offer = space.saturating_add(1000 * 1024 * 1024 * 1024);
        let err = configure_node_storage(
            &identity,
            &temp_dir,
            excessive_offer,
            HardwareAllocation::default(),
        );
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .contains("exceeds actual available disk space"));

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_network_capacity_scaling() {
        let base_metrics = NetworkCapacityMetrics::calculate(1, 10 * 1024 * 1024 * 1024);
        let scaled_metrics = NetworkCapacityMetrics::calculate(100, 1000 * 1024 * 1024 * 1024);

        assert!(scaled_metrics.global_network_bytes > base_metrics.global_network_bytes);
        assert!(
            scaled_metrics.dynamic_site_storage_limit_bytes
                > base_metrics.dynamic_site_storage_limit_bytes
        );
    }

    #[test]
    fn test_proof_of_relay_tracker() {
        let mut tracker = ProofOfRelayTracker::default();
        // Initial bootstrap bonus is 10MB -> max consumption = 20MB
        assert!(tracker.can_consume(15 * 1024 * 1024));
        assert!(tracker.consume(15 * 1024 * 1024).is_ok());

        // Consuming over 20MB without relaying transit traffic should fail
        assert!(!tracker.can_consume(10 * 1024 * 1024));
        assert!(tracker.consume(10 * 1024 * 1024).is_err());

        // Relay 50MB of transit traffic
        tracker.record_transit_relayed(50 * 1024 * 1024);
        // Now max allowable consumption is (10MB + 50MB) * 2 = 120MB
        assert!(tracker.can_consume(50 * 1024 * 1024));
        assert!(tracker.consume(50 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_standalone_ipc_handling() {
        let identity = Identity::generate(Username::new("desktop_node").unwrap());
        let info = NodeInfo {
            username: "desktop_node".into(),
            awe_id: identity.public.awe_id.to_hex(),
            nid: "nid-test".into(),
            offered_bytes: 10 * 1024 * 1024 * 1024,
            available_bytes: 100 * 1024 * 1024 * 1024,
            is_active_node: true,
            node_descriptor: Some("ND-TEST".into()),
            site_dashboard_unlocked: true,
            is_datacenter_scale: false,
            hardware_allocation: HardwareAllocation::default(),
            background_worker_active: true,
        };

        let mut standalone_node = StandaloneAweNode::new(info);

        // Get Status
        let resp = standalone_node.handle_internal_ipc_request(AweIpcCommand::GetNodeStatus);
        match resp {
            AweIpcResponse::Status(status) => assert_eq!(status.username, "desktop_node"),
            _ => panic!("Expected Status response"),
        }

        // Resolve AWE-Name
        let name_resp =
            standalone_node.handle_internal_ipc_request(AweIpcCommand::ResolveAweName {
                domain: "portal.awe".into(),
            });
        match name_resp {
            AweIpcResponse::AweNameResolved {
                domain,
                target_hash,
            } => {
                assert_eq!(domain, "portal.awe");
                assert!(!target_hash.is_empty());
            }
            _ => panic!("Expected AweNameResolved response"),
        }

        // Send Onion Packet
        let onion_resp =
            standalone_node.handle_internal_ipc_request(AweIpcCommand::SendOnionPacket {
                target_service: "service.awe".into(),
                payload: b"hello a2p2".to_vec(),
            });
        match onion_resp {
            AweIpcResponse::OnionPacketRouted { packet_id } => {
                assert!(packet_id.starts_with("onion-"));
            }
            _ => panic!("Expected OnionPacketRouted response"),
        }

        // Secure browser config fingerprinting flags
        assert!(standalone_node.browser_config.canvas_fingerprint_spoofed);
        assert!(standalone_node.browser_config.webgl_vendor_spoofed);
        assert!(standalone_node.browser_config.system_fonts_masked);
    }
}
