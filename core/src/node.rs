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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}
