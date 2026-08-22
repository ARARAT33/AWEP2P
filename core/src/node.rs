use crate::identity::Identity;
use crate::network::format_node_descriptor;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub username: String,
    pub awe_id: String,
    pub offered_bytes: u64,
    pub available_bytes: u64,
    pub is_active_node: bool,
    pub node_descriptor: Option<String>,
    pub site_dashboard_unlocked: bool,
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
) -> Result<NodeInfo, String> {
    if offered_bytes == 0 {
        return Err("Offered storage size must be greater than 0 bytes to become a Node.".into());
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

    Ok(NodeInfo {
        username: identity.public.username.as_str().to_string(),
        awe_id: identity.public.awe_id.to_hex(),
        offered_bytes,
        available_bytes: real_available,
        is_active_node: true,
        node_descriptor: Some(node_desc),
        site_dashboard_unlocked: true,
    })
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
        let info = configure_node_storage(&identity, &temp_dir, valid_offer).unwrap();
        assert!(info.is_active_node);
        assert!(info.node_descriptor.is_some());
        assert!(info.site_dashboard_unlocked);

        // Excessive offer
        let excessive_offer = space.saturating_add(1000 * 1024 * 1024 * 1024);
        let err = configure_node_storage(&identity, &temp_dir, excessive_offer);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("exceeds actual available disk space"));

        let _ = fs::remove_dir_all(temp_dir);
    }
}
