use crate::{
    namespace,
    registry::{Registry, RegistryStatus},
    storage::{content_id, LocalNodeStore},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostPolicy {
    pub max_site_bytes: u64,
    pub max_file_bytes: u64,
    pub bandwidth_bytes_per_second: u64,
    pub cache_entries: usize,
    pub replica_count: usize,
}
impl Default for HostPolicy {
    fn default() -> Self {
        Self {
            max_site_bytes: 1 << 30,
            max_file_bytes: 64 << 20,
            bandwidth_bytes_per_second: 10 << 20,
            cache_entries: 4096,
            replica_count: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedFile {
    pub path: String,
    pub object_id: [u8; 32],
    pub size: u64,
    pub content_type: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteManifest {
    pub domain: String,
    pub version: u64,
    pub root_hash: [u8; 32],
    pub files: Vec<HostedFile>,
    pub owner_key: Vec<u8>,
    pub policy: HostPolicy,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostHealth {
    pub available: bool,
    pub consecutive_failures: u32,
    pub last_check_unix: u64,
    pub latency_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRecord {
    pub node_id: [u8; 32],
    pub domain: String,
    pub version: u64,
    pub manifest_hash: [u8; 32],
    pub health: HostHealth,
}

pub struct AweHost {
    root: PathBuf,
    store: LocalNodeStore,
    policy: HostPolicy,
    cache: BTreeMap<String, Vec<u8>>,
}
impl AweHost {
    pub fn open(root: impl AsRef<Path>, quota: u64, policy: HostPolicy) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let store = LocalNodeStore::open(root.join("objects"), quota)?;
        Ok(Self {
            root,
            store,
            policy,
            cache: BTreeMap::new(),
        })
    }
    pub fn publish_file(
        &mut self,
        domain: &str,
        path: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> io::Result<HostedFile> {
        let domain = namespace::normalize_domain(domain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let path = normalize_path(path)?;
        if bytes.len() as u64 > self.policy.max_file_bytes {
            return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "file exceeds host policy"));
        }
        let object_id = content_id(bytes);
        self.store.put(object_id, bytes)?;
        let file = HostedFile {
            path,
            object_id,
            size: bytes.len() as u64,
            content_type: content_type.to_owned(),
        };
        self.cache.insert(cache_key(&domain, &file.path), bytes.to_vec());
        while self.cache.len() > self.policy.cache_entries {
            if let Some(k) = self.cache.keys().next().cloned() {
                self.cache.remove(&k);
            }
        }
        Ok(file)
    }
    pub fn publish_manifest(&self, manifest: &SiteManifest) -> io::Result<()> {
        if manifest.domain.is_empty() || manifest.files.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid site manifest"));
        }
        let total = manifest.files.iter().map(|f| f.size).sum::<u64>();
        if total > self.policy.max_site_bytes {
            return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "site exceeds host policy"));
        }
        let data = serde_json::to_vec(manifest)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "manifest serialization failed"))?;
        fs::write(self.manifest_path(&manifest.domain), data)
    }
    pub fn load_manifest(&self, domain: &str) -> io::Result<SiteManifest> {
        let b = fs::read(self.manifest_path(domain))?;
        serde_json::from_slice(&b)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid host manifest"))
    }
    pub fn manifest_path(&self, domain: &str) -> PathBuf {
        self.root
            .join(format!("{}.manifest.json", domain.replace('/', "_")))
    }
}
pub fn normalize_path(path: &str) -> io::Result<String> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|x| x == "..")
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host path"));
    }
    Ok(path.to_owned())
}
fn cache_key(domain: &str, path: &str) -> String {
    format!("{domain}{path}")
}
