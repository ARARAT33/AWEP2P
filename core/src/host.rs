use crate::{namespace, registry::{Registry, RegistryStatus}, storage::{content_id, LocalNodeStore}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io, path::{Path, PathBuf}};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostPolicy { pub max_site_bytes: u64, pub max_file_bytes: u64, pub bandwidth_bytes_per_second: u64, pub cache_entries: usize, pub replica_count: usize }
impl Default for HostPolicy { fn default() -> Self { Self { max_site_bytes: 1 << 30, max_file_bytes: 64 << 20, bandwidth_bytes_per_second: 10 << 20, cache_entries: 4096, replica_count: 3 } } }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedFile { pub path: String, pub object_id: [u8;32], pub size: u64, pub content_type: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteManifest { pub domain: String, pub version: u64, pub root_hash: [u8;32], pub files: Vec<HostedFile>, pub owner_key: Vec<u8>, pub policy: HostPolicy }
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostHealth { pub available: bool, pub consecutive_failures: u32, pub last_check_unix: u64, pub latency_ms: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRecord { pub node_id: [u8;32], pub domain: String, pub version: u64, pub manifest_hash: [u8;32], pub health: HostHealth }

pub struct AweHost { root: PathBuf, store: LocalNodeStore, policy: HostPolicy, cache: BTreeMap<String, Vec<u8>> }
impl AweHost {
    pub fn open(root: impl AsRef<Path>, quota: u64, policy: HostPolicy) -> io::Result<Self> { fs::create_dir_all(root.as_ref())?; Ok(Self { root: root.as_ref().to_path_buf(), store: LocalNodeStore::open(root.as_ref().join("objects"), quota)?, policy, cache: BTreeMap::new() }) }
    pub fn publish_file(&mut self, path: &str, data: &[u8], content_type: &str) -> io::Result<HostedFile> { let clean=normalize_path(path)?; if data.len() as u64 > self.policy.max_file_bytes { return Err(io::Error::new(io::ErrorKind::InvalidInput,"file exceeds host policy")); } let id=self.store.put(data)?; Ok(HostedFile { path:clean, object_id:id, size:data.len() as u64, content_type:content_type.to_string() }) }
    pub fn publish_manifest(&self, domain: &str, version: u64, owner_key: Vec<u8>, files: Vec<HostedFile>) -> io::Result<SiteManifest> { if domain.is_empty() || version==0 { return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid site manifest")); } let total:u64=files.iter().map(|f|f.size).sum(); if total>self.policy.max_site_bytes { return Err(io::Error::new(io::ErrorKind::InvalidInput,"site exceeds host policy")); } let mut h=Sha256::new(); h.update(domain.as_bytes()); h.update(version.to_be_bytes()); for f in &files { h.update(f.path.as_bytes()); h.update(f.object_id); h.update(f.size.to_be_bytes()); } Ok(SiteManifest { domain:domain.to_string(), version, root_hash:h.finalize().into(), files, owner_key, policy:self.policy.clone() }) }
    pub fn authorize_domain(manifest:&SiteManifest, registry:&Registry)->bool { namespace::resolve(registry,&manifest.domain).map(|r|r.status==RegistryStatus::Active && r.owner_public_key==manifest.owner_key).unwrap_or(false) }
    pub fn get(&mut self, manifest:&SiteManifest, path:&str)->io::Result<Vec<u8>> { let clean=normalize_path(path)?; if let Some(v)=self.cache.get(&clean){return Ok(v.clone())} let f=manifest.files.iter().find(|f|f.path==clean).ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"AWE host path not found"))?; let data=self.store.get(&f.object_id)?; if data.len() as u64!=f.size || content_id(&data)!=f.object_id{return Err(io::Error::new(io::ErrorKind::InvalidData,"host object integrity failure"))} if self.cache.len()>=self.policy.cache_entries {if let Some(k)=self.cache.keys().next().cloned(){self.cache.remove(&k);}} self.cache.insert(clean,data.clone()); Ok(data) }
    pub fn save_manifest(&self, manifest:&SiteManifest)->io::Result<()> { let p=self.manifest_path(&manifest.domain); fs::write(p,serde_json::to_vec_pretty(manifest).map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"manifest serialization failed"))?) }
    pub fn load_manifest(&self, domain:&str)->io::Result<SiteManifest> { let b=fs::read(self.manifest_path(domain))?; serde_json::from_slice(&b).map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"invalid host manifest")) }
    pub fn manifest_path(&self, domain:&str)->PathBuf { self.root.join(format!("{}.manifest.json",domain.replace('/','_'))) }
}
pub fn normalize_path(path:&str)->io::Result<String>{ if path.is_empty()||!path.starts_with('/')||path.contains('\\')||path.split('/').any(|x|x==".."){return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid web path"));} Ok(if path=="/"{"/index.html".into()}else{path.into()}) }

#[cfg(test)]
mod tests { use super::*; #[test] fn safe_paths(){assert!(normalize_path("/index.html").is_ok());assert!(normalize_path("/../secret").is_err())} #[test] fn host_roundtrip(){let r=std::env::temp_dir().join(format!("awe-host-{}",std::process::id()));let mut h=AweHost::open(&r,10_000_000,HostPolicy::default()).unwrap();let f=h.publish_file("/index.html",b"<h1>AWE</h1>","text/html").unwrap();let m=h.publish_manifest("example.awe",1,vec![1],vec![f]).unwrap();h.save_manifest(&m).unwrap();assert_eq!(h.get(&m,"/").unwrap(),b"<h1>AWE</h1>");let _=fs::remove_dir_all(r);}}
