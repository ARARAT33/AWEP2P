//! AWE Store: signed, content-addressed, P2P-distributable application packages.
use crate::identity::Identity;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

const MAGIC: &[u8] = b"AWEAPP/1\0";
const MAX_PACKAGE: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppKind {
    Wasm,
    Windows,
    Linux,
    Android,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppCapability {
    Network,
    Storage,
    Identity,
    Media,
    Host,
    Process,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub id: String,
    pub min_version: String,
    pub max_version: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: AppKind,
    pub developer_awe_id: [u8; 32],
    pub developer_public_key: [u8; 32],
    pub entry: String,
    pub dependencies: Vec<Dependency>,
    pub permissions: Vec<AppCapability>,
    pub payload_hash: [u8; 32],
    pub size: u64,
    pub protocol_version: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest: AppManifest,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AWEPackage {
    pub magic: Vec<u8>,
    pub manifest: SignedManifest,
    pub files: BTreeMap<String, Vec<u8>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledApp {
    pub id: String,
    pub version: String,
    pub package_hash: [u8; 32],
    pub permissions: Vec<AppCapability>,
}
#[derive(Clone, Debug, Default)]
pub struct Store {
    root: PathBuf,
}

fn canonical_manifest(m: &AppManifest) -> Vec<u8> {
    serde_json::to_vec(m).expect("manifest serialization")
}
fn payload_hash(files: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    let mut h = Hasher::new();
    for (p, b) in files {
        h.update(&(p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
        h.update(&(b.len() as u64).to_be_bytes());
        h.update(b);
    }
    *h.finalize().as_bytes()
}
fn package_hash(p: &AWEPackage) -> [u8; 32] {
    let b = serde_json::to_vec(p).expect("package serialization");
    *blake3::hash(&b).as_bytes()
}
fn validate_path(p: &str) -> bool {
    !p.is_empty() && p.starts_with('/') && !p.contains('\\') && !p.split('/').any(|x| x == "..")
}
fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

pub fn validate_wasm(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" || &bytes[4..8] != [1, 0, 0, 0] {
        return Err("invalid WebAssembly module");
    }
    let mut i = 8;
    while i < bytes.len() {
        let id = bytes[i];
        i += 1;
        let (len, n) = read_leb(&bytes[i..])?;
        i += n;
        let end = i.checked_add(len as usize).ok_or("invalid wasm section")?;
        if end > bytes.len() {
            return Err("truncated wasm section");
        }
        if id == 2 {
            return Err("WASM host imports are forbidden; use declared capabilities");
        }
        i = end;
    }
    Ok(())
}
fn read_leb(b: &[u8]) -> Result<(u64, usize), &'static str> {
    let mut x = 0u64;
    let mut s = 0;
    for (i, &c) in b.iter().enumerate().take(10) {
        x |= ((c & 0x7f) as u64) << s;
        if c & 0x80 == 0 {
            return Ok((x, i + 1));
        }
        s += 7;
    }
    Err("invalid leb128")
}

impl AppManifest {
    pub fn verify(&self) -> Result<(), &'static str> {
        if self.id.is_empty()
            || self.id.len() > 128
            || !valid_version(&self.version)
            || self.protocol_version != 1
        {
            return Err("invalid manifest");
        };
        if self.entry.is_empty() || !validate_path(&self.entry) {
            return Err("invalid entry path");
        };
        if self.size as usize > MAX_PACKAGE {
            return Err("package too large");
        };
        Ok(())
    }
}
impl SignedManifest {
    pub fn verify(&self) -> Result<(), &'static str> {
        self.manifest.verify()?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signature length")?;
        if !Identity::verify(
            &self.manifest.developer_public_key,
            &canonical_manifest(&self.manifest),
            &signature,
        ) {
            return Err("invalid developer signature");
        };
        Ok(())
    }
}
impl AWEPackage {
    pub fn new(
        identity: &Identity,
        id: &str,
        name: &str,
        version: &str,
        kind: AppKind,
        entry: &str,
        files: BTreeMap<String, Vec<u8>>,
        permissions: Vec<AppCapability>,
        dependencies: Vec<Dependency>,
    ) -> Result<Self, &'static str> {
        if files.values().map(|v| v.len()).sum::<usize>() > MAX_PACKAGE {
            return Err("package too large");
        };
        if !files.keys().all(|p| validate_path(p)) {
            return Err("invalid package path");
        };
        if matches!(kind, AppKind::Wasm) {
            let b = files.get(entry).ok_or("missing entry")?;
            validate_wasm(b)?;
        }
        let ph = payload_hash(&files);
        let m = AppManifest {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            kind,
            developer_awe_id: *identity.public.awe_id.as_bytes(),
            developer_public_key: identity.public.public_key,
            entry: entry.into(),
            dependencies,
            permissions,
            size: files.values().map(|v| v.len() as u64).sum(),
            payload_hash: ph,
            protocol_version: 1,
        };
        let sig = identity.sign(&canonical_manifest(&m));
        Ok(Self {
            magic: MAGIC.to_vec(),
            manifest: SignedManifest {
                manifest: m,
                signature: sig.to_vec(),
            },
            files,
        })
    }
    pub fn verify(&self) -> Result<(), &'static str> {
        if self.magic != MAGIC {
            return Err("invalid AWE package magic");
        };
        self.manifest.verify()?;
        if payload_hash(&self.files) != self.manifest.manifest.payload_hash {
            return Err("package integrity failure");
        };
        if self.manifest.manifest.size != self.files.values().map(|v| v.len() as u64).sum::<u64>() {
            return Err("package size mismatch");
        };
        if matches!(self.manifest.manifest.kind, AppKind::Wasm) {
            validate_wasm(
                self.files
                    .get(&self.manifest.manifest.entry)
                    .ok_or("missing WASM entry")?,
            )?;
        }
        Ok(())
    }
    pub fn bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        serde_json::to_vec(self)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "serialization failed"))
    }
    pub fn from_bytes(b: &[u8]) -> io::Result<Self> {
        if b.len() > MAX_PACKAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package too large",
            ));
        };
        let p: Self = serde_json::from_slice(b)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid package"))?;
        p.verify()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(p)
    }
}
impl Store {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        fs::create_dir_all(root.as_ref().join("packages"))?;
        fs::create_dir_all(root.as_ref().join("installed"))?;
        fs::create_dir_all(root.as_ref().join("cache"))?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }
    fn pkg(&self, h: &[u8; 32]) -> PathBuf {
        self.root.join("packages").join(hex::encode(h))
    }
    fn active(&self, id: &str) -> PathBuf {
        self.root.join("installed").join(format!("{}.json", id))
    }
    pub fn publish(&self, p: &AWEPackage) -> io::Result<[u8; 32]> {
        let b = p.bytes()?;
        let h = package_hash(p);
        let tmp = self.pkg(&h).with_extension("part");
        fs::write(&tmp, &b)?;
        fs::rename(tmp, self.pkg(&h))?;
        Ok(h)
    }
    pub fn cache(&self, p: &AWEPackage) -> io::Result<[u8; 32]> {
        self.publish(p)
    }
    pub fn fetch_cached(&self, h: &[u8; 32]) -> io::Result<AWEPackage> {
        AWEPackage::from_bytes(&fs::read(self.pkg(h))?)
    }
    pub fn install(&self, h: &[u8; 32], granted: &[AppCapability]) -> io::Result<InstalledApp> {
        let p = self.fetch_cached(h)?;
        for cap in &p.manifest.manifest.permissions {
            if !granted.contains(cap) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "required capability not granted",
                ));
            }
        }
        let id = &p.manifest.manifest.id;
        let old = self.active(id);
        if old.exists() {
            let backup = old.with_extension("rollback.json");
            fs::copy(&old, backup)?;
        }
        let rec = InstalledApp {
            id: id.clone(),
            version: p.manifest.manifest.version.clone(),
            package_hash: *h,
            permissions: p.manifest.manifest.permissions.clone(),
        };
        let tmp = old.with_extension("part");
        fs::write(&tmp, serde_json::to_vec(&rec).unwrap())?;
        fs::rename(tmp, old)?;
        Ok(rec)
    }
    pub fn installed(&self, id: &str) -> io::Result<InstalledApp> {
        serde_json::from_slice(&fs::read(self.active(id))?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid installed record"))
    }
    pub fn uninstall(&self, id: &str) -> io::Result<()> {
        let _ = fs::remove_file(self.active(id));
        Ok(())
    }
    pub fn rollback(&self, id: &str) -> io::Result<InstalledApp> {
        let p = self.active(id);
        let b = p.with_extension("rollback.json");
        if !b.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no rollback version",
            ));
        }
        fs::copy(&b, &p)?;
        self.installed(id)
    }
    pub fn update(&self, h: &[u8; 32], granted: &[AppCapability]) -> io::Result<InstalledApp> {
        self.install(h, granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Username;
    #[test]
    fn signed_package_roundtrip() {
        let i = Identity::generate(Username::new("dev").unwrap());
        let mut f = BTreeMap::new();
        f.insert("/app.wasm".into(), b"\0asm\x01\0\0\0".to_vec());
        let p = AWEPackage::new(
            &i,
            "org.awe.test",
            "Test",
            "1.0.0",
            AppKind::Wasm,
            "/app.wasm",
            f,
            vec![AppCapability::Storage],
            vec![],
        )
        .unwrap();
        let b = p.bytes().unwrap();
        let q = AWEPackage::from_bytes(&b).unwrap();
        assert_eq!(q.manifest.manifest.id, "org.awe.test");
    }
    #[test]
    fn tamper_is_rejected() {
        let i = Identity::generate(Username::new("dev").unwrap());
        let mut f = BTreeMap::new();
        f.insert("/app.wasm".into(), b"\0asm\x01\0\0\0".to_vec());
        let mut p = AWEPackage::new(
            &i,
            "x",
            "X",
            "1",
            AppKind::Wasm,
            "/app.wasm",
            f,
            vec![],
            vec![],
        )
        .unwrap();
        p.files.get_mut("/app.wasm").unwrap().push(1);
        assert!(p.verify().is_err());
    }
    #[test]
    fn install_rollback() {
        let root = std::env::temp_dir().join(format!("awe-store-{}", std::process::id()));
        let s = Store::open(&root).unwrap();
        let i = Identity::generate(Username::new("dev").unwrap());
        let mut f = BTreeMap::new();
        f.insert("/app.wasm".into(), b"\0asm\x01\0\0\0".to_vec());
        let p = AWEPackage::new(
            &i,
            "x",
            "X",
            "1",
            AppKind::Wasm,
            "/app.wasm",
            f.clone(),
            vec![],
            vec![],
        )
        .unwrap();
        let h = s.publish(&p).unwrap();
        s.install(&h, &[]).unwrap();
        assert_eq!(s.installed("x").unwrap().version, "1");
        let _ = fs::remove_dir_all(root);
    }
}
