use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{OsRng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8] = b"AWE-DRIVE-V1";
const NONCE_LEN: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkRef {
    pub index: u32,
    pub hash: [u8; 32],
    pub size: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoragePolicy {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub max_chunk_size: usize,
    pub replica_count: usize,
}

impl StoragePolicy {
    pub fn hyper_sovereign() -> Self {
        Self {
            data_shards: 450,
            parity_shards: 550,
            max_chunk_size: 4 * 1024 * 1024,
            replica_count: 3,
        }
    }
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            data_shards: 8,
            parity_shards: 4,
            max_chunk_size: 4 * 1024 * 1024,
            replica_count: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateManifest {
    pub file_id: [u8; 32],
    pub original_size: u64,
    pub chunks: Vec<ChunkRef>,
    pub policy: StoragePolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsMap {
    pub file_id: [u8; 32],
    pub site_id: Option<String>,
    pub filename: String,
    pub total_shards: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_nodes: Vec<Vec<String>>,
}

impl AsMap {
    pub fn new(file_id: [u8; 32], filename: String, site_id: Option<String>) -> Self {
        let policy = StoragePolicy::hyper_sovereign();
        let mut shard_nodes = Vec::with_capacity(1000);
        for i in 0..1000 {
            let n1 = format!("ND-{:04X}-1000-0001-{:04X}", i, (i * 7) % 65535);
            let n2 = format!("ND-{:04X}-2000-0002-{:04X}", i, (i * 13) % 65535);
            let n3 = format!("ND-{:04X}-3000-0003-{:04X}", i, (i * 19) % 65535);
            shard_nodes.push(vec![n1, n2, n3]);
        }
        Self {
            file_id,
            site_id,
            filename,
            total_shards: 1000,
            data_shards: policy.data_shards,
            parity_shards: policy.parity_shards,
            shard_nodes,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

pub const DAILY_UPLOAD_LIMIT_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GB

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DailyQuotaTracker {
    pub uploaded_today: u64,
    pub last_reset_timestamp: u64,
}

impl Default for DailyQuotaTracker {
    fn default() -> Self {
        Self {
            uploaded_today: 0,
            last_reset_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

impl DailyQuotaTracker {
    pub fn check_and_add(&mut self, bytes: u64) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(self.last_reset_timestamp) >= 86400 {
            self.uploaded_today = 0;
            self.last_reset_timestamp = now;
        }
        if self.uploaded_today.saturating_add(bytes) > DAILY_UPLOAD_LIMIT_BYTES {
            return Err(format!(
                "AWEDrive 50GB/day limit exceeded. Uploaded today: {} MB, requested: {} MB",
                self.uploaded_today / (1024 * 1024),
                bytes / (1024 * 1024)
            ));
        }
        self.uploaded_today += bytes;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicManifest {
    pub file_id: [u8; 32],
    pub original_size: u64,
    pub chunks: Vec<ChunkRef>,
    pub policy: StoragePolicy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStorageStats {
    pub capacity: u64,
    pub used: u64,
    pub objects: u64,
    pub healthy_replicas: u64,
    pub repaired_chunks: u64,
}

pub fn content_id(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

pub fn choose_chunk_size(file_size: u64, max_chunk_size: usize) -> usize {
    let target = if file_size < 16 * 1024 * 1024 {
        256 * 1024
    } else if file_size < 1024 * 1024 * 1024 {
        1024 * 1024
    } else {
        4 * 1024 * 1024
    };
    target.min(max_chunk_size.max(64 * 1024))
}

pub fn encrypt_file(data: &[u8], key_bytes: &[u8; 32]) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), data)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "encryption failed"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_file(blob: &[u8], key_bytes: &[u8; 32]) -> io::Result<Vec<u8>> {
    if blob.len() < MAGIC.len() + NONCE_LEN || &blob[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid AWE Drive object",
        ));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    cipher
        .decrypt(
            Nonce::from_slice(&blob[MAGIC.len()..MAGIC.len() + NONCE_LEN]),
            &blob[MAGIC.len() + NONCE_LEN..],
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"))
}

pub fn encode_shards(data: &[u8], policy: &StoragePolicy) -> io::Result<Vec<Vec<u8>>> {
    if policy.data_shards == 0 || policy.parity_shards == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid erasure policy",
        ));
    }
    let shard_len = data.len().div_ceil(policy.data_shards);
    let mut shards = vec![vec![0u8; shard_len]; policy.data_shards + policy.parity_shards];
    for (i, byte) in data.iter().enumerate() {
        shards[i / shard_len][i % shard_len] = *byte;
    }
    ReedSolomon::new(policy.data_shards, policy.parity_shards)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Reed-Solomon policy"))?
        .encode(&mut shards)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "erasure encoding failed"))?;
    Ok(shards)
}

pub fn recover_shards(
    shards: &mut [Option<Vec<u8>>],
    policy: &StoragePolicy,
) -> io::Result<Vec<u8>> {
    let rs = ReedSolomon::new(policy.data_shards, policy.parity_shards)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Reed-Solomon policy"))?;
    rs.reconstruct(shards)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "insufficient shards"))?;
    let mut out = Vec::new();
    for shard in shards.iter().take(policy.data_shards) {
        out.extend_from_slice(
            shard
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing data shard"))?,
        );
    }
    Ok(out)
}

pub struct LocalNodeStore {
    root: PathBuf,
    quota: u64,
}
impl LocalNodeStore {
    pub fn open(root: impl AsRef<Path>, quota: u64) -> io::Result<Self> {
        fs::create_dir_all(root.as_ref().join("objects"))?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            quota,
        })
    }
    fn path(&self, id: &[u8; 32]) -> PathBuf {
        self.root.join("objects").join(hex::encode(id))
    }
    pub fn put(&self, data: &[u8]) -> io::Result<[u8; 32]> {
        let id = content_id(data);
        let p = self.path(&id);
        if p.exists() {
            return Ok(id);
        }
        let used = self.stats()?.used;
        if used.saturating_add(data.len() as u64) > self.quota {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "AWE node storage quota exceeded",
            ));
        }
        let tmp = p.with_extension("part");
        fs::write(&tmp, data)?;
        fs::rename(tmp, p)?;
        Ok(id)
    }
    pub fn get(&self, id: &[u8; 32]) -> io::Result<Vec<u8>> {
        let data = fs::read(self.path(id))?;
        if content_id(&data) != *id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object integrity failure",
            ));
        }
        Ok(data)
    }
    pub fn remove(&self, id: &[u8; 32]) -> io::Result<()> {
        let _ = fs::remove_file(self.path(id));
        Ok(())
    }
    pub fn stats(&self) -> io::Result<NodeStorageStats> {
        let mut s = NodeStorageStats {
            capacity: self.quota,
            ..Default::default()
        };
        for e in fs::read_dir(self.root.join("objects"))? {
            let e = e?;
            let m = e.metadata()?;
            if m.is_file() {
                s.used += m.len();
                s.objects += 1;
            }
        }
        Ok(s)
    }
    pub fn gc(&self, live: &BTreeMap<[u8; 32], ()>) -> io::Result<u64> {
        let mut removed = 0;
        for e in fs::read_dir(self.root.join("objects"))? {
            let e = e?;
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(bytes) = hex::decode(name) {
                if bytes.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);
                    if !live.contains_key(&id) {
                        fs::remove_file(e.path())?;
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }
}

pub fn save_manifest(path: impl AsRef<Path>, manifest: &[u8]) -> io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(manifest)?;
    f.flush()
}
pub fn load_manifest(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretFilePackage {
    pub sfid: String,
    pub filename: String,
    pub salt: [u8; 16],
    pub encrypted_payload: Vec<u8>,
}

impl SecretFilePackage {
    pub fn create(filename: &str, plain_data: &[u8], password: &str) -> io::Result<Self> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = crate::crypto::hash(password.as_bytes(), &salt);
        let encrypted_payload = encrypt_file(plain_data, &key)?;
        let sfid = format!(
            "sfid-{}",
            &hex::encode(&crate::crypto::hash(b"AWE-SFID", &salt))[..16]
        );

        Ok(Self {
            sfid,
            filename: filename.to_string(),
            salt,
            encrypted_payload,
        })
    }

    pub fn unlock_and_decrypt(&self, password: &str) -> io::Result<Vec<u8>> {
        let key = crate::crypto::hash(password.as_bytes(), &self.salt);
        decrypt_file(&self.encrypted_payload, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encryption_roundtrip() {
        let key = [7u8; 32];
        let plain = b"AWE Drive secret";
        let enc = encrypt_file(plain, &key).unwrap();
        assert_ne!(enc, plain);
        assert_eq!(decrypt_file(&enc, &key).unwrap(), plain);
    }
    #[test]
    fn erasure_recovery() {
        let p = StoragePolicy::default();
        let data = vec![41u8; 100_000];
        let encoded = encode_shards(&data, &p).unwrap();
        let mut shards = encoded.into_iter().map(Some).collect::<Vec<_>>();
        shards[0] = None;
        shards[3] = None;
        shards[9] = None;
        let recovered = recover_shards(&mut shards, &p).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn hyper_sovereign_policy_spec() {
        let p = StoragePolicy::hyper_sovereign();
        assert_eq!(p.data_shards, 450);
        assert_eq!(p.parity_shards, 550);
        assert_eq!(p.data_shards + p.parity_shards, 1000);
        assert_eq!(p.replica_count, 3);
    }
    #[test]
    fn asmap_roundtrip() {
        let map = AsMap::new(
            [11u8; 32],
            "test.txt".to_string(),
            Some("site123".to_string()),
        );
        assert_eq!(map.total_shards, 1000);
        assert_eq!(map.shard_nodes.len(), 1000);
        assert_eq!(map.shard_nodes[0].len(), 3);
        let bytes = map.to_bytes().unwrap();
        let loaded = AsMap::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.filename, "test.txt");
    }
    #[test]
    fn daily_quota_tracker_limits() {
        let mut tracker = DailyQuotaTracker::default();
        let ok_upload = 10 * 1024 * 1024 * 1024; // 10 GB
        assert!(tracker.check_and_add(ok_upload).is_ok());
        assert_eq!(tracker.uploaded_today, ok_upload);

        let excessive_upload = 45 * 1024 * 1024 * 1024; // 45 GB (total 55 GB > 50 GB)
        assert!(tracker.check_and_add(excessive_upload).is_err());
    }
    #[test]
    fn content_addressed_store() {
        let dir = std::env::temp_dir().join(format!("awe-drive-{}", std::process::id()));
        let s = LocalNodeStore::open(&dir, 1_000_000).unwrap();
        let id = s.put(b"hello").unwrap();
        assert_eq!(s.get(&id).unwrap(), b"hello");
        s.remove(&id).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn secret_file_package_password_unlock() {
        let plain = b"Sovereign AWE Drive Secret File Data";
        let pwd = "SuperSecretPassword123";

        let sf_package = SecretFilePackage::create("secret_doc.pdf", plain, pwd).unwrap();
        assert!(sf_package.sfid.starts_with("sfid-"));

        // Correct password unlocks
        let decrypted = sf_package.unlock_and_decrypt(pwd).unwrap();
        assert_eq!(decrypted, plain);

        // Wrong password fails
        assert!(sf_package.unlock_and_decrypt("WrongPassword").is_err());
    }
}
