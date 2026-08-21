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
    fn content_addressed_store() {
        let dir = std::env::temp_dir().join(format!("awe-drive-{}", std::process::id()));
        let s = LocalNodeStore::open(&dir, 1_000_000).unwrap();
        let id = s.put(b"hello").unwrap();
        assert_eq!(s.get(&id).unwrap(), b"hello");
        s.remove(&id).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
