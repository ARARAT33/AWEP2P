use sha2::{Digest, Sha256};

/// Domain-separated SHA-256 digest used by protocol primitives.
pub fn hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((data.len() as u64).to_be_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for (x, y) in a.iter().zip(b) {
        v |= x ^ y;
    }
    v == 0
}
