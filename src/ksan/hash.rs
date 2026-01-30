use num_bigint::{Sign, BigInt};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine};

pub fn hash(m: &String) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(m.as_bytes());
    let hash_bytes = hasher.finalize();
    return BigInt::from_bytes_be(Sign::Plus, &hash_bytes);
}

pub fn encode(b: &[u8]) -> String {
    return general_purpose::STANDARD.encode(b);
}