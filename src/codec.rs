use crate::effective_digest_bytes_for_security_bits;

pub const MAX_DIGEST_BYTES: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofCodecConfig {
    pub proof_blob_version: u16,
    pub compact_query_encoding: bool,
    pub digest_bytes_override: Option<u8>,
}

impl Default for ProofCodecConfig {
    fn default() -> Self {
        Self {
            proof_blob_version: 0,
            compact_query_encoding: true,
            digest_bytes_override: None,
        }
    }
}

pub fn effective_digest_bytes(merkle_security_bits: u32, digest_bytes_override: Option<u8>) -> u8 {
    match digest_bytes_override {
        Some(override_bytes) => override_bytes.clamp(1, MAX_DIGEST_BYTES),
        None => effective_digest_bytes_for_security_bits(merkle_security_bits as usize) as u8,
    }
}
