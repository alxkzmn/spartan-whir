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
        None => {
            // Conservative birthday-bound mapping:
            // collision security ~= digest_bits / 2, so digest_bits ~= 2 * security_bits.
            // TODO: align exactly with p3_whir::effective_digest_bytes_for_security_bits in Phase 2.
            let derived = ((merkle_security_bits.saturating_mul(2).saturating_add(7)) / 8)
                .clamp(1, MAX_DIGEST_BYTES as u32);
            derived as u8
        }
    }
}
