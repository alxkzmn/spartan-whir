use alloc::vec::Vec;

use crate::engine::F;
use crate::{
    effective_digest_bytes_for_security_bits, KeccakEngine, R1csInstance, SpartanProof,
    SpartanWhirError, VerifyingKey, WhirPcs, WhirPcsConfig,
};
use crate::{profiling::ProofSizeReport, whir_pcs::derive_whir_proof_expectations};

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
            proof_blob_version: 1,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpartanBlobDecodeContext {
    pub expected_num_io: usize,
    pub expected_outer_rounds: usize,
    pub expected_inner_rounds: usize,
    pub merkle_security_bits: u32,
    pub(crate) whir: crate::whir_pcs::WhirProofExpectations,
}

impl SpartanBlobDecodeContext {
    pub fn from_vk(vk: &VerifyingKey<KeccakEngine, WhirPcs>) -> Result<Self, SpartanWhirError> {
        let expected_num_io = vk.num_io;
        let expected_outer_rounds = vk.shape_canonical.num_cons.ilog2() as usize;
        let expected_inner_rounds = vk.shape_canonical.num_vars.ilog2() as usize + 1;
        let merkle_security_bits = vk.pcs_config.security.merkle_security_bits;
        let whir = derive_whir_proof_expectations(&vk.pcs_config)?;

        Ok(Self {
            expected_num_io,
            expected_outer_rounds,
            expected_inner_rounds,
            merkle_security_bits,
            whir,
        })
    }
}

pub fn encode_spartan_blob_v1(
    codec: &ProofCodecConfig,
    pcs_config: &WhirPcsConfig,
    instance: &R1csInstance<F, [u64; 4]>,
    proof: &SpartanProof<KeccakEngine, WhirPcs>,
) -> Result<Vec<u8>, SpartanWhirError> {
    let out = crate::codec_v1::encode_spartan_blob_v1(codec, pcs_config, instance, proof)?;
    Ok(out.blob)
}

pub fn encode_spartan_blob_v1_with_report(
    codec: &ProofCodecConfig,
    pcs_config: &WhirPcsConfig,
    instance: &R1csInstance<F, [u64; 4]>,
    proof: &SpartanProof<KeccakEngine, WhirPcs>,
) -> Result<(Vec<u8>, ProofSizeReport), SpartanWhirError> {
    let out = crate::codec_v1::encode_spartan_blob_v1(codec, pcs_config, instance, proof)?;
    Ok((out.blob, out.report))
}

pub fn decode_spartan_blob_v1(
    codec: &ProofCodecConfig,
    ctx: &SpartanBlobDecodeContext,
    blob: &[u8],
) -> Result<
    (
        R1csInstance<F, [u64; 4]>,
        SpartanProof<KeccakEngine, WhirPcs>,
    ),
    SpartanWhirError,
> {
    crate::codec_v1::decode_spartan_blob_v1(codec, ctx, blob)
}

pub fn encode_spartan_blob(
    codec: &ProofCodecConfig,
    pcs_config: &WhirPcsConfig,
    instance: &R1csInstance<F, [u64; 4]>,
    proof: &SpartanProof<KeccakEngine, WhirPcs>,
) -> Result<Vec<u8>, SpartanWhirError> {
    match codec.proof_blob_version {
        1 => encode_spartan_blob_v1(codec, pcs_config, instance, proof),
        _ => Err(SpartanWhirError::UnsupportedBlobVersion),
    }
}

pub fn decode_spartan_blob(
    codec: &ProofCodecConfig,
    ctx: &SpartanBlobDecodeContext,
    blob: &[u8],
) -> Result<
    (
        R1csInstance<F, [u64; 4]>,
        SpartanProof<KeccakEngine, WhirPcs>,
    ),
    SpartanWhirError,
> {
    if blob.len() < 6 {
        return Err(SpartanWhirError::InvalidBlobHeader);
    }
    let version = u16::from_be_bytes([blob[4], blob[5]]);
    match version {
        1 => decode_spartan_blob_v1(codec, ctx, blob),
        _ => Err(SpartanWhirError::UnsupportedBlobVersion),
    }
}
