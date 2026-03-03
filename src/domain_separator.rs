use alloc::vec::Vec;

use crate::{R1csShape, SecurityConfig, SoundnessAssumption, WhirParams};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSeparator {
    pub protocol_id: &'static [u8],
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub security_level_bits: u32,
    pub merkle_security_bits: u32,
    pub soundness_assumption: SoundnessAssumption,
    pub whir_params: WhirParams,
}

impl DomainSeparator {
    pub fn new<F>(
        shape: &R1csShape<F>,
        security: &SecurityConfig,
        whir_params: &WhirParams,
    ) -> Self {
        Self {
            protocol_id: b"spartan-whir-v0",
            num_cons: shape.num_cons,
            num_vars: shape.num_vars,
            num_io: shape.num_io,
            security_level_bits: security.security_level_bits,
            merkle_security_bits: security.merkle_security_bits,
            soundness_assumption: security.soundness_assumption,
            whir_params: *whir_params,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.protocol_id);
        out.extend_from_slice(&(self.num_cons as u64).to_le_bytes());
        out.extend_from_slice(&(self.num_vars as u64).to_le_bytes());
        out.extend_from_slice(&(self.num_io as u64).to_le_bytes());
        out.extend_from_slice(&self.security_level_bits.to_le_bytes());
        out.extend_from_slice(&self.merkle_security_bits.to_le_bytes());
        out.push(soundness_to_byte(self.soundness_assumption));
        out.extend_from_slice(&self.whir_params.pow_bits.to_le_bytes());
        out.extend_from_slice(&(self.whir_params.folding_factor as u64).to_le_bytes());
        out.extend_from_slice(&(self.whir_params.starting_log_inv_rate as u64).to_le_bytes());
        out.extend_from_slice(
            &(self.whir_params.rs_domain_initial_reduction_factor as u64).to_le_bytes(),
        );
        out
    }
}

fn soundness_to_byte(soundness: SoundnessAssumption) -> u8 {
    match soundness {
        SoundnessAssumption::UniqueDecoding => 0,
        SoundnessAssumption::JohnsonBound => 1,
        SoundnessAssumption::CapacityBound => 2,
    }
}
