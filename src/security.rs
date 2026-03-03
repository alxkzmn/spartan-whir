use crate::SpartanWhirError;

pub const MIN_SECURITY_BITS: u32 = 80;
pub const DEFAULT_SECURITY_BITS: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoundnessAssumption {
    UniqueDecoding,
    JohnsonBound,
    CapacityBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityConfig {
    pub security_level_bits: u32,
    pub merkle_security_bits: u32,
    pub soundness_assumption: SoundnessAssumption,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            security_level_bits: DEFAULT_SECURITY_BITS,
            merkle_security_bits: DEFAULT_SECURITY_BITS,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        }
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<(), SpartanWhirError> {
        if self.security_level_bits < MIN_SECURITY_BITS {
            return Err(SpartanWhirError::SecurityBelowMinimum);
        }
        if self.merkle_security_bits < MIN_SECURITY_BITS {
            return Err(SpartanWhirError::MerkleSecurityBelowMinimum);
        }
        Ok(())
    }

    pub fn effective_security_bits(&self) -> u32 {
        core::cmp::min(self.security_level_bits, self.merkle_security_bits)
    }

    pub fn merkle_override_weaker_than_security(&self) -> bool {
        self.merkle_security_bits < self.security_level_bits
    }
}
