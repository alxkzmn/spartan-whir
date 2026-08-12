use spartan_whir::{
    SecurityConfig, SoundnessAssumption, SpartanWhirError, MAX_SECURITY_BITS, MIN_SECURITY_BITS,
};

#[test]
fn defaults_match_phase_one_contract() {
    let cfg = SecurityConfig::default();
    assert_eq!(cfg.security_level_bits, 100);
    assert_eq!(cfg.merkle_security_bits, 100);
    assert_eq!(cfg.soundness_assumption, SoundnessAssumption::CapacityBound);
}

#[test]
fn validation_rejects_low_security() {
    let cfg = SecurityConfig {
        security_level_bits: MIN_SECURITY_BITS - 1,
        ..SecurityConfig::default()
    };
    assert_eq!(cfg.validate(), Err(SpartanWhirError::SecurityBelowMinimum));
}

#[test]
fn validation_rejects_low_merkle_security() {
    let cfg = SecurityConfig {
        merkle_security_bits: MIN_SECURITY_BITS - 1,
        ..SecurityConfig::default()
    };
    assert_eq!(
        cfg.validate(),
        Err(SpartanWhirError::MerkleSecurityBelowMinimum)
    );
}

#[test]
fn validation_rejects_security_above_supported_maximum() {
    let cfg = SecurityConfig {
        security_level_bits: MAX_SECURITY_BITS + 1,
        ..SecurityConfig::default()
    };
    assert_eq!(cfg.validate(), Err(SpartanWhirError::SecurityAboveMaximum));
}

#[test]
fn validation_rejects_merkle_security_above_supported_maximum() {
    let cfg = SecurityConfig {
        merkle_security_bits: MAX_SECURITY_BITS + 1,
        ..SecurityConfig::default()
    };
    assert_eq!(
        cfg.validate(),
        Err(SpartanWhirError::MerkleSecurityAboveMaximum)
    );
}

#[test]
fn validation_accepts_supported_maximum() {
    let cfg = SecurityConfig {
        security_level_bits: MAX_SECURITY_BITS,
        merkle_security_bits: MAX_SECURITY_BITS,
        soundness_assumption: SoundnessAssumption::CapacityBound,
    };
    assert_eq!(cfg.validate(), Ok(()));
}

#[test]
fn effective_security_is_min_of_security_and_merkle() {
    let cfg = SecurityConfig {
        security_level_bits: MAX_SECURITY_BITS,
        merkle_security_bits: 96,
        soundness_assumption: SoundnessAssumption::CapacityBound,
    };

    assert_eq!(cfg.effective_security_bits(), 96);
    assert!(cfg.merkle_override_weaker_than_security());
}
