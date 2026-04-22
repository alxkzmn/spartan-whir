mod common;

use spartan_whir::{
    effective_digest_bytes_for_security_bits, DomainSeparator, KeccakChallenger, KeccakFieldHash,
    KeccakNodeCompress, SecurityConfig, SoundnessAssumption, WhirParams,
};
use whir_p3::{
    parameters::{errors::SecurityAssumption as WhirSecurity, FoldingFactor, ProtocolParameters},
    whir::parameters::WhirConfig,
};

type Schedule4 = WhirConfig<
    spartan_whir::QuarticBinExtension,
    spartan_whir::engine::F,
    KeccakFieldHash,
    KeccakNodeCompress,
    KeccakChallenger,
>;
type Schedule8 = WhirConfig<
    spartan_whir::OcticBinExtension,
    spartan_whir::engine::F,
    KeccakFieldHash,
    KeccakNodeCompress,
    KeccakChallenger,
>;

fn protocol_params(
    security: SecurityConfig,
    whir_params: WhirParams,
) -> ProtocolParameters<KeccakFieldHash, KeccakNodeCompress> {
    ProtocolParameters {
        starting_log_inv_rate: whir_params.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: whir_params.rs_domain_initial_reduction_factor,
        folding_factor: FoldingFactor::Constant(whir_params.folding_factor),
        soundness_type: match security.soundness_assumption {
            SoundnessAssumption::UniqueDecoding => WhirSecurity::UniqueDecoding,
            SoundnessAssumption::JohnsonBound => WhirSecurity::JohnsonBound,
            SoundnessAssumption::CapacityBound => WhirSecurity::CapacityBound,
        },
        security_level: security.security_level_bits as usize,
        pow_bits: whir_params.pow_bits as usize,
        merkle_hash: KeccakFieldHash::new(effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        )),
        merkle_compress: KeccakNodeCompress::new(effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        )),
    }
}

#[test]
fn octic_k22_jb100_schedule_is_locked() {
    let security = common::k22_jb100_security();
    let whir_params = common::k22_jb100_whir_params();
    let config = Schedule8::new(22, protocol_params(security, whir_params));
    assert!(config.check_pow_bits());
    assert_eq!(config.n_rounds(), 3);
    assert_eq!(config.final_sumcheck_rounds, 6);
    assert_eq!(config.commitment_ood_samples, 1);
    assert_eq!(config.starting_folding_pow_bits, 0);
    assert_eq!(config.final_queries, 10);
    assert_eq!(config.final_pow_bits, 25);
    assert_eq!(config.final_folding_pow_bits, 0);

    let round0 = &config.round_parameters[0];
    assert_eq!(round0.num_variables, 18);
    assert_eq!(round0.folding_factor, 4);
    assert_eq!(round0.num_queries, 24);
    assert_eq!(round0.ood_samples, 1);
    assert_eq!(round0.pow_bits, 29);
    assert_eq!(round0.folding_pow_bits, 0);

    let round1 = &config.round_parameters[1];
    assert_eq!(round1.num_variables, 14);
    assert_eq!(round1.folding_factor, 4);
    assert_eq!(round1.num_queries, 16);
    assert_eq!(round1.ood_samples, 1);
    assert_eq!(round1.pow_bits, 29);
    assert_eq!(round1.folding_pow_bits, 0);

    let round2 = &config.round_parameters[2];
    assert_eq!(round2.num_variables, 10);
    assert_eq!(round2.folding_factor, 4);
    assert_eq!(round2.num_queries, 12);
    assert_eq!(round2.ood_samples, 1);
    assert_eq!(round2.pow_bits, 28);
    assert_eq!(round2.folding_pow_bits, 0);
}

#[test]
fn quartic_k22_jb100_schedule_rejects_pow_budget_at_start() {
    let security = common::k22_jb100_security();
    let whir_params = common::k22_jb100_whir_params();
    let config = Schedule4::new(22, protocol_params(security, whir_params));

    assert!(config.starting_folding_pow_bits > whir_params.pow_bits as usize);
    assert!(!config.check_pow_bits());
}

#[test]
fn johnson_bound_domain_separator_uses_soundness_byte_one() {
    let security = common::k22_jb100_security();
    let whir_params = common::k22_jb100_whir_params();
    let domain_separator = DomainSeparator::new(&common::sample_shape(), &security, &whir_params);
    let encoded = domain_separator.to_bytes();

    assert_eq!(encoded.len(), 76);
    assert_eq!(encoded[47], 1);
}
