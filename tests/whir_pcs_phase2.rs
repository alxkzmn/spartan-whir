use p3_challenger::{CanSample, FieldChallenger};
use p3_field::PrimeCharacteristicRing;

use spartan_whir::{
    engine::F, observe_whir_fs_domain_separator, KeccakChallenger, KeccakEngine, KeccakFieldHash,
    KeccakNodeCompress, MlePcs, MultilinearPoint, PcsStatementBuilder, PointEvalClaim,
    SecurityConfig, SoundnessAssumption, SpartanWhirError, WhirParams, WhirPcs, WhirPcsConfig, EF,
};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator as WhirFsDomainSeparator,
    parameters::{errors::SecurityAssumption as WhirSecurity, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList as WhirEvaluations, multilinear::MultilinearPoint as WhirPoint},
    whir::parameters::WhirConfig,
};

fn test_config(num_variables: usize) -> WhirPcsConfig {
    WhirPcsConfig {
        num_variables,
        security: SecurityConfig {
            security_level_bits: 80,
            merkle_security_bits: 80,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        },
        whir: WhirParams::default(),
        sumcheck_strategy: spartan_whir::SumcheckStrategy::Svo,
    }
}

fn sample_poly(num_variables: usize) -> Vec<F> {
    (0..(1 << num_variables))
        .map(|i| F::from_u32((i + 1) as u32))
        .collect()
}

fn claim_from_seed(poly: &[F], num_variables: usize, seed: u32) -> (MultilinearPoint<EF>, EF) {
    let point = WhirPoint::expand_from_univariate(EF::from(F::from_u32(seed)), num_variables);
    let eval = WhirEvaluations::new(poly.to_vec()).evaluate_hypercube_base(&point);
    (MultilinearPoint(point.as_slice().to_vec()), eval)
}

fn statement_with_seeds(
    poly: &[F],
    num_variables: usize,
    seeds: &[u32],
) -> spartan_whir::PcsStatement<KeccakEngine> {
    let mut builder = PcsStatementBuilder::<KeccakEngine>::new();
    for seed in seeds {
        let (point, value) = claim_from_seed(poly, num_variables, *seed);
        builder = builder.add_point_eval(PointEvalClaim { point, value });
    }
    builder
        .finalize()
        .expect("point-eval statement must finalize")
}

fn map_soundness_assumption(soundness: SoundnessAssumption) -> WhirSecurity {
    match soundness {
        SoundnessAssumption::UniqueDecoding => WhirSecurity::UniqueDecoding,
        SoundnessAssumption::JohnsonBound => WhirSecurity::JohnsonBound,
        SoundnessAssumption::CapacityBound => WhirSecurity::CapacityBound,
    }
}

#[test]
fn whir_pcs_roundtrip_point_eval() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = statement_with_seeds(&poly, config.num_variables, &[3]);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let proof = WhirPcs::open(&config, prover_data, &statement, &mut prover_challenger).unwrap();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verify_result = WhirPcs::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verify_result, Ok(()));
}

#[test]
fn whir_pcs_constraint_order_regression() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = statement_with_seeds(&poly, config.num_variables, &[2, 7]);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let proof = WhirPcs::open(&config, prover_data, &statement, &mut prover_challenger).unwrap();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verify_result = WhirPcs::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verify_result, Ok(()));
}

#[test]
fn whir_pcs_tampered_commitment_fails() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = statement_with_seeds(&poly, config.num_variables, &[5]);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let proof = WhirPcs::open(&config, prover_data, &statement, &mut prover_challenger).unwrap();

    let mut tampered_commitment = commitment;
    tampered_commitment[0] ^= 1;

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verify_result = WhirPcs::verify(
        &config,
        &tampered_commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verify_result, Err(SpartanWhirError::CommitmentMismatch));
}

#[test]
fn whir_pcs_wrong_eval_fails() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let (point, eval) = claim_from_seed(&poly, config.num_variables, 9);
    let wrong_statement = PcsStatementBuilder::<KeccakEngine>::new()
        .add_point_eval(PointEvalClaim {
            point,
            value: eval + EF::ONE,
        })
        .finalize()
        .unwrap();

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (_commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let open_result = WhirPcs::open(
        &config,
        prover_data,
        &wrong_statement,
        &mut prover_challenger,
    );
    assert!(matches!(open_result, Err(SpartanWhirError::WhirOpenFailed)));
}

#[test]
fn whir_pcs_rejects_non_power_of_two_poly() {
    let config = test_config(6);
    let bad_poly = vec![F::from_u32(1), F::from_u32(2), F::from_u32(3)];
    let mut challenger = spartan_whir::new_keccak_challenger();

    let result = WhirPcs::commit(&config, &bad_poly, &mut challenger);
    assert!(matches!(
        result,
        Err(SpartanWhirError::InvalidPolynomialLength)
    ));
}

#[test]
fn whir_pcs_rejects_num_variables_mismatch() {
    let config = test_config(5);
    let poly = sample_poly(6);
    let mut challenger = spartan_whir::new_keccak_challenger();

    let result = WhirPcs::commit(&config, &poly, &mut challenger);
    assert!(matches!(result, Err(SpartanWhirError::InvalidNumVariables)));
}

#[test]
fn whir_pcs_rejects_linear_constraints_phase2() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let linear_statement = PcsStatementBuilder::<KeccakEngine>::new()
        .add_linear_constraint(spartan_whir::LinearConstraintClaim {
            coefficients: vec![F::from_u32(1)],
            expected: EF::from(F::from_u32(1)),
        })
        .finalize()
        .unwrap();

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (_commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let open_result = WhirPcs::open(
        &config,
        prover_data,
        &linear_statement,
        &mut prover_challenger,
    );
    assert!(matches!(
        open_result,
        Err(SpartanWhirError::UnsupportedStatementType)
    ));
}

#[test]
fn whir_pcs_transcript_checkpoint_match() {
    let config = test_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = statement_with_seeds(&poly, config.num_variables, &[4, 11]);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (commitment, prover_data) =
        WhirPcs::commit(&config, &poly, &mut prover_challenger).unwrap();
    let proof = WhirPcs::open(&config, prover_data, &statement, &mut prover_challenger).unwrap();
    let checkpoint_prover: EF = prover_challenger.sample_algebra_element();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verify_result = WhirPcs::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verify_result, Ok(()));

    let checkpoint_verifier: EF = verifier_challenger.sample_algebra_element();
    assert_eq!(checkpoint_prover, checkpoint_verifier);
}

#[test]
fn whir_pcs_sumcheck_strategy_default_is_svo() {
    let config = WhirPcsConfig::default();
    assert_eq!(
        config.sumcheck_strategy,
        spartan_whir::SumcheckStrategy::Svo
    );
}

#[test]
fn whir_pcs_domain_separator_roundtrip_alignment() {
    let config = test_config(6);

    let mut adapter_challenger = spartan_whir::new_keccak_challenger();
    observe_whir_fs_domain_separator(&config, &mut adapter_challenger).unwrap();
    let adapter_sample: F = adapter_challenger.sample();

    let protocol_params = ProtocolParameters {
        starting_log_inv_rate: config.whir.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: config.whir.rs_domain_initial_reduction_factor,
        folding_factor: FoldingFactor::Constant(config.whir.folding_factor),
        soundness_type: map_soundness_assumption(config.security.soundness_assumption),
        security_level: config.security.security_level_bits as usize,
        pow_bits: config.whir.pow_bits as usize,
        merkle_hash: KeccakFieldHash::for_security_bits(
            config.security.merkle_security_bits as usize,
        ),
        merkle_compress: KeccakNodeCompress::for_security_bits(
            config.security.merkle_security_bits as usize,
        ),
    };
    let whir_config =
        WhirConfig::<EF, F, KeccakFieldHash, KeccakNodeCompress, KeccakChallenger>::new(
            config.num_variables,
            protocol_params,
        );

    let mut manual_challenger = spartan_whir::new_keccak_challenger();
    let mut domain_separator: WhirFsDomainSeparator<EF, F> = WhirFsDomainSeparator::new(vec![]);
    domain_separator.commit_statement::<_, _, _, 4>(&whir_config);
    domain_separator.add_whir_proof::<_, _, _, 4>(&whir_config);
    domain_separator.observe_domain_separator(&mut manual_challenger);
    let manual_sample: F = manual_challenger.sample();

    assert_eq!(adapter_sample, manual_sample);
}
