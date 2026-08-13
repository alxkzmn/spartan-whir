mod common;

use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use rand::{rngs::StdRng, SeedableRng};
use spartan_whir::{
    engine::F, generate_satisfiable_fixture, setup_poseidon_zk, InvalidConfigReason,
    LinearConstraintClaim, MatrixClosingMode, MlePcs, MultilinearPoint, OcticBinExtension,
    PcsStatement, PcsStatementBuilder, Plonky3WhirPcs, PointEvalClaim, PoseidonQuarticEngine,
    PoseidonSpartanProtocol, PoseidonZkProvingKey, PoseidonZkSetupConfig,
    PoseidonZkSpartanProtocol, PoseidonZkVerifyingKey, QuarticBinExtension as EF, SparkWhirParams,
    SpartanSnarkConfig, SpartanWhirError, SyntheticR1csConfig, WhirFoldingSchedule, WhirParams,
    WhirPcsConfig, MAX_SECURITY_BITS,
};

type PoseidonEngineForTest = PoseidonQuarticEngine;
type Protocol = PoseidonSpartanProtocol<spartan_whir::QuarticBinExtension>;
type ZkProtocol = PoseidonZkSpartanProtocol<spartan_whir::QuarticBinExtension>;
type PcsCommitment = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::Commitment;
type PcsProof = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::Proof;

fn pcs_config(num_variables: usize) -> WhirPcsConfig {
    let mut config = common::phase3_pcs_config();
    config.num_variables = num_variables;
    config.whir.starting_log_inv_rate = 2;
    config
}

fn sample_poly(num_variables: usize) -> Vec<F> {
    (0..(1 << num_variables))
        .map(|i| F::from_u32((i + 1) as u32))
        .collect()
}

fn point_eval_claim(
    poly: &[F],
    num_variables: usize,
    seed: u32,
) -> PointEvalClaim<PoseidonEngineForTest> {
    let point = MultilinearPoint(
        (0..num_variables)
            .map(|i| EF::from_u32(seed + i as u32))
            .collect(),
    );
    let value = spartan_whir::evaluate_mle_table(
        &poly.iter().copied().map(EF::from).collect::<Vec<_>>(),
        &point.0,
    )
    .expect("point evaluates");
    PointEvalClaim { point, value }
}

fn point_eval_statement(
    poly: &[F],
    num_variables: usize,
    seeds: &[u32],
) -> PcsStatement<PoseidonEngineForTest> {
    let mut builder = PcsStatementBuilder::<PoseidonEngineForTest>::new();
    for &seed in seeds {
        builder = builder.add_point_eval(point_eval_claim(poly, num_variables, seed));
    }
    builder.finalize().expect("statement finalizes")
}

fn commit_and_open(
    config: &WhirPcsConfig,
    poly: &[F],
    statement: &PcsStatement<PoseidonEngineForTest>,
) -> (PcsCommitment, PcsProof, spartan_whir::PoseidonChallenger) {
    let mut challenger = spartan_whir::poseidon_challenger();
    let (commitment, prover_data) = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::commit(
        config,
        &poly.to_vec(),
        &mut challenger,
    )
    .expect("commit succeeds");
    let proof = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::open(
        config,
        prover_data,
        statement,
        &mut challenger,
    )
    .expect("open succeeds");
    (commitment, proof, challenger)
}

fn poseidon_config(mode: MatrixClosingMode) -> SpartanSnarkConfig {
    SpartanSnarkConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        spark_whir_params: None,
    }
}

fn poseidon_zk_config(mode: MatrixClosingMode) -> PoseidonZkSetupConfig {
    PoseidonZkSetupConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        ell_zk: spartan_whir::DEFAULT_ZK_ELL,
        mask_log_inv_rate: spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
    }
}

fn setup_zk(
    shape: &spartan_whir::R1csShape<F>,
) -> (PoseidonZkProvingKey<EF>, PoseidonZkVerifyingKey<EF>) {
    setup_poseidon_zk(
        shape.clone(),
        poseidon_zk_config(MatrixClosingMode::DirectSparse),
    )
    .expect("full-ZK setup succeeds")
}

fn fixture() -> spartan_whir::SyntheticR1csFixture {
    generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 2,
        num_constraints: 2,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0xC11E_1715_7A7E,
    })
    .expect("fixture generation succeeds")
}

#[test]
fn poseidon_direct_plonky3_whir_roundtrip() {
    let fixture = fixture();
    let (pk, vk) = Protocol::setup_with_config(
        &fixture.shape,
        &poseidon_config(MatrixClosingMode::DirectSparse),
    )
    .expect("no-ZK setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();

    let (instance, proof) = Protocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("Poseidon prove succeeds");

    Protocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("Poseidon verify succeeds");
}

#[test]
fn poseidon_direct_full_zk_roundtrip() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();

    let (instance, proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");

    ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("full-ZK verify succeeds");
}

#[test]
fn poseidon_direct_full_zk_rejects_unattainable_quartic_security() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::DirectSparse);
    config.security.security_level_bits = MAX_SECURITY_BITS;
    config.security.merkle_security_bits = MAX_SECURITY_BITS;
    let error = match setup_poseidon_zk::<EF>(fixture.shape, config) {
        Ok(_) => panic!("quartic setup must reject the unattainable maximum target"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::FullZkSecurityExceedsExtensionField {
            requested_bits: MAX_SECURITY_BITS,
            ..
        })
    ));
}

#[test]
fn poseidon_direct_full_zk_accepts_octic_maximum_security() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::DirectSparse);
    config.security.security_level_bits = MAX_SECURITY_BITS;
    config.security.merkle_security_bits = MAX_SECURITY_BITS;
    setup_poseidon_zk::<OcticBinExtension>(fixture.shape, config)
        .expect("octic setup supports the maximum target");
}

#[test]
fn poseidon_direct_full_zk_rejects_oversized_application_mask_domain_at_setup() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::DirectSparse);
    config.ell_zk = 3;
    config.mask_log_inv_rate = 23;
    let error = match setup_poseidon_zk::<EF>(fixture.shape, config) {
        Ok(_) => panic!("setup must reject the length-8 application mask domain"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ZkWhirMaskDomainExceedsTwoAdicity {
            log_domain_size: 27,
            two_adicity: 26,
        })
    );
}

#[test]
fn poseidon_direct_full_zk_rejects_mismatched_application_mask_domains_at_setup() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::DirectSparse);
    config.security.security_level_bits = 110;
    config.security.merkle_security_bits = 110;
    config.mask_log_inv_rate = 1;
    let error = match setup_poseidon_zk::<OcticBinExtension>(fixture.shape, config) {
        Ok(_) => panic!("setup must reject incompatible application-mask domains"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::IncompatibleApplicationMaskDomains {
            inner_domain_size: 256,
            outer_domain_size: 512,
        })
    );
}

#[test]
fn poseidon_direct_full_zk_rejects_tampered_outer_claim() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, mut proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");
    proof.outer_claims.0 += spartan_whir::QuarticBinExtension::ONE;

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger).is_err());
}

#[test]
fn poseidon_direct_full_zk_rejects_tampered_mask_commitment() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, mut proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");
    let mut roots = proof.application_mask_commitment.roots().to_vec();
    roots[0][0] += F::ONE;
    proof.application_mask_commitment = p3_symmetric::MerkleCap::new(roots);

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger).is_err());
}

#[test]
fn poseidon_direct_full_zk_rejects_tampered_inner_sumcheck() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, mut proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");
    proof.inner_sumcheck.mu_tilde += spartan_whir::QuarticBinExtension::ONE;

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger).is_err());
}

#[test]
fn poseidon_direct_full_zk_rejects_tampered_pcs_relation() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, mut proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");
    proof.pcs_proof.sumchecks[0].mu_tilde += spartan_whir::QuarticBinExtension::ONE;

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger).is_err());
}

#[test]
fn poseidon_direct_full_zk_rejects_outer_eval_count_mismatch() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, mut proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK prove succeeds");
    proof.outer_mask_evals.pop();

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger).is_err());
}

#[test]
fn poseidon_direct_full_zk_seed_controls_fixed_witness_transcript() {
    let fixture = fixture();
    let (pk, vk) = setup_zk(&fixture.shape);

    let mut first_challenger = spartan_whir::poseidon_challenger();
    let mut first_rng = StdRng::seed_from_u64(0xA11C_E001);
    let first = ZkProtocol::prove_with_rng(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut first_challenger,
        &mut first_rng,
    )
    .expect("first full-ZK proof succeeds");
    let mut replay_challenger = spartan_whir::poseidon_challenger();
    let mut replay_rng = StdRng::seed_from_u64(0xA11C_E001);
    let replay = ZkProtocol::prove_with_rng(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut replay_challenger,
        &mut replay_rng,
    )
    .expect("replayed full-ZK proof succeeds");
    let mut second_challenger = spartan_whir::poseidon_challenger();
    let mut second_rng = StdRng::seed_from_u64(0xA11C_E002);
    let second = ZkProtocol::prove_with_rng(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut second_challenger,
        &mut second_rng,
    )
    .expect("second full-ZK proof succeeds");

    assert_eq!(
        bincode::serialize(&first).expect("first proof serializes"),
        bincode::serialize(&replay).expect("replayed proof serializes")
    );
    assert_ne!(
        bincode::serialize(&first).expect("first proof serializes"),
        bincode::serialize(&second).expect("second proof serializes")
    );
    let mut first_verifier = spartan_whir::poseidon_challenger();
    ZkProtocol::verify(&vk, &first.0, &first.1, &mut first_verifier).expect("first proof verifies");
    let mut second_verifier = spartan_whir::poseidon_challenger();
    ZkProtocol::verify(&vk, &second.0, &second.1, &mut second_verifier)
        .expect("second proof verifies");
}

#[test]
fn poseidon_full_zk_spark_is_rejected_at_setup() {
    let fixture = fixture();
    let error = match setup_poseidon_zk::<EF>(
        fixture.shape,
        poseidon_zk_config(MatrixClosingMode::Spark),
    ) {
        Ok(_) => panic!("full-ZK Spark setup must be rejected"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        SpartanWhirError::UnsupportedFullZkMatrixClosing(MatrixClosingMode::Spark)
    );
}

#[test]
fn poseidon_direct_accepts_explicit_per_round_schedule() {
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 12,
        num_constraints: 8,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0x5C4E_DA1E,
    })
    .expect("fixture generation succeeds");
    let mut config = poseidon_config(MatrixClosingMode::DirectSparse);
    let whir_params = WhirParams {
        pow_bits: 4,
        folding_factor: 2,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 1,
        folding_schedule: Some(WhirFoldingSchedule::PerRound(vec![2, 2, 2])),
        round_log_inv_rates: vec![2, 3],
    };
    config.whir_params = whir_params.clone();

    let (pk, vk) =
        Protocol::setup_with_config(&fixture.shape, &config).expect("explicit setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = Protocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("explicit schedule prove succeeds");

    Protocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("explicit schedule verify succeeds");
}

#[test]
fn poseidon_spark_plonky3_whir_roundtrip() {
    let fixture = fixture();
    let (pk, vk) =
        Protocol::setup_with_config(&fixture.shape, &poseidon_config(MatrixClosingMode::Spark))
            .expect("Poseidon Spark setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();

    let (instance, proof) = Protocol::prove_spark(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("Poseidon Spark prove succeeds");

    Protocol::verify_spark(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("Poseidon Spark verify succeeds");
}

#[test]
fn poseidon_spark_accepts_independent_table_whir_params() {
    let fixture = fixture();
    let mut config = poseidon_config(MatrixClosingMode::Spark);
    config.whir_params = whir_params_with_starting_log_inv_rate(6);
    config.spark_whir_params = Some(SparkWhirParams {
        fixed_value: whir_params_with_starting_log_inv_rate(7),
        fixed_audit: whir_params_with_starting_log_inv_rate(8),
        read: whir_params_with_starting_log_inv_rate(7),
    });

    let (pk, vk) =
        Protocol::setup_with_config(&fixture.shape, &config).expect("independent setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = Protocol::prove_spark(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("independent Spark prove succeeds");

    Protocol::verify_spark(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("independent Spark verify succeeds");
}

fn whir_params_with_starting_log_inv_rate(starting_log_inv_rate: usize) -> WhirParams {
    let mut params = common::phase3_whir_params();
    params.starting_log_inv_rate = starting_log_inv_rate;
    params
}

#[test]
fn poseidon_point_order_matches_spartan_mle_convention() {
    let config = spartan_whir::WhirPcsConfig {
        num_variables: 2,
        security: common::phase3_security(),
        whir: common::phase3_whir_params(),
    };
    let poly = vec![
        F::from_u32(3),
        F::from_u32(5),
        F::from_u32(7),
        F::from_u32(11),
    ];
    let point = MultilinearPoint(vec![
        spartan_whir::QuarticBinExtension::from_u32(2),
        spartan_whir::QuarticBinExtension::from_u32(4),
    ]);
    let expected = spartan_whir::evaluate_mle_table(
        &poly
            .iter()
            .map(|&value| spartan_whir::QuarticBinExtension::from(value))
            .collect::<Vec<_>>(),
        &point.0,
    )
    .expect("point evaluates");
    let statement = PcsStatementBuilder::<PoseidonEngineForTest>::new()
        .add_point_eval(PointEvalClaim {
            point,
            value: expected,
        })
        .finalize()
        .expect("statement finalizes");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let (commitment, prover_data) = <Plonky3WhirPcs as spartan_whir::MlePcs<
        PoseidonEngineForTest,
    >>::commit(&config, &poly, &mut prover_challenger)
    .expect("commit succeeds");
    let proof = <Plonky3WhirPcs as spartan_whir::MlePcs<PoseidonEngineForTest>>::open(
        &config,
        prover_data,
        &statement,
        &mut prover_challenger,
    )
    .expect("open succeeds");

    <Plonky3WhirPcs as spartan_whir::MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    )
    .expect("verify succeeds");
}

#[test]
fn poseidon_whir_preserves_multiple_claim_order() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = point_eval_statement(&poly, config.num_variables, &[2, 7]);
    let (commitment, proof, _) = commit_and_open(&config, &poly, &statement);

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    )
    .expect("ordered claims verify");

    let swapped_statement = point_eval_statement(&poly, config.num_variables, &[7, 2]);
    let mut swapped_verifier_challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &swapped_statement,
        &proof,
        &mut swapped_verifier_challenger,
    );
    assert_eq!(result, Err(SpartanWhirError::WhirVerifyFailed));
}

#[test]
fn poseidon_whir_rejects_tampered_commitment() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = point_eval_statement(&poly, config.num_variables, &[5]);
    let (commitment, proof, _) = commit_and_open(&config, &poly, &statement);
    let mut roots = commitment.into_roots();
    roots[0][0] += F::ONE;
    let tampered_commitment = roots.into();

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &tampered_commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(result, Err(SpartanWhirError::WhirVerifyFailed));
}

#[test]
fn poseidon_whir_rejects_wrong_claimed_evaluation() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = point_eval_statement(&poly, config.num_variables, &[9]);
    let (commitment, proof, _) = commit_and_open(&config, &poly, &statement);
    let claim = point_eval_claim(&poly, config.num_variables, 9);
    let wrong_statement = PcsStatementBuilder::<PoseidonEngineForTest>::new()
        .add_point_eval(PointEvalClaim {
            point: claim.point,
            value: claim.value + EF::ONE,
        })
        .finalize()
        .expect("wrong statement finalizes");

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &wrong_statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(result, Err(SpartanWhirError::WhirVerifyFailed));
}

#[test]
fn poseidon_whir_rejects_non_power_of_two_polynomial() {
    let config = pcs_config(6);
    let mut challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::commit(
        &config,
        &vec![F::ONE, F::from_u32(2), F::from_u32(3)],
        &mut challenger,
    );
    assert!(matches!(
        result,
        Err(SpartanWhirError::InvalidPolynomialLength)
    ));
}

#[test]
fn poseidon_whir_rejects_num_variables_mismatch() {
    let config = pcs_config(5);
    let poly = sample_poly(6);
    let mut challenger = spartan_whir::poseidon_challenger();
    let result =
        <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::commit(&config, &poly, &mut challenger);
    assert!(matches!(result, Err(SpartanWhirError::InvalidNumVariables)));
}

#[test]
fn poseidon_whir_rejects_linear_constraints() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let linear_statement = PcsStatementBuilder::<PoseidonEngineForTest>::new()
        .add_linear_constraint(LinearConstraintClaim {
            coefficients: vec![F::ONE],
            expected: EF::ONE,
        })
        .finalize()
        .expect("linear statement finalizes");
    let mut challenger = spartan_whir::poseidon_challenger();
    let (_, prover_data) =
        <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::commit(&config, &poly, &mut challenger)
            .expect("commit succeeds");
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::open(
        &config,
        prover_data,
        &linear_statement,
        &mut challenger,
    );
    assert_eq!(
        result.err(),
        Some(SpartanWhirError::UnsupportedStatementType)
    );

    let point_statement = point_eval_statement(&poly, config.num_variables, &[3]);
    let (commitment, proof, _) = commit_and_open(&config, &poly, &point_statement);
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &linear_statement,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(result, Err(SpartanWhirError::UnsupportedStatementType));
}

#[test]
fn poseidon_whir_transcript_matches_after_opening() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = point_eval_statement(&poly, config.num_variables, &[4, 11]);
    let (commitment, proof, mut prover_challenger) = commit_and_open(&config, &poly, &statement);
    let prover_checkpoint: EF = prover_challenger.sample_algebra_element();

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &statement,
        &proof,
        &mut verifier_challenger,
    )
    .expect("verify succeeds");
    let verifier_checkpoint: EF = verifier_challenger.sample_algebra_element();

    assert_eq!(prover_checkpoint, verifier_checkpoint);
}
