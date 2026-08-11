mod common;

use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use spartan_whir::{
    engine::F, generate_satisfiable_fixture, LinearConstraintClaim, MatrixClosingMode, MlePcs,
    MultilinearPoint, PcsStatement, PcsStatementBuilder, Plonky3WhirPcs, PointEvalClaim,
    PoseidonQuarticEngine, PoseidonSpartanProtocol, QuarticBinExtension as EF, SparkWhirParams,
    SpartanSnarkConfig, SpartanWhirError, SyntheticR1csConfig, WhirFoldingSchedule, WhirParams,
    WhirPcsConfig,
};

type PoseidonEngineForTest = PoseidonQuarticEngine;
type Protocol = PoseidonSpartanProtocol<spartan_whir::QuarticBinExtension>;
type PcsCommitment = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::Commitment;
type PcsProof = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::Proof;

fn pcs_config(num_variables: usize) -> WhirPcsConfig {
    WhirPcsConfig {
        num_variables,
        ..common::phase3_pcs_config()
    }
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
        pcs_config: common::phase3_pcs_config(),
        spark_whir_params: None,
    }
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
    .expect("Poseidon setup succeeds");
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
    config.pcs_config.whir = whir_params;

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
    config.whir_params = whir_params_with_starting_log_inv_rate(1);
    config.pcs_config.whir = config.whir_params.clone();
    config.spark_whir_params = Some(SparkWhirParams {
        fixed_value: whir_params_with_starting_log_inv_rate(2),
        fixed_audit: whir_params_with_starting_log_inv_rate(3),
        read: whir_params_with_starting_log_inv_rate(2),
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
