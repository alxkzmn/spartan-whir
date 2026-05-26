mod common;

use p3_field::PrimeCharacteristicRing;
use spartan_whir::{
    engine::F, generate_satisfiable_fixture, MatrixClosingMode, MultilinearPoint,
    PcsStatementBuilder, Plonky3WhirPcs, PointEvalClaim, PoseidonQuarticEngine,
    PoseidonSpartanProtocol, SpartanSnarkConfig, SyntheticR1csConfig, WhirFoldingSchedule,
    WhirParams,
};

type PoseidonEngineForTest = PoseidonQuarticEngine;
type Protocol = PoseidonSpartanProtocol<spartan_whir::QuarticBinExtension>;

fn poseidon_config(mode: MatrixClosingMode) -> SpartanSnarkConfig {
    SpartanSnarkConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        pcs_config: common::phase3_pcs_config(),
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
fn poseidon_point_order_matches_spartan_mle_convention() {
    let config = spartan_whir::WhirPcsConfig {
        num_variables: 2,
        security: common::phase3_security(),
        whir: common::phase3_whir_params(),
        sumcheck_strategy: spartan_whir::SumcheckStrategy::Svo,
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
