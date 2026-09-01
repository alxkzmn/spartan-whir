mod common;

use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use rand::{rngs::StdRng, SeedableRng};
use spartan_whir::{
    engine::F, generate_satisfiable_fixture, setup_poseidon_zk, InvalidConfigReason,
    LinearConstraintClaim, MatrixClosingMode, MlePcs, MultilinearPoint, OcticBinExtension,
    PcsStatement, PcsStatementBuilder, Plonky3WhirPcs, PointEvalClaim, PoseidonQuarticEngine,
    PoseidonSpartanProtocol, PoseidonZkProvingKey, PoseidonZkSetupConfig,
    PoseidonZkSpartanProtocol, PoseidonZkVerifyingKey, ProtocolPcs, QuarticBinExtension as EF,
    QuinticExtension, SecurityConfig, SoundnessAssumption, SparkWhirParams, SpartanSnarkConfig,
    SpartanWhirError, SyntheticR1csConfig, WhirFoldingSchedule, WhirParams, WhirPcsConfig,
    ZkMatrixClosingProof, MAX_SECURITY_BITS,
};

type PoseidonEngineForTest = PoseidonQuarticEngine;
type Protocol = PoseidonSpartanProtocol<spartan_whir::QuarticBinExtension>;
type OcticProtocol = PoseidonSpartanProtocol<OcticBinExtension>;
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
        whir_params: common::phase3_zk_whir_params(),
        spark_whir_params: None,
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
fn poseidon_direct_no_zk_enforces_octic_composed_security_boundary() {
    let fixture = fixture();
    let mut accepted = poseidon_config(MatrixClosingMode::DirectSparse);
    accepted.security.security_level_bits = 121;
    accepted.security.merkle_security_bits = 121;
    OcticProtocol::setup_with_config(&fixture.shape, &accepted)
        .expect("121-bit composed DirectSparse target is attainable");

    let mut rejected = accepted;
    rejected.security.security_level_bits = 122;
    rejected.security.merkle_security_bits = 122;
    let error = OcticProtocol::setup_with_config(&fixture.shape, &rejected)
        .err()
        .expect("122-bit composed DirectSparse target is unattainable");
    assert!(matches!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ComposedSecurityUnavailable {
            requested_bits: 122,
            attainable_bits: 121,
            ..
        })
    ));
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
fn poseidon_direct_full_zk_quintic_recommended_profile_roundtrips() {
    type QuinticProtocol = PoseidonZkSpartanProtocol<QuinticExtension>;

    let fixture = fixture();
    let num_variables = fixture.shape.num_vars.next_power_of_two().ilog2() as usize;
    let config = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: 116,
            merkle_security_bits: 116,
            soundness_assumption: SoundnessAssumption::JohnsonBound,
        },
        whir_params: spartan_whir::recommended_quintic_zk_whir_params(num_variables),
        spark_whir_params: None,
        ell_zk: spartan_whir::DEFAULT_ZK_ELL,
        mask_log_inv_rate: spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
    };
    let (pk, vk) = setup_poseidon_zk::<QuinticExtension>(fixture.shape, config)
        .expect("116-bit quintic DirectSparse setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = QuinticProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("quintic DirectSparse proof succeeds");

    QuinticProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("quintic DirectSparse proof verifies");
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
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ComposedSecurityUnavailable {
            requested_bits: MAX_SECURITY_BITS,
            ..
        })
    ));
}

#[test]
fn poseidon_direct_full_zk_enforces_octic_composed_security_boundary() {
    let fixture = fixture();
    let mut accepted = poseidon_zk_config(MatrixClosingMode::DirectSparse);
    accepted.security.security_level_bits = 118;
    accepted.security.merkle_security_bits = 118;
    setup_poseidon_zk::<OcticBinExtension>(fixture.shape.clone(), accepted.clone())
        .expect("118-bit composed full-ZK DirectSparse target is attainable");

    let mut rejected = accepted;
    rejected.security.security_level_bits = 119;
    rejected.security.merkle_security_bits = 119;
    let error = setup_poseidon_zk::<OcticBinExtension>(fixture.shape, rejected)
        .err()
        .expect("119-bit composed full-ZK DirectSparse target is unattainable");
    assert!(matches!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ComposedSecurityUnavailable {
            requested_bits: 119,
            attainable_bits: 118,
            ..
        })
    ));
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
fn poseidon_full_zk_spark_roundtrip() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon_zk::<EF>(
        fixture.shape.clone(),
        poseidon_zk_config(MatrixClosingMode::Spark),
    )
    .expect("full-ZK SPARK setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = ZkProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("full-ZK SPARK proof succeeds");
    assert_eq!(proof.matrix_closing.mode(), MatrixClosingMode::Spark);

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    ZkProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("full-ZK SPARK proof verifies");
}

fn verify_zk_rejects(
    vk: &PoseidonZkVerifyingKey<EF>,
    instance: &spartan_whir::R1csInstance<F, spartan_whir::plonky3_whir_pcs::PoseidonCommitment>,
    proof: &spartan_whir::ZkSpartanProof<EF>,
) {
    let mut challenger = spartan_whir::poseidon_challenger();
    assert!(ZkProtocol::verify(vk, instance, proof, &mut challenger).is_err());
}

fn spark_closing_mut(
    proof: &mut spartan_whir::ZkSpartanProof<EF>,
) -> &mut spartan_whir::ZkSparkClosingProof<EF> {
    let ZkMatrixClosingProof::Spark(closing) = &mut proof.matrix_closing else {
        panic!("expected SPARK closing payload");
    };
    closing
}

#[test]
fn poseidon_full_zk_spark_rejects_tampered_closing_payloads() {
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 4,
        num_constraints: 8,
        num_io: 1,
        a_terms_per_constraint: 3,
        b_terms_per_constraint: 3,
        seed: 0x5A4A_7A4E,
    })
    .expect("fixture generation succeeds");
    let (pk, vk) =
        setup_poseidon_zk::<EF>(fixture.shape, poseidon_zk_config(MatrixClosingMode::Spark))
            .expect("full-ZK SPARK setup succeeds");
    let mut prover = spartan_whir::poseidon_challenger();
    let (instance, proof) =
        ZkProtocol::prove(&pk, &fixture.public_inputs, &fixture.witness, &mut prover)
            .expect("full-ZK SPARK proof succeeds");

    let mut tampered = proof.clone();
    spark_closing_mut(&mut tampered)
        .spark_products
        .proof_ops
        .layers
        .iter_mut()
        .find_map(|layer| layer.rounds.first_mut())
        .expect("SPARK product proof has a sumcheck round")
        .0[0] += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    spark_closing_mut(&mut tampered).spark_products.matrix_evals[0] += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    spark_closing_mut(&mut tampered)
        .spark_products
        .products
        .row
        .read_root += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    let closing = spark_closing_mut(&mut tampered);
    let mut roots = closing
        .spark_fixed_openings
        .value_commitment
        .roots()
        .to_vec();
    roots[0][0] += F::ONE;
    closing.spark_fixed_openings.value_commitment = p3_symmetric::MerkleCap::new(roots);
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    let closing = spark_closing_mut(&mut tampered);
    let mut roots = closing.spark_read_openings.groups[0]
        .commitment
        .roots()
        .to_vec();
    roots[0][0] += F::ONE;
    closing.spark_read_openings.groups[0].commitment = p3_symmetric::MerkleCap::new(roots);
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    spark_closing_mut(&mut tampered)
        .spark_fixed_openings
        .evals
        .val_a_low += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    *spark_closing_mut(&mut tampered).spark_read_openings.groups[0].evals[0]
        .first_mut()
        .expect("read-table opening has a low evaluation") += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    *spark_closing_mut(&mut tampered)
        .spark_fixed_openings
        .value_proof
        .initial_ood_answers
        .first_mut()
        .expect("fixed-table WHIR proof has an initial OOD answer") += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof.clone();
    *spark_closing_mut(&mut tampered).spark_read_openings.groups[0]
        .proof
        .initial_ood_answers
        .first_mut()
        .expect("read-table WHIR proof has an initial OOD answer") += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);

    let mut tampered = proof;
    tampered.pcs_proof.sumchecks[0].mu_tilde += EF::ONE;
    verify_zk_rejects(&vk, &instance, &tampered);
}

#[test]
fn poseidon_full_zk_rejects_matrix_closing_kind_mismatch() {
    let fixture = fixture();
    let (direct_pk, direct_vk) = setup_poseidon_zk::<EF>(
        fixture.shape.clone(),
        poseidon_zk_config(MatrixClosingMode::DirectSparse),
    )
    .expect("direct setup succeeds");
    let (spark_pk, spark_vk) =
        setup_poseidon_zk::<EF>(fixture.shape, poseidon_zk_config(MatrixClosingMode::Spark))
            .expect("SPARK setup succeeds");
    let mut direct_prover = spartan_whir::poseidon_challenger();
    let (direct_instance, direct_proof) = ZkProtocol::prove(
        &direct_pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut direct_prover,
    )
    .expect("direct proof succeeds");
    let mut spark_prover = spartan_whir::poseidon_challenger();
    let (spark_instance, spark_proof) = ZkProtocol::prove(
        &spark_pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut spark_prover,
    )
    .expect("SPARK proof succeeds");

    let mut verifier = spartan_whir::poseidon_challenger();
    assert_eq!(
        ZkProtocol::verify(&direct_vk, &spark_instance, &spark_proof, &mut verifier),
        Err(SpartanWhirError::ProofKindMismatch)
    );
    let mut verifier = spartan_whir::poseidon_challenger();
    assert_eq!(
        ZkProtocol::verify(&spark_vk, &direct_instance, &direct_proof, &mut verifier),
        Err(SpartanWhirError::ProofKindMismatch)
    );
}

#[test]
fn poseidon_full_zk_spark_seed_controls_transcript() {
    let fixture = fixture();
    let (pk, vk) =
        setup_poseidon_zk::<EF>(fixture.shape, poseidon_zk_config(MatrixClosingMode::Spark))
            .expect("full-ZK SPARK setup succeeds");
    let mut first_rng = StdRng::seed_from_u64(0x5A4A_0001);
    let mut replay_rng = StdRng::seed_from_u64(0x5A4A_0001);
    let mut other_rng = StdRng::seed_from_u64(0x5A4A_0002);
    let first = pk
        .prove_with_rng(
            fixture.witness.clone(),
            fixture.public_inputs.clone(),
            &mut first_rng,
        )
        .expect("seeded proof succeeds");
    let replay = pk
        .prove_with_rng(
            fixture.witness.clone(),
            fixture.public_inputs.clone(),
            &mut replay_rng,
        )
        .expect("replayed proof succeeds");
    let other = pk
        .prove_with_rng(fixture.witness, fixture.public_inputs, &mut other_rng)
        .expect("second seeded proof succeeds");
    assert_eq!(
        bincode::serialize(&first).expect("first proof serializes"),
        bincode::serialize(&replay).expect("replayed proof serializes")
    );
    assert_ne!(
        bincode::serialize(&first).expect("first proof serializes"),
        bincode::serialize(&other).expect("other proof serializes")
    );
    vk.verify(&first.instance.public_inputs, &first)
        .expect("first proof verifies");
    vk.verify(&other.instance.public_inputs, &other)
        .expect("other proof verifies");
}

#[test]
fn poseidon_full_zk_spark_rejects_invalid_table_schedule_at_setup() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::Spark);
    let invalid = WhirParams {
        folding_factor: 0,
        ..common::phase3_whir_params()
    };
    config.spark_whir_params = Some(SparkWhirParams {
        fixed_value: invalid.clone(),
        fixed_audit: invalid.clone(),
        read: invalid,
    });
    assert!(setup_poseidon_zk::<EF>(fixture.shape, config).is_err());
}

#[test]
fn poseidon_full_zk_spark_rejects_schedule_for_wrong_table_shape_at_setup() {
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 8,
        num_constraints: 64,
        num_io: 1,
        a_terms_per_constraint: 3,
        b_terms_per_constraint: 3,
        seed: 0x5A4A_5C4E,
    })
    .expect("fixture generation succeeds");
    let mut config = poseidon_zk_config(MatrixClosingMode::Spark);
    let valid = common::phase3_whir_params();
    let mismatched = WhirParams {
        folding_factor: 1,
        folding_schedule: Some(WhirFoldingSchedule::PerRound(vec![1])),
        ..valid.clone()
    };
    config.spark_whir_params = Some(SparkWhirParams {
        fixed_value: mismatched,
        fixed_audit: valid.clone(),
        read: valid,
    });

    assert!(matches!(
        setup_poseidon_zk::<EF>(fixture.shape, config),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::InvalidFoldingSchedule { .. }
        ))
    ));
}

#[test]
fn poseidon_full_zk_spark_rejects_unattainable_composed_security() {
    let fixture = fixture();
    let mut config = poseidon_zk_config(MatrixClosingMode::Spark);
    config.security.security_level_bits = MAX_SECURITY_BITS;
    config.security.merkle_security_bits = MAX_SECURITY_BITS;
    let error = setup_poseidon_zk::<OcticBinExtension>(fixture.shape, config)
        .err()
        .expect("composed target must be rejected");
    assert!(matches!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ComposedSecurityUnavailable {
            requested_bits: MAX_SECURITY_BITS,
            ..
        })
    ));
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
fn poseidon_full_zk_quintic_spark_roundtrip_uses_two_read_commitments() {
    type QuinticProtocol = PoseidonZkSpartanProtocol<QuinticExtension>;
    let fixture = fixture();
    let (pk, vk) = setup_poseidon_zk::<QuinticExtension>(
        fixture.shape,
        poseidon_zk_config(MatrixClosingMode::Spark),
    )
    .expect("quintic full-ZK SPARK setup succeeds");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = QuinticProtocol::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("quintic full-ZK SPARK proof succeeds");
    let ZkMatrixClosingProof::Spark(closing) = &proof.matrix_closing else {
        panic!("expected SPARK closing payload");
    };
    assert_eq!(closing.spark_read_openings.groups.len(), 2);

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    QuinticProtocol::verify(&vk, &instance, &proof, &mut verifier_challenger)
        .expect("quintic full-ZK SPARK proof verifies");
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
fn poseidon_whir_rejects_batch_cancelling_forged_openings() {
    let config = pcs_config(6);
    let poly = sample_poly(config.num_variables);
    let statement = point_eval_statement(&poly, config.num_variables, &[4, 13]);
    let (commitment, proof, _) = commit_and_open(&config, &poly, &statement);

    // Replay the verifier transcript the way an attacker on the unbound
    // adapter could: domain separator, commitment, and commitment OOD claims,
    // then sample the claim-batching challenge without absorbing any
    // statement claims. Before the claims were bound, this draw equaled the
    // verifier's batching challenge, so a prover knew it before choosing the
    // claimed values.
    let mut replay_challenger = spartan_whir::poseidon_challenger();
    <Plonky3WhirPcs as ProtocolPcs<PoseidonEngineForTest>>::verify_parse_commitment(
        &config,
        &commitment,
        &proof,
        &mut replay_challenger,
    )
    .expect("commitment parses");
    let alpha: EF = replay_challenger.sample_algebra_element();

    // Shift both claimed values along the cancellation direction. The batched
    // combination `value_0 + alpha * value_1` is unchanged, so the honest
    // WHIR proof authenticates the forged pair whenever the batching
    // challenge is not bound to the claims. Both individual openings are
    // false.
    let first = point_eval_claim(&poly, config.num_variables, 4);
    let second = point_eval_claim(&poly, config.num_variables, 13);
    let delta = EF::from_u32(97);
    let forged_statement = PcsStatementBuilder::<PoseidonEngineForTest>::new()
        .add_point_eval(PointEvalClaim {
            point: first.point,
            value: first.value - alpha * delta,
        })
        .add_point_eval(PointEvalClaim {
            point: second.point,
            value: second.value + delta,
        })
        .finalize()
        .expect("forged statement finalizes");

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let result = <Plonky3WhirPcs as MlePcs<PoseidonEngineForTest>>::verify(
        &config,
        &commitment,
        &forged_statement,
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
