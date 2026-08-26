mod common;

use p3_challenger::FieldChallenger;
use spartan_whir::{
    MatrixClosingMode, Plonky3WhirPcs, PoseidonQuarticEngine as PoseidonEngine,
    QuarticBinExtension as EF, SpartanProtocol, SpartanSnarkConfig,
};

#[test]
fn protocol_transcript_checkpoint_matches_between_prover_and_verifier() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = SpartanProtocol::<PoseidonEngine, Plonky3WhirPcs>::setup_with_config(
        &shape,
        &SpartanSnarkConfig {
            matrix_closing: MatrixClosingMode::DirectSparse,
            security: common::phase3_security(),
            whir_params: common::phase3_whir_params(),
            spark_whir_params: None,
        },
    )
    .expect("setup succeeds");

    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = SpartanProtocol::<PoseidonEngine, Plonky3WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(13),
        &common::koala_witness(13),
        &mut prover_challenger,
    )
    .expect("prove succeeds");
    let prover_checkpoint = prover_challenger.sample_algebra_element::<EF>();

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    SpartanProtocol::<PoseidonEngine, Plonky3WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .expect("verify succeeds");
    let verifier_checkpoint = verifier_challenger.sample_algebra_element::<EF>();

    assert_eq!(prover_checkpoint, verifier_checkpoint);
}
