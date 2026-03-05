mod common;

use p3_challenger::FieldChallenger;
use spartan_whir::{KeccakEngine, SpartanProtocol, WhirPcs, EF};

#[test]
fn protocol_transcript_checkpoint_matches_between_prover_and_verifier() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = SpartanProtocol::<KeccakEngine, WhirPcs>::setup(
        &shape,
        &common::phase3_security(),
        &common::phase3_whir_params(),
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds");

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(13),
        &common::koala_witness(13),
        &mut prover_challenger,
    )
    .expect("prove succeeds");
    let prover_checkpoint = prover_challenger.sample_algebra_element::<EF>();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .expect("verify succeeds");
    let verifier_checkpoint = verifier_challenger.sample_algebra_element::<EF>();

    assert_eq!(prover_checkpoint, verifier_checkpoint);
}
