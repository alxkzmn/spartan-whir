mod common;

use spartan_whir::{
    generate_satisfiable_fixture_for_pow2, KeccakQuarticEngine as KeccakEngine, SpartanProtocol,
    WhirPcs,
};

fn run_target_e2e(k: usize) {
    let fixture =
        generate_satisfiable_fixture_for_pow2(k).expect("synthetic fixture generation succeeds");

    let (pk, vk) = SpartanProtocol::<KeccakEngine, WhirPcs>::setup(
        &fixture.shape,
        &common::phase3_security(),
        &common::phase3_whir_params(),
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds");

    assert_eq!(pk.shape_canonical.num_vars, 1usize << k);
    assert_eq!(vk.shape_canonical.num_vars, 1usize << k);
    assert_eq!(pk.pcs_config.num_variables, k);
    assert_eq!(vk.pcs_config.num_variables, k);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verified = SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn protocol_e2e_target_2_pow_18() {
    run_target_e2e(18);
}

#[test]
#[ignore = "Heavy size target for manual runs"]
fn protocol_e2e_target_2_pow_22() {
    run_target_e2e(22);
}
