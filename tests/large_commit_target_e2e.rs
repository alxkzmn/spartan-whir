mod common;

use spartan_whir::{
    engine::ExtField, generate_satisfiable_fixture_for_pow2, KeccakEngine, SpartanProtocol, WhirPcs,
};

fn run_target_e2e<EF: ExtField>(
    k: usize,
    security: &spartan_whir::SecurityConfig,
    whir_params: &spartan_whir::WhirParams,
) {
    let fixture =
        generate_satisfiable_fixture_for_pow2(k).expect("synthetic fixture generation succeeds");

    let (pk, vk) = SpartanProtocol::<KeccakEngine<EF>, WhirPcs>::setup(
        &fixture.shape,
        security,
        whir_params,
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds");

    assert_eq!(pk.shape_canonical.num_vars, 1usize << k);
    assert_eq!(vk.shape_canonical.num_vars, 1usize << k);
    assert_eq!(pk.pcs_config.num_variables, k);
    assert_eq!(vk.pcs_config.num_variables, k);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine<EF>, WhirPcs>::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verified = SpartanProtocol::<KeccakEngine<EF>, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn protocol_e2e_target_2_pow_18() {
    run_target_e2e::<spartan_whir::QuarticBinExtension>(
        18,
        &common::phase3_security(),
        &common::phase3_whir_params(),
    );
}

#[test]
#[ignore = "Heavy size target for manual runs"]
fn protocol_e2e_target_2_pow_22() {
    run_target_e2e::<spartan_whir::QuarticBinExtension>(
        22,
        &common::phase3_security(),
        &common::phase3_whir_params(),
    );
}

#[test]
#[ignore = "Heavy size target for manual runs"]
fn protocol_e2e_target_2_pow_22_octic_johnson_bound() {
    run_target_e2e::<spartan_whir::OcticBinExtension>(
        22,
        &common::k22_jb100_security(),
        &common::k22_jb100_whir_params(),
    );
}
