mod common;

use rand::distr::{Distribution, StandardUniform};
use spartan_whir::{
    engine::ExtField, generate_satisfiable_fixture_for_pow2, MatrixClosingMode, Plonky3WhirPcs,
    PoseidonEngine, SpartanProtocol, SpartanSnarkConfig,
};

fn run_target_e2e<EF>(
    k: usize,
    security: &spartan_whir::SecurityConfig,
    whir_params: &spartan_whir::WhirParams,
) where
    EF: ExtField,
    StandardUniform: Distribution<EF>,
{
    let fixture =
        generate_satisfiable_fixture_for_pow2(k).expect("synthetic fixture generation succeeds");

    let (pk, vk) = SpartanProtocol::<PoseidonEngine<EF>, Plonky3WhirPcs>::setup_with_config(
        &fixture.shape,
        &SpartanSnarkConfig {
            matrix_closing: MatrixClosingMode::DirectSparse,
            security: *security,
            whir_params: whir_params.clone(),
            spark_whir_params: None,
        },
    )
    .expect("setup succeeds");

    assert_eq!(pk.shape_canonical.num_vars, 1usize << k);
    assert_eq!(vk.shape_canonical().num_vars, 1usize << k);
    assert_eq!(pk.pcs_config.num_variables, k);
    assert_eq!(vk.pcs_config().num_variables, k);

    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = SpartanProtocol::<PoseidonEngine<EF>, Plonky3WhirPcs>::prove(
        &pk,
        &fixture.public_inputs,
        &fixture.witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    let verified = SpartanProtocol::<PoseidonEngine<EF>, Plonky3WhirPcs>::verify(
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
