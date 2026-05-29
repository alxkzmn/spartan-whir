#![cfg(all(feature = "circom", feature = "whir-p3-backend"))]

mod common;

use p3_field::PrimeCharacteristicRing;

use spartan_whir::{
    circom::import_bytes, engine::F, KeccakQuarticEngine as KeccakEngine, MatrixClosingMode,
    SpartanProtocol, SpartanSnarkConfig, SpartanWhirError, WhirPcs,
};

const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");
const TINY_WTNS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.wtns");
const NON_POWER_R1CS: &[u8] = include_bytes!("fixtures/circom/non_power_of_two.r1cs");
const NON_POWER_WTNS: &[u8] = include_bytes!("fixtures/circom/non_power_of_two.wtns");
const SUM_OF_SQUARES_SOURCE: &str = include_str!("circuits/sum_of_squares.circom");

fn direct_config() -> SpartanSnarkConfig {
    SpartanSnarkConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        pcs_config: common::phase3_pcs_config(),
        spark_whir_params: None,
    }
}

fn prove_and_verify(
    shape: &spartan_whir::R1csShape<F>,
    witness: &spartan_whir::R1csWitness<F>,
    public_inputs: &[F],
) {
    let (pk, vk) =
        SpartanProtocol::<KeccakEngine, WhirPcs>::setup_with_config(shape, &direct_config())
            .expect("setup succeeds");
    assert_eq!(pk.num_vars_unpadded, witness.w.len());

    let mut prover_challenger = spartan_whir::keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
        &pk,
        public_inputs,
        witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut verifier_challenger = spartan_whir::keccak_challenger();
    assert_eq!(
        SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
            &vk,
            &instance,
            &proof,
            &mut verifier_challenger,
        ),
        Ok(())
    );
}

#[test]
fn imports_real_generated_tiny_fixture_layout() {
    let (shape, witness, public_inputs) =
        import_bytes(TINY_R1CS, TINY_WTNS).expect("real tiny fixture imports");

    assert_eq!(shape.num_cons, 1);
    assert_eq!(shape.num_vars, 1);
    assert_eq!(shape.num_io, 2);
    assert_eq!(public_inputs, vec![F::from_u32(47), F::from_u32(5)]);
    assert_eq!(witness.w, vec![F::from_u32(7)]);
}

#[test]
fn imports_real_generated_non_power_of_two_fixture_and_protocol_pads_it() {
    let (shape, witness, public_inputs) =
        import_bytes(NON_POWER_R1CS, NON_POWER_WTNS).expect("real non-power fixture imports");

    assert_eq!(shape.num_cons, 4);
    assert_eq!(shape.num_vars, 3);
    assert_eq!(shape.num_io, 2);
    assert_eq!(public_inputs, vec![F::from_u32(903), F::from_u32(5)]);
    assert_eq!(
        witness.w,
        vec![F::from_u32(25), F::from_u32(30), F::from_u32(900)]
    );

    let (pk, _vk) =
        SpartanProtocol::<KeccakEngine, WhirPcs>::setup_with_config(&shape, &direct_config())
            .expect("setup pads imported raw shape");
    assert_eq!(pk.num_vars_unpadded, 3);
    assert_eq!(pk.shape_canonical.num_vars, 4);

    prove_and_verify(&shape, &witness, &public_inputs);
}

#[test]
fn proves_and_verifies_real_generated_tiny_fixture() {
    let (shape, witness, public_inputs) =
        import_bytes(TINY_R1CS, TINY_WTNS).expect("real tiny fixture imports");
    let (pk, _vk) =
        SpartanProtocol::<KeccakEngine, WhirPcs>::setup_with_config(&shape, &direct_config())
            .expect("setup succeeds");

    assert_eq!(pk.num_vars_unpadded, witness.w.len());

    let mut bad_witness = witness.clone();
    bad_witness.w.push(F::ZERO);
    let mut bad_challenger = spartan_whir::keccak_challenger();
    assert!(matches!(
        SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
            &pk,
            &public_inputs,
            &bad_witness,
            &mut bad_challenger,
        ),
        Err(SpartanWhirError::InvalidWitnessLength)
    ));

    prove_and_verify(&shape, &witness, &public_inputs);
}

#[test]
fn sum_of_squares_is_the_benchmark_circuit() {
    assert!(SUM_OF_SQUARES_SOURCE.contains("template SumOfSquares(N)"));
    assert!(SUM_OF_SQUARES_SOURCE.contains("component main { public [xs] } = SumOfSquares(65536);"));
}
