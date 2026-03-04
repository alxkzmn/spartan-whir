mod common;

use p3_field::PrimeCharacteristicRing;
use spartan_whir::{
    KoalaExtension, KoalaField, KoalaKeccakEngine, R1csShape, SpartanProtocol, SpartanWhirError,
    WhirPcs,
};

fn regular_shape_two_constraints() -> R1csShape<KoalaField> {
    let one = KoalaField::ONE;
    R1csShape {
        num_cons: 2,
        num_vars: 2,
        num_io: 1,
        a: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 0,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 0,
                    val: one,
                },
            ],
        },
        b: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 2,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 2,
                    val: one,
                },
            ],
        },
        c: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 3,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 3,
                    val: one,
                },
            ],
        },
    }
}

fn setup_keys(
    shape: &R1csShape<KoalaField>,
) -> (
    spartan_whir::ProvingKey<KoalaKeccakEngine, WhirPcs>,
    spartan_whir::VerifyingKey<KoalaKeccakEngine, WhirPcs>,
) {
    SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::setup(
        shape,
        &common::phase3_security(),
        &common::phase3_whir_params(),
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds")
}

#[test]
fn protocol_roundtrip_regular_shape() {
    let shape = regular_shape_two_constraints();
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let witness = spartan_whir::R1csWitness {
        w: vec![KoalaField::from_u32(7), KoalaField::ZERO],
    };
    let public_inputs = common::koala_public_inputs(7);

    let (instance, proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &public_inputs,
        &witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn protocol_roundtrip_irregular_shape_autopad() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let witness = common::koala_witness(9);
    let public_inputs = common::koala_public_inputs(9);
    let (instance, proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &public_inputs,
        &witness,
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn protocol_wrong_public_input_fails() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let (instance, proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(5),
        &common::koala_witness(5),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut wrong_instance = instance;
    wrong_instance.public_inputs[0] = KoalaField::from_u32(6);
    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &wrong_instance,
        &proof,
        &mut verifier_challenger,
    );
    assert!(verified.is_err());
}

#[test]
fn protocol_tampered_commitment_fails() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let (instance, proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(5),
        &common::koala_witness(5),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let mut bad_instance = instance;
    bad_instance.witness_commitment[0] ^= 1;
    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &bad_instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Err(SpartanWhirError::CommitmentMismatch));
}

#[test]
fn protocol_tampered_outer_claims_fail() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let (instance, mut proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(11),
        &common::koala_witness(11),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    proof.outer_claims.0 += KoalaExtension::ONE;
    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Err(SpartanWhirError::SumcheckFailed));
}

#[test]
fn protocol_tampered_witness_eval_fails() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let (instance, mut proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(11),
        &common::koala_witness(11),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    proof.witness_eval += KoalaExtension::ONE;
    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert!(matches!(
        verified,
        Err(SpartanWhirError::SumcheckFailed) | Err(SpartanWhirError::WhirVerifyFailed)
    ));
}

#[test]
fn protocol_tampered_pcs_proof_fails() {
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = setup_keys(&shape);
    let mut prover_challenger = spartan_whir::new_koala_keccak_challenger();
    let mut verifier_challenger = spartan_whir::new_koala_keccak_challenger();

    let (instance, mut proof) = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(15),
        &common::koala_witness(15),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    if let Some(first) = proof.pcs_proof.initial_ood_answers.first_mut() {
        *first += KoalaExtension::ONE;
    } else {
        proof.pcs_proof.initial_commitment[0] ^= 1;
    }

    let verified = SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    );
    assert!(matches!(
        verified,
        Err(SpartanWhirError::WhirVerifyFailed)
            | Err(SpartanWhirError::CommitmentMismatch)
            | Err(SpartanWhirError::SumcheckFailed)
    ));
}
