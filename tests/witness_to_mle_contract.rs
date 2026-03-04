mod common;

use p3_field::PrimeCharacteristicRing;
use spartan_whir::{KoalaField, SpartanWhirError};

#[test]
fn witness_to_mle_pads_to_canonical_witness_size() {
    let shape = common::koala_shape_single_constraint(2)
        .pad_regular()
        .expect("regularization succeeds");
    assert_eq!(shape.num_vars, 2);

    let mle = shape
        .witness_to_mle(&[KoalaField::from_u32(7)])
        .expect("witness conversion succeeds");
    assert_eq!(mle.len(), 2);
    assert_eq!(mle[0], KoalaField::from_u32(7));
    assert_eq!(mle[1], KoalaField::ZERO);
}

#[test]
fn witness_to_mle_rejects_oversized_witness() {
    let shape = common::koala_shape_single_constraint(2)
        .pad_regular()
        .expect("regularization succeeds");
    let result = shape.witness_to_mle(&[KoalaField::ONE, KoalaField::ONE, KoalaField::ONE]);
    assert_eq!(result, Err(SpartanWhirError::InvalidWitnessLength));
}
