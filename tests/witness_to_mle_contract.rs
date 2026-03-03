mod common;

use spartan_whir::SpartanWhirError;

#[test]
fn witness_to_mle_stub_returns_typed_error() {
    let shape = common::sample_shape();
    let result = shape.witness_to_mle(&[1, 2, 3]);

    assert_eq!(
        result,
        Err(SpartanWhirError::Unimplemented("r1cs::witness_to_mle"))
    );
}
