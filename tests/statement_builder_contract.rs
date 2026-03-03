mod common;

use spartan_whir::{
    LinearConstraintClaim, MultilinearPoint, PcsStatementBuilder, PointEvalClaim, SpartanWhirError,
};

#[test]
fn finalize_rejects_empty_builder() {
    let result = PcsStatementBuilder::<common::DummyEngine>::new().finalize();
    assert!(matches!(result, Err(SpartanWhirError::InvalidConfig)));
}

#[test]
fn finalize_accepts_point_eval_statement() {
    let result = PcsStatementBuilder::<common::DummyEngine>::new()
        .add_point_eval(PointEvalClaim {
            point: MultilinearPoint(vec![0, 1]),
            value: 3,
        })
        .finalize();

    assert!(result.is_ok());
}

#[test]
#[ignore = "Reserved for non-Spartan/batched use cases in Phase 2+"]
fn finalize_accepts_linear_constraint_statement() {
    let result = PcsStatementBuilder::<common::DummyEngine>::new()
        .add_linear_constraint(LinearConstraintClaim {
            coefficients: vec![1, 2, 3],
            expected: 6,
        })
        .finalize();

    assert!(result.is_ok());
}
