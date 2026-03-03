mod common;

use spartan_whir::{
    prove_inner, prove_outer, verify_inner, verify_outer, InnerSumcheckProof, MultilinearPoint,
    OuterSumcheckProof, SpartanWhirError,
};

#[test]
fn outer_sumcheck_stubs_return_typed_errors() {
    let mut challenger = common::DummyChallenger;
    let shape = common::sample_shape();
    let tau = MultilinearPoint(vec![0_u64, 1_u64]);

    let prove = prove_outer::<u64, _>(&shape, &[], &[], &[], &tau, &mut challenger);
    assert_eq!(
        prove,
        Err(SpartanWhirError::Unimplemented("sumcheck::prove_outer"))
    );

    let verify = verify_outer::<u64>(&OuterSumcheckProof { rounds: vec![] }, &(0, 0, 0), &tau);
    assert_eq!(
        verify,
        Err(SpartanWhirError::Unimplemented("sumcheck::verify_outer"))
    );
}

#[test]
fn inner_sumcheck_stubs_return_typed_errors() {
    let mut challenger = common::DummyChallenger;
    let shape = common::sample_shape();
    let r_x = MultilinearPoint(vec![1_u64, 0_u64]);

    let prove = prove_inner::<u64, _>(&shape, &[], &[], &r_x, &mut challenger);
    assert_eq!(
        prove,
        Err(SpartanWhirError::Unimplemented("sumcheck::prove_inner"))
    );

    let r_y = MultilinearPoint(vec![1_u64]);
    let verify = verify_inner::<u64>(&InnerSumcheckProof { rounds: vec![] }, &0_u64, &r_y);
    assert_eq!(
        verify,
        Err(SpartanWhirError::Unimplemented("sumcheck::verify_inner"))
    );
}
