mod common;

use common::{sample_statement, DummyChallenger, DummyPcs, DummyPcsConfig};
use spartan_whir::{Evaluations, MlePcs, SpartanWhirError};

#[test]
fn commit_stub_returns_typed_error() {
    let mut challenger = DummyChallenger;
    let poly: Evaluations<u64> = vec![1, 2, 3, 4];

    let result = DummyPcs::commit(&DummyPcsConfig, &poly, &mut challenger);
    assert_eq!(result, Err(SpartanWhirError::Unimplemented("pcs::commit")));
}

#[test]
fn open_stub_returns_typed_error_with_finalized_statement() {
    let mut challenger = DummyChallenger;
    let statement = sample_statement();

    let result = DummyPcs::open(&DummyPcsConfig, (), &statement, &mut challenger);
    assert_eq!(result, Err(SpartanWhirError::Unimplemented("pcs::open")));
}

#[test]
fn verify_stub_returns_typed_error_with_finalized_statement() {
    let mut challenger = DummyChallenger;
    let statement = sample_statement();

    let result = DummyPcs::verify(
        &DummyPcsConfig,
        &[0_u64; 4],
        &statement,
        &common::DummyPcsProof,
        &mut challenger,
    );
    assert_eq!(result, Err(SpartanWhirError::Unimplemented("pcs::verify")));
}
