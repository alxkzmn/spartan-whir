mod common;

use common::DummyPcs;
use spartan_whir::{SpartanProof, SpartanProtocol, SpartanWhirError};

#[test]
fn transcript_consistency_checkpoint_stub_returns_typed_error() {
    let proof = SpartanProof::<common::DummyEngine, DummyPcs> {
        outer_sumcheck: spartan_whir::OuterSumcheckProof { rounds: vec![] },
        outer_claims: (0, 0, 0),
        inner_sumcheck: spartan_whir::InnerSumcheckProof { rounds: vec![] },
        witness_eval: 0,
        pcs_proof: common::DummyPcsProof,
    };

    let result =
        SpartanProtocol::<common::DummyEngine, DummyPcs>::transcript_consistency_checkpoint(&proof);
    assert_eq!(
        result,
        Err(SpartanWhirError::Unimplemented(
            "protocol::transcript_consistency_checkpoint"
        ))
    );
}
