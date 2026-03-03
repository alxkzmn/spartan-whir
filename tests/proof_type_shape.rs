mod common;

use common::{sample_instance, DummyChallenger, DummyPcs};
use spartan_whir::{SpartanProof, SpartanProtocol, SpartanWhirError};

#[test]
fn verify_signature_accepts_external_instance_and_proof() {
    let vk = spartan_whir::VerifyingKey::<common::DummyEngine, DummyPcs>::new(
        common::sample_domain_separator(),
    );

    let proof = SpartanProof::<common::DummyEngine, DummyPcs> {
        outer_sumcheck: spartan_whir::OuterSumcheckProof { rounds: vec![] },
        outer_claims: (0, 0, 0),
        inner_sumcheck: spartan_whir::InnerSumcheckProof { rounds: vec![] },
        witness_eval: 0,
        pcs_proof: common::DummyPcsProof,
    };

    let mut challenger = DummyChallenger;
    let result = SpartanProtocol::<common::DummyEngine, DummyPcs>::verify(
        &vk,
        &sample_instance(),
        &proof,
        &mut challenger,
    );

    assert_eq!(
        result,
        Err(SpartanWhirError::Unimplemented("protocol::verify"))
    );
}
