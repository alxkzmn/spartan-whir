mod common;

use common::{
    sample_instance, sample_shape, sample_witness, DummyChallenger, DummyPcs, DummyPcsConfig,
};
use spartan_whir::{SecurityConfig, SpartanProtocol, SpartanWhirError, WhirParams};

#[test]
fn setup_stub_returns_typed_error() {
    let result = SpartanProtocol::<common::DummyEngine, DummyPcs>::setup(
        &sample_shape(),
        &SecurityConfig::default(),
        &WhirParams::default(),
        &DummyPcsConfig,
    );

    assert!(matches!(
        result,
        Err(SpartanWhirError::Unimplemented("protocol::setup"))
    ));
}

#[test]
fn prove_stub_returns_typed_error() {
    let mut challenger = DummyChallenger;
    let pk = spartan_whir::ProvingKey::<common::DummyEngine, DummyPcs>::new(
        common::sample_domain_separator(),
    );

    let result = SpartanProtocol::<common::DummyEngine, DummyPcs>::prove(
        &pk,
        &sample_instance(),
        &sample_witness(),
        &mut challenger,
    );

    assert!(matches!(
        result,
        Err(SpartanWhirError::Unimplemented("protocol::prove"))
    ));
}

#[test]
fn verify_stub_returns_typed_error() {
    let mut challenger = DummyChallenger;
    let vk = spartan_whir::VerifyingKey::<common::DummyEngine, DummyPcs>::new(
        common::sample_domain_separator(),
    );

    let proof = spartan_whir::SpartanProof::<common::DummyEngine, DummyPcs> {
        outer_sumcheck: spartan_whir::OuterSumcheckProof { rounds: vec![] },
        outer_claims: (0, 0, 0),
        inner_sumcheck: spartan_whir::InnerSumcheckProof { rounds: vec![] },
        witness_eval: 0,
        pcs_proof: common::DummyPcsProof,
    };

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
