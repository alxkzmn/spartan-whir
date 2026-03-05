use spartan_whir::{
    engine::F, KeccakChallenger, KeccakEngine, ProvingKey, R1csInstance, R1csWitness, SpartanProof,
    SpartanProtocol, SpartanWhirError, VerifyingKey, WhirPcs,
};

fn assert_prove_signature(
    _f: fn(
        &ProvingKey<KeccakEngine, WhirPcs>,
        &[F],
        &R1csWitness<F>,
        &mut KeccakChallenger,
    ) -> Result<
        (
            R1csInstance<F, [u64; 4]>,
            SpartanProof<KeccakEngine, WhirPcs>,
        ),
        SpartanWhirError,
    >,
) {
}

fn assert_verify_signature(
    _f: fn(
        &VerifyingKey<KeccakEngine, WhirPcs>,
        &R1csInstance<F, [u64; 4]>,
        &SpartanProof<KeccakEngine, WhirPcs>,
        &mut KeccakChallenger,
    ) -> Result<(), SpartanWhirError>,
) {
}

#[test]
fn protocol_signatures_expose_external_instance() {
    assert_prove_signature(SpartanProtocol::<KeccakEngine, WhirPcs>::prove);
    assert_verify_signature(SpartanProtocol::<KeccakEngine, WhirPcs>::verify);
}
