use spartan_whir::{
    KoalaField, KoalaKeccakChallenger, KoalaKeccakEngine, ProvingKey, R1csInstance, R1csWitness,
    SpartanProof, SpartanProtocol, SpartanWhirError, VerifyingKey, WhirPcs,
};

fn assert_prove_signature(
    _f: fn(
        &ProvingKey<KoalaKeccakEngine, WhirPcs>,
        &[KoalaField],
        &R1csWitness<KoalaField>,
        &mut KoalaKeccakChallenger,
    ) -> Result<
        (
            R1csInstance<KoalaField, [u64; 4]>,
            SpartanProof<KoalaKeccakEngine, WhirPcs>,
        ),
        SpartanWhirError,
    >,
) {
}

fn assert_verify_signature(
    _f: fn(
        &VerifyingKey<KoalaKeccakEngine, WhirPcs>,
        &R1csInstance<KoalaField, [u64; 4]>,
        &SpartanProof<KoalaKeccakEngine, WhirPcs>,
        &mut KoalaKeccakChallenger,
    ) -> Result<(), SpartanWhirError>,
) {
}

#[test]
fn protocol_signatures_expose_external_instance() {
    assert_prove_signature(SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::prove);
    assert_verify_signature(SpartanProtocol::<KoalaKeccakEngine, WhirPcs>::verify);
}
