use spartan_whir::{
    engine::F, KeccakChallenger, KeccakQuarticEngine, KeccakQuinticEngine, MlePcs, ProvingKey,
    R1csInstance, R1csWitness, SpartanProof, SpartanProtocol, SpartanWhirEngine, SpartanWhirError,
    VerifyingKey, WhirPcs,
};

fn assert_prove_signature<E>(
    _f: fn(
        &ProvingKey<E, WhirPcs>,
        &[F],
        &R1csWitness<F>,
        &mut KeccakChallenger,
    ) -> Result<(R1csInstance<F, [u64; 4]>, SpartanProof<E, WhirPcs>), SpartanWhirError>,
) where
    E: SpartanWhirEngine<F = F, Challenger = KeccakChallenger, W = u64>,
    WhirPcs: MlePcs<E>,
{
}

fn assert_verify_signature<E>(
    _f: fn(
        &VerifyingKey<E, WhirPcs>,
        &R1csInstance<F, [u64; 4]>,
        &SpartanProof<E, WhirPcs>,
        &mut KeccakChallenger,
    ) -> Result<(), SpartanWhirError>,
) where
    E: SpartanWhirEngine<F = F, Challenger = KeccakChallenger, W = u64>,
    WhirPcs: MlePcs<E>,
{
}

#[test]
fn protocol_signatures_expose_external_instance() {
    assert_prove_signature::<KeccakQuarticEngine>(
        SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::prove,
    );
    assert_verify_signature::<KeccakQuarticEngine>(
        SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::verify,
    );
    assert_prove_signature::<KeccakQuinticEngine>(
        SpartanProtocol::<KeccakQuinticEngine, WhirPcs>::prove,
    );
    assert_verify_signature::<KeccakQuinticEngine>(
        SpartanProtocol::<KeccakQuinticEngine, WhirPcs>::verify,
    );
}
