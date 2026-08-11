use spartan_whir::{
    engine::F, MlePcs, Plonky3WhirPcs, PoseidonChallenger, PoseidonQuarticEngine,
    PoseidonQuinticEngine, ProvingKey, R1csInstance, R1csWitness, SpartanProof, SpartanProtocol,
    SpartanWhirEngine, SpartanWhirError, VerifyingKey,
};

fn assert_prove_signature<E>(
    _f: fn(
        &ProvingKey<E, Plonky3WhirPcs>,
        &[F],
        &R1csWitness<F>,
        &mut PoseidonChallenger,
    ) -> Result<
        (
            R1csInstance<F, <Plonky3WhirPcs as MlePcs<E>>::Commitment>,
            SpartanProof<E, Plonky3WhirPcs>,
        ),
        SpartanWhirError,
    >,
) where
    E: SpartanWhirEngine<F = F, Challenger = PoseidonChallenger, W = F>,
    Plonky3WhirPcs: MlePcs<E>,
{
}

fn assert_verify_signature<E>(
    _f: fn(
        &VerifyingKey<E, Plonky3WhirPcs>,
        &R1csInstance<F, <Plonky3WhirPcs as MlePcs<E>>::Commitment>,
        &SpartanProof<E, Plonky3WhirPcs>,
        &mut PoseidonChallenger,
    ) -> Result<(), SpartanWhirError>,
) where
    E: SpartanWhirEngine<F = F, Challenger = PoseidonChallenger, W = F>,
    Plonky3WhirPcs: MlePcs<E>,
{
}

#[test]
fn protocol_signatures_expose_external_instance() {
    assert_prove_signature::<PoseidonQuarticEngine>(
        SpartanProtocol::<PoseidonQuarticEngine, Plonky3WhirPcs>::prove,
    );
    assert_verify_signature::<PoseidonQuarticEngine>(
        SpartanProtocol::<PoseidonQuarticEngine, Plonky3WhirPcs>::verify,
    );
    assert_prove_signature::<PoseidonQuinticEngine>(
        SpartanProtocol::<PoseidonQuinticEngine, Plonky3WhirPcs>::prove,
    );
    assert_verify_signature::<PoseidonQuinticEngine>(
        SpartanProtocol::<PoseidonQuinticEngine, Plonky3WhirPcs>::verify,
    );
}
