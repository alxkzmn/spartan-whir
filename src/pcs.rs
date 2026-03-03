use crate::{Evaluations, PcsStatement, SpartanWhirEngine, SpartanWhirError};

pub trait MlePcs<E: SpartanWhirEngine> {
    type Commitment;
    type ProverData;
    type Proof;
    type Config;

    fn commit(
        config: &Self::Config,
        poly: &Evaluations<E::F>,
        challenger: &mut E::Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError>;

    fn open(
        config: &Self::Config,
        prover_data: Self::ProverData,
        statement: &PcsStatement<E>,
        challenger: &mut E::Challenger,
    ) -> Result<Self::Proof, SpartanWhirError>;

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        statement: &PcsStatement<E>,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError>;
}
