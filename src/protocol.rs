use core::marker::PhantomData;

use crate::{
    DomainSeparator, InnerSumcheckProof, MlePcs, OuterSumcheckProof, R1csInstance, R1csShape,
    R1csWitness, SecurityConfig, SpartanWhirEngine, SpartanWhirError, WhirParams,
};

pub struct ProvingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub domain_separator: DomainSeparator,
    marker: PhantomData<(E, Pcs)>,
}

pub struct VerifyingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub domain_separator: DomainSeparator,
    marker: PhantomData<(E, Pcs)>,
}

pub struct SpartanProof<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub outer_sumcheck: OuterSumcheckProof<E::EF>,
    pub outer_claims: (E::EF, E::EF, E::EF),
    pub inner_sumcheck: InnerSumcheckProof<E::EF>,
    pub witness_eval: E::EF,
    pub pcs_proof: Pcs::Proof,
}

pub struct SpartanProtocol<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    marker: PhantomData<(E, Pcs)>,
}

impl<E: SpartanWhirEngine, Pcs: MlePcs<E>> SpartanProtocol<E, Pcs> {
    pub fn setup(
        _shape: &R1csShape<E::F>,
        _security: &SecurityConfig,
        _whir_params: &WhirParams,
        _pcs_config: &Pcs::Config,
    ) -> Result<(ProvingKey<E, Pcs>, VerifyingKey<E, Pcs>), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("protocol::setup"))
    }

    pub fn prove(
        _pk: &ProvingKey<E, Pcs>,
        _instance: &R1csInstance<E::F, Pcs::Commitment>,
        _witness: &R1csWitness<E::F>,
        _challenger: &mut E::Challenger,
    ) -> Result<SpartanProof<E, Pcs>, SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("protocol::prove"))
    }

    pub fn verify(
        _vk: &VerifyingKey<E, Pcs>,
        _instance: &R1csInstance<E::F, Pcs::Commitment>,
        _proof: &SpartanProof<E, Pcs>,
        _challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("protocol::verify"))
    }

    pub fn transcript_consistency_checkpoint(
        _proof: &SpartanProof<E, Pcs>,
    ) -> Result<(), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented(
            "protocol::transcript_consistency_checkpoint",
        ))
    }
}

impl<E: SpartanWhirEngine, Pcs: MlePcs<E>> ProvingKey<E, Pcs> {
    pub fn new(domain_separator: DomainSeparator) -> Self {
        Self {
            domain_separator,
            marker: PhantomData,
        }
    }
}

impl<E: SpartanWhirEngine, Pcs: MlePcs<E>> VerifyingKey<E, Pcs> {
    pub fn new(domain_separator: DomainSeparator) -> Self {
        Self {
            domain_separator,
            marker: PhantomData,
        }
    }
}
