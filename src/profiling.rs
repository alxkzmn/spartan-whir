use crate::engine::F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolStage {
    SetupStart,
    SetupEnd,
    ProveStart,
    ProveEnd,
    VerifyStart,
    VerifyEnd,
    PcsCommit,
    PcsOpen,
    PcsVerify,
}

pub trait ProtocolObserver {
    fn on_stage(&mut self, _stage: ProtocolStage) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoopObserver;

impl ProtocolObserver for NoopObserver {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSizeSection {
    Header,
    Instance,
    OuterSumcheck,
    OuterClaims,
    InnerSumcheck,
    WitnessEval,
    WhirInitial,
    WhirRounds,
    WhirFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSize {
    pub section: ProofSizeSection,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProofSizeCounters {
    pub num_outer_rounds: usize,
    pub num_inner_rounds: usize,
    pub num_whir_rounds: usize,
    pub num_query_batches: usize,
    pub num_base_query_values: usize,
    pub num_extension_query_values: usize,
    pub num_decommitments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProofSizeReport {
    pub total_bytes: usize,
    pub effective_digest_byte_width: usize,
    pub total_digest_data_bytes: usize,
    pub sections: alloc::vec::Vec<SectionSize>,
    pub counters: ProofSizeCounters,
}

pub fn profile_spartan_blob_v1(
    codec: &crate::ProofCodecConfig,
    pcs_config: &crate::WhirPcsConfig,
    instance: &crate::R1csInstance<F, [u64; 4]>,
    proof: &crate::SpartanProof<crate::KeccakEngine, crate::WhirPcs>,
) -> Result<ProofSizeReport, crate::SpartanWhirError> {
    let (_, report) =
        crate::codec::encode_spartan_blob_v1_with_report(codec, pcs_config, instance, proof)?;
    Ok(report)
}
