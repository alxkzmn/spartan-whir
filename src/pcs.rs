use crate::{
    Evaluations, MatrixClosingMode, MultilinearPoint, PcsStatement, SpartanWhirEngine,
    SpartanWhirError, WhirPcsConfig,
};

mod sealed {
    pub trait SealedNoZkPcs {}
}

/// PCS families that may be composed with the ordinary, non-ZK Spartan IOP.
///
/// The capability is attached to the PCS family rather than an engine pairing,
/// so future engines can reuse a supported plain PCS implementation.
pub trait NoZkPcs: sealed::SealedNoZkPcs {}

pub(crate) use sealed::SealedNoZkPcs;

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

pub trait ProtocolPcs<E: SpartanWhirEngine>: MlePcs<E> {
    type ParsedCommitment;

    fn validate_spartan_config(
        config: &WhirPcsConfig,
        _matrix_closing: MatrixClosingMode,
        _num_outer_rounds: usize,
        _num_inner_rounds: usize,
    ) -> Result<(), SpartanWhirError>
    where
        Self: MlePcs<E, Config = WhirPcsConfig>,
    {
        config.validate()
    }

    fn prepare_committed_opening(
        config: &Self::Config,
        prover_data: Self::ProverData,
        challenger: &mut E::Challenger,
    ) -> Result<Self::ProverData, SpartanWhirError>;

    fn verify_parse_commitment(
        config: &Self::Config,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<Self::ParsedCommitment, SpartanWhirError>;

    fn verify_finalize(
        config: &Self::Config,
        parsed: &Self::ParsedCommitment,
        statement: &PcsStatement<E>,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError>;
}

/// Plain PCS support for SPARK's two read tables.
///
/// The logical row and column tables share one commitment and one opening
/// argument. Their extension-field entries are supplied as one column-major
/// base-coordinate buffer, with all row-table coordinates followed by all
/// column-table coordinates. The opening points are fixed by the surrounding
/// SPARK transcript before this interface is called.
pub trait SparkReadPcs<E: SpartanWhirEngine>: ProtocolPcs<E, Config = WhirPcsConfig> {
    type ReadProverData;
    type ParsedReadCommitment;

    fn commit_read_tables(
        config: &WhirPcsConfig,
        coordinate_columns: Evaluations<E::F>,
        domain_size: usize,
        challenger: &mut E::Challenger,
    ) -> Result<(Self::Commitment, Self::ReadProverData), SpartanWhirError>;

    fn open_read_tables(
        config: &WhirPcsConfig,
        prover_data: Self::ReadProverData,
        points: &[MultilinearPoint<E::EF>],
        challenger: &mut E::Challenger,
    ) -> Result<(Self::Proof, Vec<Vec<E::EF>>), SpartanWhirError>;

    fn verify_parse_read_commitment(
        config: &WhirPcsConfig,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<Self::ParsedReadCommitment, SpartanWhirError>;

    fn verify_finalize_read_tables(
        config: &WhirPcsConfig,
        parsed: &Self::ParsedReadCommitment,
        proof: &Self::Proof,
        points: &[MultilinearPoint<E::EF>],
        evals: &[Vec<E::EF>],
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError>;
}

pub trait CommittedPolynomialView<EF> {
    fn num_variables(&self) -> usize;
    fn polynomial(&self) -> &[crate::engine::F];
}
