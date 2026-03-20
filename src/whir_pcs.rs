use alloc::{vec, vec::Vec};

use p3_dft::Radix2DFTSmallBatch;
use p3_field::TwoAdicField;

use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTree;
use p3_symmetric::Hash;
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator as WhirFsDomainSeparator,
    parameters::{errors::SecurityAssumption as WhirSecurity, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList as WhirEvaluations, multilinear::MultilinearPoint as WhirPoint},
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{initial::InitialStatement, EqStatement},
        parameters::WhirConfig,
        proof::WhirProof,
        prover::Prover,
        verifier::Verifier,
    },
};

use crate::{
    effective_digest_bytes_for_security_bits,
    engine::{ExtField, KeccakChallenger, KeccakEngine, KeccakFieldHash, KeccakNodeCompress, F},
    Evaluations, LinearConstraintClaim, MlePcs, PcsStatement, SecurityConfig, SoundnessAssumption,
    SpartanWhirError, WhirParams,
};

pub use whir_p3::whir::parameters::SumcheckStrategy;

type WhirProtocolParams = ProtocolParameters<KeccakFieldHash, KeccakNodeCompress>;
type PcsConfig<EF> = WhirConfig<EF, F, KeccakFieldHash, KeccakNodeCompress, KeccakChallenger>;
type WhirPcsPoint<Ext> = WhirPoint<Ext>;
type WhirPcsProof<Ext> = WhirProof<F, Ext, u64, 4>;
type WhirMerkleTree = MerkleTree<F, u64, DenseMatrix<F>, 4>;
pub type ParsedWhirCommitment<Ext> =
    whir_p3::whir::committer::reader::ParsedCommitment<Ext, Hash<F, u64, 4>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhirPcsConfig {
    pub num_variables: usize,
    pub security: SecurityConfig,
    pub whir: WhirParams,
    pub sumcheck_strategy: SumcheckStrategy,
}

impl Default for WhirPcsConfig {
    fn default() -> Self {
        Self {
            num_variables: 0,
            security: SecurityConfig::default(),
            whir: WhirParams::default(),
            sumcheck_strategy: SumcheckStrategy::Svo,
        }
    }
}

impl WhirPcsConfig {
    pub fn validate(&self) -> Result<(), SpartanWhirError> {
        self.security.validate()?;

        if self.whir.folding_factor == 0
            || self.whir.rs_domain_initial_reduction_factor == 0
            || self.whir.rs_domain_initial_reduction_factor > self.whir.folding_factor
            || self.whir.folding_factor > self.num_variables
        {
            return Err(SpartanWhirError::InvalidConfig);
        }

        let log_folded_domain_size = self
            .num_variables
            .checked_add(self.whir.starting_log_inv_rate)
            .and_then(|v| v.checked_sub(self.whir.folding_factor))
            .ok_or(SpartanWhirError::InvalidConfig)?;

        if log_folded_domain_size > F::TWO_ADICITY {
            return Err(SpartanWhirError::InvalidConfig);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct WhirProverData<Ext> {
    pub merkle_tree: WhirMerkleTree,
    pub proof: WhirPcsProof<Ext>,
    pub polynomial: Vec<F>,
    pub ood_pairs: Vec<(WhirPcsPoint<Ext>, Ext)>,
    pub num_variables: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WhirProofExpectations {
    pub n_rounds: usize,
    pub round_num_queries: Vec<usize>,
    pub final_num_queries: usize,
    pub requires_final_query_batch: bool,
    pub requires_final_sumcheck: bool,
    pub final_poly_num_variables: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WhirPcs;

pub(crate) fn derive_whir_proof_expectations<Ext>(
    config: &WhirPcsConfig,
) -> Result<WhirProofExpectations, SpartanWhirError>
where
    Ext: ExtField,
{
    let (_, whir_config) = build_whir_config::<Ext>(config)?;
    let n_rounds = whir_config.n_rounds();
    let round_num_queries = whir_config
        .round_parameters
        .iter()
        .map(|round| round.num_queries)
        .collect();
    let final_num_queries = whir_config.final_queries;
    let requires_final_query_batch = whir_config.final_queries > 0;
    let requires_final_sumcheck = whir_config.final_sumcheck_rounds > 0;
    let final_poly_num_variables = whir_config.final_round_config().num_variables;

    Ok(WhirProofExpectations {
        n_rounds,
        round_num_queries,
        final_num_queries,
        requires_final_query_batch,
        requires_final_sumcheck,
        final_poly_num_variables,
    })
}

pub fn observe_whir_fs_domain_separator<Ext>(
    config: &WhirPcsConfig,
    challenger: &mut KeccakChallenger,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
{
    let (_, whir_config) = build_whir_config::<Ext>(config)?;
    observe_whir_fs_domain_separator_for_config::<Ext>(&whir_config, challenger);
    Ok(())
}

pub fn verify_parse_commitment<Ext>(
    config: &WhirPcsConfig,
    commitment: &[u64; 4],
    proof: &WhirPcsProof<Ext>,
    challenger: &mut KeccakChallenger,
) -> Result<ParsedWhirCommitment<Ext>, SpartanWhirError>
where
    Ext: ExtField,
{
    config.validate()?;
    let (_, whir_config) = build_whir_config::<Ext>(config)?;
    observe_whir_fs_domain_separator_for_config::<Ext>(&whir_config, challenger);

    let reader = CommitmentReader::new(&whir_config);
    let parsed = reader.parse_commitment::<u64, 4>(proof, challenger);
    if *parsed.root.as_ref() != *commitment {
        return Err(SpartanWhirError::CommitmentMismatch);
    }
    Ok(parsed)
}

pub fn verify_finalize<Ext>(
    config: &WhirPcsConfig,
    parsed: &ParsedWhirCommitment<Ext>,
    statement: &PcsStatement<KeccakEngine<Ext>>,
    proof: &WhirPcsProof<Ext>,
    challenger: &mut KeccakChallenger,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
{
    config.validate()?;
    // Note: this rebuilds config independently from `verify_parse_commitment`.
    // We keep the split API for transcript ordering clarity; may be optimized later.
    let (_, whir_config) = build_whir_config::<Ext>(config)?;
    let user_statement = build_user_statement::<Ext>(statement, config.num_variables)?;

    let verifier = Verifier::new(&whir_config);
    verifier
        .verify::<F, u64, u64, 4>(proof, challenger, parsed, user_statement)
        .map(|_| ())
        .map_err(|_| SpartanWhirError::WhirVerifyFailed)
}

impl<Ext> MlePcs<KeccakEngine<Ext>> for WhirPcs
where
    Ext: ExtField,
{
    type Commitment = [u64; 4];
    type ProverData = WhirProverData<Ext>;
    type Proof = WhirPcsProof<Ext>;
    type Config = WhirPcsConfig;

    fn commit(
        config: &Self::Config,
        poly: &Evaluations<F>,
        challenger: &mut KeccakChallenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError> {
        config.validate()?;
        validate_polynomial_shape(poly, config.num_variables)?;

        let (protocol_params, whir_config) = build_whir_config::<Ext>(config)?;
        observe_whir_fs_domain_separator_for_config::<Ext>(&whir_config, challenger);

        let polynomial = poly.clone();
        let mut statement = whir_config.initial_statement(
            WhirEvaluations::new(polynomial.clone()),
            config.sumcheck_strategy,
        );

        let mut proof =
            WhirPcsProof::<Ext>::from_protocol_parameters(&protocol_params, config.num_variables);
        let dft = Radix2DFTSmallBatch::<F>::default();
        let committer = CommitmentWriter::new(&whir_config);
        let merkle_tree = committer
            .commit::<_, F, u64, u64, 4>(&dft, &mut proof, challenger, &mut statement)
            .map_err(|_| SpartanWhirError::WhirCommitFailed)?;

        let ood_pairs = statement
            .normalize()
            .iter()
            .map(|(point, eval)| (point.clone(), *eval))
            .collect();

        let commitment = proof.initial_commitment;
        let prover_data = WhirProverData::<Ext> {
            merkle_tree,
            proof,
            polynomial,
            ood_pairs,
            num_variables: config.num_variables,
        };

        Ok((commitment, prover_data))
    }

    fn open(
        config: &Self::Config,
        prover_data: Self::ProverData,
        statement: &PcsStatement<KeccakEngine<Ext>>,
        challenger: &mut KeccakChallenger,
    ) -> Result<Self::Proof, SpartanWhirError> {
        config.validate()?;
        if prover_data.num_variables != config.num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        validate_user_point_claims::<Ext>(
            statement,
            &prover_data.polynomial,
            config.num_variables,
        )?;

        let (_, whir_config) = build_whir_config::<Ext>(config)?;
        let mut user_statement = build_user_statement::<Ext>(statement, config.num_variables)?;

        for (point, eval) in &prover_data.ood_pairs {
            user_statement.add_evaluated_constraint(point.clone(), *eval);
        }

        let mut proof = prover_data.proof;
        let initial_statement = InitialStatement::from_eq_statement(
            WhirEvaluations::new(prover_data.polynomial),
            user_statement,
        );

        let dft = Radix2DFTSmallBatch::<F>::default();
        let prover = Prover(&whir_config);
        prover
            .prove::<_, F, u64, u64, 4>(
                &dft,
                &mut proof,
                challenger,
                &initial_statement,
                prover_data.merkle_tree,
            )
            .map_err(|_| SpartanWhirError::WhirOpenFailed)?;

        Ok(proof)
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        statement: &PcsStatement<KeccakEngine<Ext>>,
        proof: &Self::Proof,
        challenger: &mut KeccakChallenger,
    ) -> Result<(), SpartanWhirError> {
        let parsed = verify_parse_commitment::<Ext>(config, commitment, proof, challenger)?;
        verify_finalize::<Ext>(config, &parsed, statement, proof, challenger)
    }
}

fn build_whir_config<Ext>(
    config: &WhirPcsConfig,
) -> Result<(WhirProtocolParams, PcsConfig<Ext>), SpartanWhirError>
where
    Ext: ExtField,
{
    config.validate()?;
    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(config.security.merkle_security_bits as usize);
    let protocol_params = ProtocolParameters {
        starting_log_inv_rate: config.whir.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: config.whir.rs_domain_initial_reduction_factor,
        folding_factor: FoldingFactor::Constant(config.whir.folding_factor),
        soundness_type: map_soundness_assumption(config.security.soundness_assumption),
        security_level: config.security.security_level_bits as usize,
        pow_bits: config.whir.pow_bits as usize,
        // WHIR treats Merkle digests as opaque words and does not truncate them internally.
        // All digest-length reduction is enforced once, at the hasher/compressor layer.
        merkle_hash: KeccakFieldHash::new(effective_digest_bytes),
        merkle_compress: KeccakNodeCompress::new(effective_digest_bytes),
    };
    // Current spartan-whir does not enable WHIR's univariate-skip path. If that changes,
    // skip width must remain <= Ext::TWO_ADICITY (24 for KoalaBear quintic).
    let whir_config = PcsConfig::<Ext>::new(config.num_variables, protocol_params.clone());
    Ok((protocol_params, whir_config))
}

fn observe_whir_fs_domain_separator_for_config<Ext>(
    whir_config: &PcsConfig<Ext>,
    challenger: &mut KeccakChallenger,
) where
    Ext: ExtField,
{
    let mut domain_separator: WhirFsDomainSeparator<Ext, F> = WhirFsDomainSeparator::new(vec![]);
    domain_separator.commit_statement::<_, _, _, 4>(whir_config);
    domain_separator.add_whir_proof::<_, _, _, 4>(whir_config);
    domain_separator.observe_domain_separator(challenger);
}

fn build_user_statement<Ext>(
    statement: &PcsStatement<KeccakEngine<Ext>>,
    num_variables: usize,
) -> Result<EqStatement<Ext>, SpartanWhirError>
where
    Ext: ExtField,
{
    reject_linear_constraints::<Ext>(statement.linear_constraints())?;

    let mut whir_statement = EqStatement::initialize(num_variables);
    for claim in statement.point_evals() {
        if claim.point.0.len() != num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        whir_statement.add_evaluated_constraint(to_whir_point::<Ext>(&claim.point.0), claim.value);
    }
    Ok(whir_statement)
}

fn reject_linear_constraints<Ext>(
    linear_constraints: &[LinearConstraintClaim<KeccakEngine<Ext>>],
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
{
    if !linear_constraints.is_empty() {
        return Err(SpartanWhirError::UnsupportedStatementType);
    }
    Ok(())
}

fn validate_polynomial_shape(
    poly: &Evaluations<F>,
    num_variables: usize,
) -> Result<(), SpartanWhirError> {
    if poly.is_empty() || !poly.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidPolynomialLength);
    }
    if poly.len().ilog2() as usize != num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    Ok(())
}

fn validate_user_point_claims<Ext>(
    statement: &PcsStatement<KeccakEngine<Ext>>,
    polynomial: &[F],
    num_variables: usize,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
{
    reject_linear_constraints::<Ext>(statement.linear_constraints())?;
    let poly = WhirEvaluations::new(polynomial.to_vec());
    for claim in statement.point_evals() {
        if claim.point.0.len() != num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        let expected = poly.evaluate_hypercube_base(&to_whir_point::<Ext>(&claim.point.0));
        if expected != claim.value {
            return Err(SpartanWhirError::WhirOpenFailed);
        }
    }
    Ok(())
}

fn to_whir_point<Ext>(point: &[Ext]) -> WhirPcsPoint<Ext>
where
    Ext: ExtField,
{
    WhirPcsPoint::new(point.to_vec())
}

const fn map_soundness_assumption(soundness: SoundnessAssumption) -> WhirSecurity {
    match soundness {
        SoundnessAssumption::UniqueDecoding => WhirSecurity::UniqueDecoding,
        SoundnessAssumption::JohnsonBound => WhirSecurity::JohnsonBound,
        SoundnessAssumption::CapacityBound => WhirSecurity::CapacityBound,
    }
}
