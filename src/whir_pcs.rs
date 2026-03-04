use alloc::{vec, vec::Vec};

use p3_dft::Radix2DFTSmallBatch;
use p3_field::TwoAdicField;
use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTree;
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
    engine::{
        KoalaExtension, KoalaField, KoalaKeccakChallenger, KoalaKeccakCompress, KoalaKeccakEngine,
        KoalaKeccakFieldHash,
    },
    Evaluations, LinearConstraintClaim, MlePcs, PcsStatement, SecurityConfig, SoundnessAssumption,
    SpartanWhirError, WhirParams,
};

pub use whir_p3::whir::parameters::SumcheckStrategy;

type KoalaProtocolParameters = ProtocolParameters<KoalaKeccakFieldHash, KoalaKeccakCompress>;
type KoalaWhirConfig = WhirConfig<
    KoalaExtension,
    KoalaField,
    KoalaKeccakFieldHash,
    KoalaKeccakCompress,
    KoalaKeccakChallenger,
>;
type KoalaWhirPoint = WhirPoint<KoalaExtension>;
type KoalaWhirProof = WhirProof<KoalaField, KoalaExtension, u64, 4>;
type KoalaMerkleTree = MerkleTree<KoalaField, u64, DenseMatrix<KoalaField>, 4>;

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

        if log_folded_domain_size > KoalaField::TWO_ADICITY {
            return Err(SpartanWhirError::InvalidConfig);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct WhirProverData {
    pub merkle_tree: KoalaMerkleTree,
    pub proof: KoalaWhirProof,
    pub polynomial: Vec<KoalaField>,
    pub ood_pairs: Vec<(KoalaWhirPoint, KoalaExtension)>,
    pub num_variables: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WhirPcs;

pub fn observe_whir_fs_domain_separator(
    config: &WhirPcsConfig,
    challenger: &mut KoalaKeccakChallenger,
) -> Result<(), SpartanWhirError> {
    let (_, whir_config) = build_whir_config(config)?;
    observe_whir_fs_domain_separator_for_config(&whir_config, challenger);
    Ok(())
}

impl MlePcs<KoalaKeccakEngine> for WhirPcs {
    type Commitment = [u64; 4];
    type ProverData = WhirProverData;
    type Proof = KoalaWhirProof;
    type Config = WhirPcsConfig;

    fn commit(
        config: &Self::Config,
        poly: &Evaluations<KoalaField>,
        challenger: &mut KoalaKeccakChallenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError> {
        config.validate()?;
        validate_polynomial_shape(poly, config.num_variables)?;

        let (protocol_params, whir_config) = build_whir_config(config)?;
        observe_whir_fs_domain_separator_for_config(&whir_config, challenger);

        let polynomial = poly.clone();
        let mut statement = whir_config.initial_statement(
            WhirEvaluations::new(polynomial.clone()),
            config.sumcheck_strategy,
        );

        let mut proof =
            KoalaWhirProof::from_protocol_parameters(&protocol_params, config.num_variables);
        let dft = Radix2DFTSmallBatch::<KoalaField>::default();
        let committer = CommitmentWriter::new(&whir_config);
        let merkle_tree = committer
            .commit::<_, KoalaField, u64, u64, 4>(&dft, &mut proof, challenger, &mut statement)
            .map_err(|_| SpartanWhirError::WhirCommitFailed)?;

        let ood_pairs = statement
            .normalize()
            .iter()
            .map(|(point, eval)| (point.clone(), *eval))
            .collect();

        let commitment = proof.initial_commitment;
        let prover_data = WhirProverData {
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
        statement: &PcsStatement<KoalaKeccakEngine>,
        challenger: &mut KoalaKeccakChallenger,
    ) -> Result<Self::Proof, SpartanWhirError> {
        config.validate()?;
        if prover_data.num_variables != config.num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        validate_user_point_claims(statement, &prover_data.polynomial, config.num_variables)?;

        let (_, whir_config) = build_whir_config(config)?;
        let mut user_statement = build_user_statement(statement, config.num_variables)?;

        for (point, eval) in &prover_data.ood_pairs {
            user_statement.add_evaluated_constraint(point.clone(), *eval);
        }

        let mut proof = prover_data.proof;
        let initial_statement = InitialStatement::from_eq_statement(
            WhirEvaluations::new(prover_data.polynomial),
            user_statement,
        );

        let dft = Radix2DFTSmallBatch::<KoalaField>::default();
        let prover = Prover(&whir_config);
        prover
            .prove::<_, KoalaField, u64, u64, 4>(
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
        statement: &PcsStatement<KoalaKeccakEngine>,
        proof: &Self::Proof,
        challenger: &mut KoalaKeccakChallenger,
    ) -> Result<(), SpartanWhirError> {
        config.validate()?;

        let (_, whir_config) = build_whir_config(config)?;
        observe_whir_fs_domain_separator_for_config(&whir_config, challenger);

        let commitment_reader = CommitmentReader::new(&whir_config);
        let parsed_commitment = commitment_reader.parse_commitment::<u64, 4>(proof, challenger);
        if *parsed_commitment.root.as_ref() != *commitment {
            return Err(SpartanWhirError::CommitmentMismatch);
        }

        let user_statement = build_user_statement(statement, config.num_variables)?;
        let verifier = Verifier::new(&whir_config);
        verifier
            .verify::<KoalaField, u64, u64, 4>(
                proof,
                challenger,
                &parsed_commitment,
                user_statement,
            )
            .map_err(|_| SpartanWhirError::WhirVerifyFailed)?;

        Ok(())
    }
}

fn build_whir_config(
    config: &WhirPcsConfig,
) -> Result<(KoalaProtocolParameters, KoalaWhirConfig), SpartanWhirError> {
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
        merkle_hash: KoalaKeccakFieldHash::new(effective_digest_bytes),
        merkle_compress: KoalaKeccakCompress::new(effective_digest_bytes),
    };
    let whir_config = KoalaWhirConfig::new(config.num_variables, protocol_params.clone());
    Ok((protocol_params, whir_config))
}

fn observe_whir_fs_domain_separator_for_config(
    whir_config: &KoalaWhirConfig,
    challenger: &mut KoalaKeccakChallenger,
) {
    let mut domain_separator: WhirFsDomainSeparator<KoalaExtension, KoalaField> =
        WhirFsDomainSeparator::new(vec![]);
    domain_separator.commit_statement::<_, _, _, 4>(whir_config);
    domain_separator.add_whir_proof::<_, _, _, 4>(whir_config);
    domain_separator.observe_domain_separator(challenger);
}

fn build_user_statement(
    statement: &PcsStatement<KoalaKeccakEngine>,
    num_variables: usize,
) -> Result<EqStatement<KoalaExtension>, SpartanWhirError> {
    reject_linear_constraints(statement.linear_constraints())?;

    let mut whir_statement = EqStatement::initialize(num_variables);
    for claim in statement.point_evals() {
        if claim.point.0.len() != num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        whir_statement.add_evaluated_constraint(to_whir_point(&claim.point.0), claim.value);
    }
    Ok(whir_statement)
}

fn reject_linear_constraints(
    linear_constraints: &[LinearConstraintClaim<KoalaKeccakEngine>],
) -> Result<(), SpartanWhirError> {
    if !linear_constraints.is_empty() {
        return Err(SpartanWhirError::UnsupportedStatementType);
    }
    Ok(())
}

fn validate_polynomial_shape(
    poly: &Evaluations<KoalaField>,
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

fn validate_user_point_claims(
    statement: &PcsStatement<KoalaKeccakEngine>,
    polynomial: &[KoalaField],
    num_variables: usize,
) -> Result<(), SpartanWhirError> {
    reject_linear_constraints(statement.linear_constraints())?;
    let poly = WhirEvaluations::new(polynomial.to_vec());
    for claim in statement.point_evals() {
        if claim.point.0.len() != num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        let expected = poly.evaluate_hypercube_base(&to_whir_point(&claim.point.0));
        if expected != claim.value {
            return Err(SpartanWhirError::WhirOpenFailed);
        }
    }
    Ok(())
}

fn to_whir_point(point: &[KoalaExtension]) -> KoalaWhirPoint {
    KoalaWhirPoint::new(point.to_vec())
}

const fn map_soundness_assumption(soundness: SoundnessAssumption) -> WhirSecurity {
    match soundness {
        SoundnessAssumption::UniqueDecoding => WhirSecurity::UniqueDecoding,
        SoundnessAssumption::JohnsonBound => WhirSecurity::JohnsonBound,
        SoundnessAssumption::CapacityBound => WhirSecurity::CapacityBound,
    }
}
