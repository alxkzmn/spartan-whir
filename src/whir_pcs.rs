use alloc::{rc::Rc, vec, vec::Vec};

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{PackedValue, TwoAdicField};

use p3_matrix::dense::DenseMatrix;
use p3_merkle_tree::MerkleTree;
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

use crate::profiling::profile_scope;
use crate::{
    effective_digest_bytes_for_security_bits,
    engine::{ExtField, KeccakEngine, PoseidonEngine, WhirHashEngine, F},
    CommittedPolynomialView, Evaluations, LinearConstraintClaim, MlePcs, PcsStatement, ProtocolPcs,
    SecurityConfig, SoundnessAssumption, SpartanWhirEngine, SpartanWhirError, WhirParams,
};

pub use whir_p3::whir::parameters::SumcheckStrategy;

type WhirProtocolParams<E> =
    ProtocolParameters<<E as SpartanWhirEngine>::Hash, <E as SpartanWhirEngine>::Compress>;
type PcsConfig<E, EF> = WhirConfig<
    EF,
    F,
    <E as SpartanWhirEngine>::Hash,
    <E as SpartanWhirEngine>::Compress,
    <E as SpartanWhirEngine>::Challenger,
>;
type WhirPcsPoint<Ext> = WhirPoint<Ext>;
type WhirPcsProof<Ext, W, const DIGEST_ELEMS: usize> = WhirProof<F, Ext, W, DIGEST_ELEMS>;
type WhirMerkleTree<W, const DIGEST_ELEMS: usize> =
    MerkleTree<F, W, DenseMatrix<F>, 2, DIGEST_ELEMS>;
pub type ParsedWhirCommitment<Ext, W = u64, const DIGEST_ELEMS: usize = 4> =
    whir_p3::whir::committer::reader::ParsedCommitment<Ext, Hash<F, W, DIGEST_ELEMS>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhirPcsConfig {
    pub num_variables: usize,
    pub security: SecurityConfig,
    pub whir: WhirParams,
    pub sumcheck_strategy: SumcheckStrategy,
}

#[derive(Serialize, Deserialize)]
struct WhirPcsConfigSerde {
    num_variables: usize,
    security: SecurityConfig,
    whir: WhirParams,
    sumcheck_strategy: u8,
}

impl Serialize for WhirPcsConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let sumcheck_strategy = match self.sumcheck_strategy {
            // Keep stable on the wire: 0 = Classic, 1 = Svo.
            SumcheckStrategy::Classic => 0,
            SumcheckStrategy::Svo => 1,
        };
        WhirPcsConfigSerde {
            num_variables: self.num_variables,
            security: self.security,
            whir: self.whir,
            sumcheck_strategy,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WhirPcsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let config = WhirPcsConfigSerde::deserialize(deserializer)?;
        let sumcheck_strategy = match config.sumcheck_strategy {
            // Keep stable on the wire: 0 = Classic, 1 = Svo.
            0 => SumcheckStrategy::Classic,
            1 => SumcheckStrategy::Svo,
            other => {
                return Err(serde::de::Error::custom(alloc::format!(
                    "unsupported sumcheck strategy {other}"
                )))
            }
        };
        Ok(Self {
            num_variables: config.num_variables,
            security: config.security,
            whir: config.whir,
            sumcheck_strategy,
        })
    }
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

#[derive(Debug, Clone)]
pub struct WhirProverData<Ext, W = u64, const DIGEST_ELEMS: usize = 4> {
    pub merkle_tree: Rc<WhirMerkleTree<W, DIGEST_ELEMS>>,
    pub proof: WhirPcsProof<Ext, W, DIGEST_ELEMS>,
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

pub trait WhirPcsEngine<Ext: ExtField, const DIGEST_ELEMS: usize>:
    WhirHashEngine<Ext, DIGEST_ELEMS>
where
    Self::Hash: CryptographicHasher<F, [Self::W; DIGEST_ELEMS]> + Clone + Sync,
    Self::Hash: CryptographicHasher<Self::PackedF, [Self::PackedW; DIGEST_ELEMS]>,
    Self::Compress: PseudoCompressionFunction<[Self::W; DIGEST_ELEMS], 2> + Clone + Sync,
    Self::Compress: PseudoCompressionFunction<[Self::PackedW; DIGEST_ELEMS], 2>,
    Self::W: PackedValue<Value = Self::W> + Eq + Send + Sync,
    Self::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, Self::W, DIGEST_ELEMS>>,
    [Self::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
}

impl<E, Ext, const DIGEST_ELEMS: usize> WhirPcsEngine<Ext, DIGEST_ELEMS> for E
where
    Ext: ExtField,
    E: WhirHashEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
}

pub(crate) fn derive_whir_proof_expectations<Ext>(
    config: &WhirPcsConfig,
) -> Result<WhirProofExpectations, SpartanWhirError>
where
    Ext: ExtField,
{
    let (_, whir_config) = build_whir_config::<KeccakEngine<Ext>, Ext, 4>(config)?;
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

pub fn observe_whir_fs_domain_separator<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
    challenger: &mut E::Challenger,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let (_, whir_config) = build_whir_config::<E, Ext, DIGEST_ELEMS>(config)?;
    observe_whir_fs_domain_separator_for_config::<E, Ext, DIGEST_ELEMS>(&whir_config, challenger);
    Ok(())
}

pub fn verify_parse_commitment<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
    commitment: &[E::W; DIGEST_ELEMS],
    proof: &WhirPcsProof<Ext, E::W, DIGEST_ELEMS>,
    challenger: &mut E::Challenger,
) -> Result<ParsedWhirCommitment<Ext, E::W, DIGEST_ELEMS>, SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let _profile = profile_scope("verify_parse_commitment");
    config.validate()?;
    let (_, whir_config) = build_whir_config::<E, Ext, DIGEST_ELEMS>(config)?;
    observe_whir_fs_domain_separator_for_config::<E, Ext, DIGEST_ELEMS>(&whir_config, challenger);

    let reader = CommitmentReader::new(&whir_config);
    let parsed = reader.parse_commitment::<E::W, DIGEST_ELEMS>(proof, challenger);
    if *parsed.root.as_ref() != *commitment {
        return Err(SpartanWhirError::CommitmentMismatch);
    }
    Ok(parsed)
}

pub fn verify_finalize<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
    parsed: &ParsedWhirCommitment<Ext, E::W, DIGEST_ELEMS>,
    statement: &PcsStatement<E>,
    proof: &WhirPcsProof<Ext, E::W, DIGEST_ELEMS>,
    challenger: &mut E::Challenger,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let _profile = profile_scope("verify_finalize");
    config.validate()?;
    // Note: this rebuilds config independently from `verify_parse_commitment`.
    // We keep the split API for transcript ordering clarity; may be optimized later.
    let (_, whir_config) = build_whir_config::<E, Ext, DIGEST_ELEMS>(config)?;
    let user_statement = build_user_statement::<E, Ext>(statement, config.num_variables)?;

    let verifier = Verifier::new(&whir_config);
    verifier
        .verify::<E::PackedF, E::W, E::PackedW, DIGEST_ELEMS>(
            proof,
            challenger,
            parsed,
            user_statement,
        )
        .map(|_| ())
        .map_err(|_| SpartanWhirError::WhirVerifyFailed)
}

pub fn prepare_committed_opening<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
    mut prover_data: WhirProverData<Ext, E::W, DIGEST_ELEMS>,
    challenger: &mut E::Challenger,
) -> Result<WhirProverData<Ext, E::W, DIGEST_ELEMS>, SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let _profile = profile_scope("prepare_committed_opening");
    config.validate()?;
    if prover_data.num_variables != config.num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    let (_, whir_config) = build_whir_config::<E, Ext, DIGEST_ELEMS>(config)?;
    observe_whir_fs_domain_separator_for_config::<E, Ext, DIGEST_ELEMS>(&whir_config, challenger);
    let root: Hash<F, E::W, DIGEST_ELEMS> = prover_data.proof.initial_commitment.into();
    challenger.observe(root);

    let polynomial = WhirEvaluations::new(prover_data.polynomial.clone());
    prover_data.proof.initial_ood_answers.clear();
    prover_data.ood_pairs.clear();
    {
        let _ood_profile = profile_scope("initial_ood_sampling");
        for _ in 0..whir_config.commitment_ood_samples {
            let point = WhirPoint::expand_from_univariate(
                challenger.sample_algebra_element(),
                config.num_variables,
            );
            let eval = polynomial.evaluate_hypercube_base(&point);
            challenger.observe_algebra_element(eval);
            prover_data.proof.initial_ood_answers.push(eval);
            prover_data.ood_pairs.push((point, eval));
        }
    }
    Ok(prover_data)
}

macro_rules! impl_whir_pcs {
    ($engine:ident, $digest_elems:literal) => {
impl<Ext> MlePcs<$engine<Ext>> for WhirPcs
where
    Ext: ExtField,
    $engine<Ext>: WhirPcsEngine<Ext, $digest_elems>,
    <$engine<Ext> as SpartanWhirEngine>::Hash:
        CryptographicHasher<F, [<$engine<Ext> as SpartanWhirEngine>::W; $digest_elems]>
            + CryptographicHasher<
                <$engine<Ext> as SpartanWhirEngine>::PackedF,
                [<$engine<Ext> as SpartanWhirEngine>::PackedW; $digest_elems],
            >
            + Clone
            + Sync,
    <$engine<Ext> as SpartanWhirEngine>::Compress:
        PseudoCompressionFunction<[<$engine<Ext> as SpartanWhirEngine>::W; $digest_elems], 2>
            + PseudoCompressionFunction<
                [<$engine<Ext> as SpartanWhirEngine>::PackedW; $digest_elems],
                2,
            >
            + Clone
            + Sync,
    <$engine<Ext> as SpartanWhirEngine>::W:
        PackedValue<Value = <$engine<Ext> as SpartanWhirEngine>::W> + Eq + Send + Sync,
    <$engine<Ext> as SpartanWhirEngine>::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems>>,
    [<$engine<Ext> as SpartanWhirEngine>::W; $digest_elems]:
        Serialize + for<'de> Deserialize<'de>,
{
    type Commitment = [<$engine<Ext> as SpartanWhirEngine>::W; $digest_elems];
    type ProverData =
        WhirProverData<Ext, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems>;
    type Proof = WhirPcsProof<Ext, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems>;
    type Config = WhirPcsConfig;

    fn commit(
        config: &Self::Config,
        poly: &Evaluations<F>,
        challenger: &mut <$engine<Ext> as SpartanWhirEngine>::Challenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError> {
        let _profile = profile_scope("pcs_commit");
        config.validate()?;
        validate_polynomial_shape(poly, config.num_variables)?;

        let (protocol_params, whir_config) =
            build_whir_config::<$engine<Ext>, Ext, $digest_elems>(config)?;
        observe_whir_fs_domain_separator_for_config::<$engine<Ext>, Ext, $digest_elems>(
            &whir_config,
            challenger,
        );

        let polynomial = poly.clone();
        let mut statement = whir_config.initial_statement(
            WhirEvaluations::new(polynomial.clone()),
            config.sumcheck_strategy,
        );

        let mut proof =
            WhirPcsProof::<Ext, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems>::from_protocol_parameters(
                &protocol_params,
                config.num_variables,
            );
        let dft = Radix2DFTSmallBatch::<F>::default();
        let committer = CommitmentWriter::new(&whir_config);
        let merkle_tree = {
            let _commit_profile = profile_scope("commit_writer_commit");
            committer
                .commit::<
                    _,
                    <$engine<Ext> as SpartanWhirEngine>::PackedF,
                    <$engine<Ext> as SpartanWhirEngine>::W,
                    <$engine<Ext> as SpartanWhirEngine>::PackedW,
                    $digest_elems,
                >(
                    &dft,
                    &mut proof,
                    challenger,
                    &mut statement,
                )
                .map_err(|_| SpartanWhirError::WhirCommitFailed)?
        };

        let ood_pairs = statement
            .normalize()
            .iter()
            .map(|(point, eval)| (point.clone(), *eval))
            .collect();

        let commitment = proof.initial_commitment;
        let prover_data =
            WhirProverData::<Ext, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems> {
            merkle_tree: Rc::new(merkle_tree),
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
        statement: &PcsStatement<$engine<Ext>>,
        challenger: &mut <$engine<Ext> as SpartanWhirEngine>::Challenger,
    ) -> Result<Self::Proof, SpartanWhirError> {
        open_without_commit_observation(config, prover_data, statement, challenger)
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        statement: &PcsStatement<$engine<Ext>>,
        proof: &Self::Proof,
        challenger: &mut <$engine<Ext> as SpartanWhirEngine>::Challenger,
    ) -> Result<(), SpartanWhirError> {
        let parsed =
            verify_parse_commitment::<$engine<Ext>, Ext, $digest_elems>(
                config,
                commitment,
                proof,
                challenger,
            )?;
        verify_finalize::<$engine<Ext>, Ext, $digest_elems>(
            config, &parsed, statement, proof, challenger,
        )
    }
}
    };
}

impl_whir_pcs!(KeccakEngine, 4);
impl_whir_pcs!(PoseidonEngine, 8);

pub trait ProtocolWhirEngine: SpartanWhirEngine<F = F> + Sized
where
    Self::EF: ExtField,
    WhirPcs: MlePcs<Self, Config = WhirPcsConfig>,
{
    type ParsedCommitment;

    fn challenger() -> Self::Challenger;

    fn prepare_committed_opening(
        config: &WhirPcsConfig,
        prover_data: <WhirPcs as MlePcs<Self>>::ProverData,
        challenger: &mut Self::Challenger,
    ) -> Result<<WhirPcs as MlePcs<Self>>::ProverData, SpartanWhirError>;

    fn verify_parse_commitment(
        config: &WhirPcsConfig,
        commitment: &<WhirPcs as MlePcs<Self>>::Commitment,
        proof: &<WhirPcs as MlePcs<Self>>::Proof,
        challenger: &mut Self::Challenger,
    ) -> Result<Self::ParsedCommitment, SpartanWhirError>;

    fn verify_finalize(
        config: &WhirPcsConfig,
        parsed: &Self::ParsedCommitment,
        statement: &PcsStatement<Self>,
        proof: &<WhirPcs as MlePcs<Self>>::Proof,
        challenger: &mut Self::Challenger,
    ) -> Result<(), SpartanWhirError>;
}

macro_rules! impl_protocol_whir_engine {
    ($engine:ident, $digest_elems:literal) => {
        impl<Ext> ProtocolWhirEngine for $engine<Ext>
        where
            Ext: ExtField,
        {
            type ParsedCommitment =
                ParsedWhirCommitment<Ext, <$engine<Ext> as SpartanWhirEngine>::W, $digest_elems>;

            fn challenger() -> Self::Challenger {
                <$engine<Ext> as WhirHashEngine<Ext, $digest_elems>>::challenger()
            }

            fn prepare_committed_opening(
                config: &WhirPcsConfig,
                prover_data: <WhirPcs as MlePcs<Self>>::ProverData,
                challenger: &mut Self::Challenger,
            ) -> Result<<WhirPcs as MlePcs<Self>>::ProverData, SpartanWhirError> {
                prepare_committed_opening::<Self, Ext, $digest_elems>(
                    config,
                    prover_data,
                    challenger,
                )
            }

            fn verify_parse_commitment(
                config: &WhirPcsConfig,
                commitment: &<WhirPcs as MlePcs<Self>>::Commitment,
                proof: &<WhirPcs as MlePcs<Self>>::Proof,
                challenger: &mut Self::Challenger,
            ) -> Result<Self::ParsedCommitment, SpartanWhirError> {
                verify_parse_commitment::<Self, Ext, $digest_elems>(
                    config, commitment, proof, challenger,
                )
            }

            fn verify_finalize(
                config: &WhirPcsConfig,
                parsed: &Self::ParsedCommitment,
                statement: &PcsStatement<Self>,
                proof: &<WhirPcs as MlePcs<Self>>::Proof,
                challenger: &mut Self::Challenger,
            ) -> Result<(), SpartanWhirError> {
                verify_finalize::<Self, Ext, $digest_elems>(
                    config, parsed, statement, proof, challenger,
                )
            }
        }
    };
}

impl_protocol_whir_engine!(KeccakEngine, 4);
impl_protocol_whir_engine!(PoseidonEngine, 8);

pub trait WhirProverDataView<Ext: ExtField> {
    fn num_variables(&self) -> usize;
    fn polynomial(&self) -> &[F];
}

impl<Ext, W, const DIGEST_ELEMS: usize> WhirProverDataView<Ext>
    for WhirProverData<Ext, W, DIGEST_ELEMS>
where
    Ext: ExtField,
{
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn polynomial(&self) -> &[F] {
        &self.polynomial
    }
}

impl<Ext, W, const DIGEST_ELEMS: usize> CommittedPolynomialView<Ext>
    for WhirProverData<Ext, W, DIGEST_ELEMS>
where
    Ext: ExtField,
{
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn polynomial(&self) -> &[F] {
        &self.polynomial
    }
}

impl<E> ProtocolPcs<E> for WhirPcs
where
    E: ProtocolWhirEngine,
    E::EF: ExtField,
    WhirPcs: MlePcs<E, Config = WhirPcsConfig>,
{
    type ParsedCommitment = E::ParsedCommitment;

    fn prepare_committed_opening(
        config: &Self::Config,
        prover_data: Self::ProverData,
        challenger: &mut E::Challenger,
    ) -> Result<Self::ProverData, SpartanWhirError> {
        E::prepare_committed_opening(config, prover_data, challenger)
    }

    fn verify_parse_commitment(
        config: &Self::Config,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<Self::ParsedCommitment, SpartanWhirError> {
        E::verify_parse_commitment(config, commitment, proof, challenger)
    }

    fn verify_finalize(
        config: &Self::Config,
        parsed: &Self::ParsedCommitment,
        statement: &PcsStatement<E>,
        proof: &Self::Proof,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError> {
        E::verify_finalize(config, parsed, statement, proof, challenger)
    }
}

fn open_without_commit_observation<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
    prover_data: WhirProverData<Ext, E::W, DIGEST_ELEMS>,
    statement: &PcsStatement<E>,
    challenger: &mut E::Challenger,
) -> Result<WhirPcsProof<Ext, E::W, DIGEST_ELEMS>, SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let _profile = profile_scope("pcs_open");
    config.validate()?;
    if prover_data.num_variables != config.num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    {
        let _validate_profile = profile_scope("validate_user_point_claims");
        validate_user_point_claims::<E, Ext>(
            statement,
            &prover_data.polynomial,
            config.num_variables,
        )?;
    }

    let (_, whir_config) = build_whir_config::<E, Ext, DIGEST_ELEMS>(config)?;
    let mut user_statement = {
        let _statement_profile = profile_scope("build_user_statement");
        build_user_statement::<E, Ext>(statement, config.num_variables)?
    };
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
    {
        let _prove_profile = profile_scope("old_whir_prove");
        prover
            .prove::<_, E::PackedF, E::W, E::PackedW, DIGEST_ELEMS>(
                &dft,
                &mut proof,
                challenger,
                &initial_statement,
                prover_data.merkle_tree.as_ref(),
            )
            .map_err(|_| SpartanWhirError::WhirOpenFailed)?;
    }

    Ok(proof)
}

fn build_whir_config<E, Ext, const DIGEST_ELEMS: usize>(
    config: &WhirPcsConfig,
) -> Result<(WhirProtocolParams<E>, PcsConfig<E, Ext>), SpartanWhirError>
where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let _profile = profile_scope("build_whir_config");
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
        merkle_hash: E::merkle_hash(effective_digest_bytes),
        merkle_compress: E::merkle_compress(effective_digest_bytes),
    };
    // Current spartan-whir does not enable WHIR's univariate-skip path. If that changes,
    // skip width must remain <= Ext::TWO_ADICITY (24 for KoalaBear quintic).
    let whir_config = PcsConfig::<E, Ext>::new(config.num_variables, protocol_params.clone());
    Ok((protocol_params, whir_config))
}

fn observe_whir_fs_domain_separator_for_config<E, Ext, const DIGEST_ELEMS: usize>(
    whir_config: &PcsConfig<E, Ext>,
    challenger: &mut E::Challenger,
) where
    Ext: ExtField,
    E: WhirPcsEngine<Ext, DIGEST_ELEMS>,
    E::Hash: CryptographicHasher<F, [E::W; DIGEST_ELEMS]> + Clone + Sync,
    E::Hash: CryptographicHasher<E::PackedF, [E::PackedW; DIGEST_ELEMS]>,
    E::Compress: PseudoCompressionFunction<[E::W; DIGEST_ELEMS], 2> + Clone + Sync,
    E::Compress: PseudoCompressionFunction<[E::PackedW; DIGEST_ELEMS], 2>,
    E::W: PackedValue<Value = E::W> + Eq + Send + Sync,
    E::Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<Hash<F, E::W, DIGEST_ELEMS>>,
    [E::W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let mut domain_separator: WhirFsDomainSeparator<Ext, F> = WhirFsDomainSeparator::new(vec![]);
    domain_separator.commit_statement::<_, _, _, DIGEST_ELEMS>(whir_config);
    domain_separator.add_whir_proof::<_, _, _, DIGEST_ELEMS>(whir_config);
    domain_separator.observe_domain_separator(challenger);
}

fn build_user_statement<E, Ext>(
    statement: &PcsStatement<E>,
    num_variables: usize,
) -> Result<EqStatement<Ext>, SpartanWhirError>
where
    Ext: ExtField,
    E: SpartanWhirEngine<EF = Ext>,
{
    reject_linear_constraints::<E, Ext>(statement.linear_constraints())?;

    let mut whir_statement = EqStatement::initialize(num_variables);
    for claim in statement.point_evals() {
        if claim.point.0.len() != num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        whir_statement.add_evaluated_constraint(to_whir_point::<Ext>(&claim.point.0), claim.value);
    }
    Ok(whir_statement)
}

fn reject_linear_constraints<E, Ext>(
    linear_constraints: &[LinearConstraintClaim<E>],
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
    E: SpartanWhirEngine<EF = Ext>,
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

fn validate_user_point_claims<E, Ext>(
    statement: &PcsStatement<E>,
    polynomial: &[F],
    num_variables: usize,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
    E: SpartanWhirEngine<EF = Ext>,
{
    reject_linear_constraints::<E, Ext>(statement.linear_constraints())?;
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
