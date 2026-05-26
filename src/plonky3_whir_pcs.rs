use alloc::{rc::Rc, vec::Vec};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{Field, PackedValue};
use p3_matrix::{dense::DenseMatrix, Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    commit::commit_base,
    constraints::{statement::EqStatement, Constraint},
    layout::{Layout, LayoutStrategy},
    product_polynomial::ProductPolynomial,
    strategy::{SumcheckProver, VariableOrder},
    SumcheckData,
};
use p3_util::log2_strict_usize;
use p3_whir::{
    fiat_shamir::domain_separator::DomainSeparator as WhirDomainSeparator,
    parameters::{
        FoldingFactor as Plonky3FoldingFactor, ProtocolParameters,
        SecurityAssumption as Plonky3SecurityAssumption, WhirConfig as Plonky3WhirConfig,
    },
    pcs::{
        committer::reader::ParsedCommitment, proof::WhirProof, prover::WhirProver,
        verifier::WhirVerifier,
    },
};
use serde::{Deserialize, Serialize};

use crate::profiling::profile_scope;
use crate::{
    engine::{
        poseidon_merkle_compress, poseidon_merkle_hash, ExtField, PoseidonChallenger,
        PoseidonEngine, PoseidonFieldHash, PoseidonNodeCompress, F,
    },
    CommittedPolynomialView, Evaluations, MlePcs, PcsStatement, ProtocolPcs, SoundnessAssumption,
    SpartanProtocol, SpartanWhirError, WhirPcsConfig,
};

pub struct Plonky3WhirPcs;

pub type PoseidonSpartanProtocol<Ext> = SpartanProtocol<PoseidonEngine<Ext>, Plonky3WhirPcs>;
pub type PoseidonProvingKey<Ext> = crate::ProvingKey<PoseidonEngine<Ext>, Plonky3WhirPcs>;
pub type PoseidonVerifyingKey<Ext> = crate::VerifyingKey<PoseidonEngine<Ext>, Plonky3WhirPcs>;
pub type PoseidonSpartanProof<Ext> = crate::SpartanProof<PoseidonEngine<Ext>, Plonky3WhirPcs>;
pub type PoseidonSparkSpartanProof<Ext> =
    crate::SparkSpartanProof<PoseidonEngine<Ext>, Plonky3WhirPcs>;
pub type PoseidonSpartanSnarkConfig = crate::SpartanSnarkConfig;

type InnerPoseidonMmcs = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    PoseidonFieldHash,
    PoseidonNodeCompress,
    2,
    8,
>;
type PoseidonMmcs = RcMmcs<InnerPoseidonMmcs>;
type PoseidonCommitment = <PoseidonMmcs as Mmcs<F>>::Commitment;
type PoseidonMerkleTree = <PoseidonMmcs as Mmcs<F>>::ProverData<DenseMatrix<F>>;
type PoseidonWhirProof<Ext> = WhirProof<F, Ext, PoseidonMmcs>;
type PoseidonWhirConfig<Ext> = Plonky3WhirConfig<Ext, F, PoseidonChallenger>;

#[derive(Clone)]
pub struct RcMmcs<Inner>(Inner);

impl<T, Inner> Mmcs<T> for RcMmcs<Inner>
where
    T: Send + Sync + Clone,
    Inner: Mmcs<T>,
{
    type ProverData<M> = Rc<Inner::ProverData<M>>;
    type Commitment = Inner::Commitment;
    type Proof = Inner::Proof;
    type Error = Inner::Error;

    fn commit<M: Matrix<T>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, prover_data) = self.0.commit(inputs);
        (commitment, Rc::new(prover_data))
    }

    fn open_batch<M: Matrix<T>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<T, Self> {
        let opening = self.0.open_batch(index, prover_data.as_ref());
        BatchOpening::new(opening.opened_values, opening.opening_proof)
    }

    fn get_matrices<'a, M: Matrix<T>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.0.get_matrices(prover_data.as_ref())
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, T, Self>,
    ) -> Result<(), Self::Error> {
        self.0.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::<T, Inner>::new(
                batch_opening.opened_values,
                batch_opening.opening_proof,
            ),
        )
    }
}

/// Prover-side state retained for Plonky3 WHIR openings.
///
/// Serialization includes the Merkle tree contents. The `Rc` sharing used for
/// cheap in-process clones is not preserved across a serde roundtrip.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "Ext: Serialize", deserialize = "Ext: Deserialize<'de>"))]
pub struct Plonky3WhirProverData<Ext> {
    commitment: PoseidonCommitment,
    merkle_tree: Option<PoseidonMerkleTree>,
    proof: PoseidonWhirProof<Ext>,
    polynomial: Vec<F>,
    ood_pairs: Vec<(Vec<Ext>, Ext)>,
    num_variables: usize,
}

impl<Ext: ExtField> Clone for Plonky3WhirProverData<Ext> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment.clone(),
            merkle_tree: self.merkle_tree.clone(),
            proof: self.proof.clone(),
            polynomial: self.polynomial.clone(),
            ood_pairs: self.ood_pairs.clone(),
            num_variables: self.num_variables,
        }
    }
}

impl<Ext: ExtField> CommittedPolynomialView<Ext> for Plonky3WhirProverData<Ext> {
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn polynomial(&self) -> &[F] {
        &self.polynomial
    }
}

impl<Ext> MlePcs<PoseidonEngine<Ext>> for Plonky3WhirPcs
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<PoseidonCommitment>,
{
    type Commitment = PoseidonCommitment;
    type ProverData = Plonky3WhirProverData<Ext>;
    type Proof = PoseidonWhirProof<Ext>;
    type Config = WhirPcsConfig;

    fn commit(
        config: &Self::Config,
        poly: &Evaluations<F>,
        challenger: &mut PoseidonChallenger,
    ) -> Result<(Self::Commitment, Self::ProverData), SpartanWhirError> {
        let _profile = profile_scope("pcs_commit");
        config.validate()?;
        validate_polynomial_shape(poly, config.num_variables)?;

        let pcs = build_poseidon_pcs::<Ext>(config)?;
        observe_poseidon_domain_separator::<Ext>(&pcs, challenger);

        let polynomial = Poly::new(poly.clone());
        let (commitment, merkle_tree) = {
            let _commit_profile = profile_scope("commit_base");
            commit_base(
                VariableOrder::Prefix,
                &pcs.dft,
                &pcs.mmcs,
                challenger,
                &polynomial,
                config.whir.folding_factor,
                config.whir.starting_log_inv_rate,
            )
        };

        let mut proof = pcs.config.empty_proof::<PoseidonMmcs>();
        let mut ood_pairs = Vec::with_capacity(pcs.config.commitment_ood_samples);
        {
            let _ood_profile = profile_scope("initial_ood_sampling");
            for _ in 0..pcs.config.commitment_ood_samples {
                let point = Point::expand_from_univariate(
                    challenger.sample_algebra_element(),
                    config.num_variables,
                );
                let eval = polynomial.eval_base(&point);
                challenger.observe_algebra_element(eval);
                proof.initial_ood_answers.push(eval);
                ood_pairs.push((point.as_slice().to_vec(), eval));
            }
        }

        Ok((
            commitment.clone(),
            Plonky3WhirProverData {
                commitment,
                merkle_tree: Some(merkle_tree),
                proof,
                polynomial: poly.clone(),
                ood_pairs,
                num_variables: config.num_variables,
            },
        ))
    }

    fn open(
        config: &Self::Config,
        prover_data: Self::ProverData,
        statement: &PcsStatement<PoseidonEngine<Ext>>,
        challenger: &mut PoseidonChallenger,
    ) -> Result<Self::Proof, SpartanWhirError> {
        open_without_commit_observation(config, prover_data, statement, challenger)
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        statement: &PcsStatement<PoseidonEngine<Ext>>,
        proof: &Self::Proof,
        challenger: &mut PoseidonChallenger,
    ) -> Result<(), SpartanWhirError> {
        let parsed = <Self as ProtocolPcs<PoseidonEngine<Ext>>>::verify_parse_commitment(
            config, commitment, proof, challenger,
        )?;
        <Self as ProtocolPcs<PoseidonEngine<Ext>>>::verify_finalize(
            config, &parsed, statement, proof, challenger,
        )
    }
}

impl<Ext> ProtocolPcs<PoseidonEngine<Ext>> for Plonky3WhirPcs
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<PoseidonCommitment>,
{
    type ParsedCommitment = ParsedCommitment<Ext, PoseidonCommitment>;

    fn prepare_committed_opening(
        config: &Self::Config,
        mut prover_data: Self::ProverData,
        challenger: &mut PoseidonChallenger,
    ) -> Result<Self::ProverData, SpartanWhirError> {
        let _profile = profile_scope("prepare_committed_opening");
        config.validate()?;
        if prover_data.num_variables != config.num_variables {
            return Err(SpartanWhirError::InvalidNumVariables);
        }
        let pcs = build_poseidon_pcs::<Ext>(config)?;
        observe_poseidon_domain_separator::<Ext>(&pcs, challenger);
        challenger.observe(prover_data.commitment.clone());
        let polynomial = Poly::new(prover_data.polynomial.clone());
        if prover_data.merkle_tree.is_none() {
            return Err(SpartanWhirError::InvalidConfig);
        }

        prover_data.proof.initial_ood_answers.clear();
        prover_data.ood_pairs.clear();
        {
            let _ood_profile = profile_scope("initial_ood_sampling");
            for _ in 0..pcs.config.commitment_ood_samples {
                let point = Point::expand_from_univariate(
                    challenger.sample_algebra_element(),
                    config.num_variables,
                );
                let eval = polynomial.eval_base(&point);
                challenger.observe_algebra_element(eval);
                prover_data.proof.initial_ood_answers.push(eval);
                prover_data
                    .ood_pairs
                    .push((point.as_slice().to_vec(), eval));
            }
        }
        Ok(prover_data)
    }

    fn verify_parse_commitment(
        config: &Self::Config,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        challenger: &mut PoseidonChallenger,
    ) -> Result<Self::ParsedCommitment, SpartanWhirError> {
        let _profile = profile_scope("verify_parse_commitment");
        config.validate()?;
        let pcs = build_poseidon_pcs::<Ext>(config)?;
        observe_poseidon_domain_separator::<Ext>(&pcs, challenger);
        challenger.observe(commitment.clone());
        parse_initial_commitment::<Ext>(
            config.num_variables,
            &pcs.config,
            commitment,
            proof,
            challenger,
        )
    }

    fn verify_finalize(
        config: &Self::Config,
        parsed: &Self::ParsedCommitment,
        statement: &PcsStatement<PoseidonEngine<Ext>>,
        proof: &Self::Proof,
        challenger: &mut PoseidonChallenger,
    ) -> Result<(), SpartanWhirError> {
        let _profile = profile_scope("verify_finalize");
        config.validate()?;
        let pcs = build_poseidon_pcs::<Ext>(config)?;
        let mut eq_statement = build_eq_statement(statement, config.num_variables)?;
        for (point, eval) in parsed.ood_statement.iter() {
            eq_statement.add_evaluated_constraint(point.clone(), *eval);
        }
        let alpha = challenger.sample_algebra_element();
        let initial_constraint = Constraint::new_eq_only(alpha, eq_statement);
        let mut claimed_eval = Ext::ZERO;
        initial_constraint.combine_evals(&mut claimed_eval);

        let verifier = WhirVerifier::new(&pcs.config, &pcs.mmcs, VariableOrder::Prefix);
        verifier
            .verify(
                proof,
                challenger,
                &parsed.root,
                initial_constraint,
                claimed_eval,
            )
            .map(|_| ())
            .map_err(|_| SpartanWhirError::WhirVerifyFailed)
    }
}

struct SpartanEqLayout<Ext: ExtField> {
    polynomial: Poly<F>,
    claims: Vec<(Point<Ext>, Ext)>,
    folding: usize,
    num_variables: usize,
}

impl<Ext> Layout<F, Ext> for SpartanEqLayout<Ext>
where
    Ext: ExtField,
{
    fn from_witness(_witness: p3_sumcheck::layout::Witness<F>) -> Self {
        unreachable!("SpartanEqLayout is built from Spartan point-evaluation claims")
    }

    fn new_witness(
        _tables: Vec<p3_sumcheck::layout::Table<F>>,
        _folding: usize,
    ) -> p3_sumcheck::layout::Witness<F> {
        unreachable!("SpartanEqLayout does not use table witnesses")
    }

    fn commit<Dft, MT, Challenger>(
        _dft: &Dft,
        _mmcs: &MT,
        _challenger: &mut Challenger,
        _witness: p3_sumcheck::layout::Witness<F>,
        _folding: usize,
        _starting_log_inv_rate: usize,
    ) -> (Self, MT::Commitment, MT::ProverData<DenseMatrix<F>>)
    where
        Dft: p3_dft::TwoAdicSubgroupDft<F>,
        MT: Mmcs<F>,
        Challenger: CanObserve<MT::Commitment>,
    {
        unreachable!("SpartanEqLayout commits through Plonky3WhirPcs::commit")
    }

    fn num_claims(&self) -> usize {
        self.claims.len()
    }

    fn strategy() -> LayoutStrategy {
        LayoutStrategy::new(true, VariableOrder::Prefix)
    }

    fn folding(&self) -> usize {
        self.folding
    }

    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn num_variables_table(&self, _id: usize) -> usize {
        self.num_variables
    }

    fn eval<Ch>(&mut self, _table_idx: usize, _polys: &[usize], _challenger: &mut Ch) -> Vec<Ext>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        unreachable!("SpartanEqLayout uses explicit point-evaluation claims")
    }

    fn add_virtual_eval<Ch>(&mut self, _challenger: &mut Ch) -> Ext
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        unreachable!("SpartanEqLayout carries commitment OOD claims explicitly")
    }

    fn into_sumcheck<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, Ext>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, Ext>, Point<Ext>)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let _profile = profile_scope("initial_sumcheck");
        let mut eq_statement = EqStatement::initialize(self.num_variables);
        for (point, eval) in self.claims {
            eq_statement.add_evaluated_constraint(point, eval);
        }
        let alpha = challenger.sample_algebra_element();
        let constraint = Constraint::new_eq_only(alpha, eq_statement);
        if self.num_variables > log2_strict_usize(<F as Field>::Packing::WIDTH) {
            let (weights, sum) = constraint.combine_new_packed();
            let evals = pack_base_evals::<Ext>(self.polynomial.as_slice());
            let product = ProductPolynomial::new_packed(VariableOrder::Prefix, evals, weights);
            let mut prover = SumcheckProver::new(product, sum);
            let point = prover.compute_sumcheck_polynomials(
                sumcheck_data,
                challenger,
                self.folding,
                pow_bits,
                None,
            );
            (prover, point)
        } else {
            let (weights, sum) = constraint.combine_new();
            let evals = Poly::new(
                self.polynomial
                    .as_slice()
                    .iter()
                    .map(|&value| Ext::from(value))
                    .collect(),
            );
            let product = ProductPolynomial::new_unpacked(VariableOrder::Prefix, evals, weights);
            let mut prover = SumcheckProver::new(product, sum);
            let point = prover.compute_sumcheck_polynomials(
                sumcheck_data,
                challenger,
                self.folding,
                pow_bits,
                None,
            );
            (prover, point)
        }
    }
}

fn pack_base_evals<Ext: ExtField>(values: &[F]) -> Poly<Ext::ExtensionPacking> {
    let _profile = profile_scope("pack_base_evals");
    Poly::new(
        <F as Field>::Packing::pack_slice(values)
            .iter()
            .map(|&packed| packed.into())
            .collect(),
    )
}

fn open_without_commit_observation<Ext>(
    config: &WhirPcsConfig,
    prover_data: Plonky3WhirProverData<Ext>,
    statement: &PcsStatement<PoseidonEngine<Ext>>,
    challenger: &mut PoseidonChallenger,
) -> Result<PoseidonWhirProof<Ext>, SpartanWhirError>
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<PoseidonCommitment>,
{
    let _profile = profile_scope("pcs_open");
    config.validate()?;
    if prover_data.num_variables != config.num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    {
        let _validate_profile = profile_scope("validate_user_point_claims");
        validate_user_point_claims(statement, &prover_data.polynomial, config.num_variables)?;
    }
    let pcs = build_poseidon_pcs::<Ext>(config)?;
    let mut claims = statement_point_claims(statement, config.num_variables)?;
    claims.extend(
        prover_data
            .ood_pairs
            .iter()
            .map(|(point, eval)| (Point::new(point.clone()), *eval)),
    );
    let layout = SpartanEqLayout {
        polynomial: Poly::new(prover_data.polynomial),
        claims,
        folding: config.whir.first_folding_factor(),
        num_variables: config.num_variables,
    };
    let mut proof = prover_data.proof;
    let merkle_tree = prover_data
        .merkle_tree
        .ok_or(SpartanWhirError::InvalidConfig)?;
    {
        let _prove_profile = profile_scope("p3_whir_prove");
        pcs.prove(&mut proof, challenger, layout, merkle_tree);
    }
    Ok(proof)
}

fn build_poseidon_pcs<Ext>(
    config: &WhirPcsConfig,
) -> Result<
    WhirProver<
        Ext,
        F,
        Radix2DFTSmallBatch<F>,
        PoseidonMmcs,
        PoseidonChallenger,
        SpartanEqLayout<Ext>,
    >,
    SpartanWhirError,
>
where
    Ext: ExtField,
{
    let _profile = profile_scope("build_poseidon_pcs");
    config.validate()?;
    let protocol_params = ProtocolParameters {
        starting_log_inv_rate: config.whir.starting_log_inv_rate,
        round_log_inv_rates: poseidon_round_log_inv_rates(
            config.num_variables,
            &config.whir.effective_folding_schedule(),
            config.whir.starting_log_inv_rate,
            config.whir.rs_domain_initial_reduction_factor,
            &config.whir.round_log_inv_rates,
        )?,
        folding_factor: map_poseidon_folding_schedule(&config.whir.effective_folding_schedule()),
        soundness_type: map_soundness_assumption(config.security.soundness_assumption),
        security_level: config.security.security_level_bits as usize,
        pow_bits: config.whir.pow_bits as usize,
    };
    let whir_config =
        Plonky3WhirConfig::<Ext, F, PoseidonChallenger>::new(config.num_variables, protocol_params);
    let mmcs = RcMmcs(InnerPoseidonMmcs::new(
        poseidon_merkle_hash(),
        poseidon_merkle_compress(),
        0,
    ));
    Ok(WhirProver::new(
        whir_config,
        Radix2DFTSmallBatch::<F>::default(),
        mmcs,
    ))
}

fn observe_poseidon_domain_separator<Ext>(
    pcs: &WhirProver<
        Ext,
        F,
        Radix2DFTSmallBatch<F>,
        PoseidonMmcs,
        PoseidonChallenger,
        SpartanEqLayout<Ext>,
    >,
    challenger: &mut PoseidonChallenger,
) where
    Ext: ExtField,
{
    let mut domain_separator = WhirDomainSeparator::new(Vec::new());
    pcs.add_domain_separator::<8>(&mut domain_separator);
    domain_separator.observe_domain_separator(challenger);
}

fn parse_initial_commitment<Ext>(
    num_variables: usize,
    whir_config: &PoseidonWhirConfig<Ext>,
    commitment: &PoseidonCommitment,
    proof: &PoseidonWhirProof<Ext>,
    challenger: &mut PoseidonChallenger,
) -> Result<ParsedCommitment<Ext, PoseidonCommitment>, SpartanWhirError>
where
    Ext: ExtField,
{
    if proof.initial_ood_answers.len() != whir_config.commitment_ood_samples {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let mut ood_statement = EqStatement::initialize(num_variables);
    for &eval in &proof.initial_ood_answers {
        let point =
            Point::expand_from_univariate(challenger.sample_algebra_element(), num_variables);
        challenger.observe_algebra_element(eval);
        ood_statement.add_evaluated_constraint(point, eval);
    }
    Ok(ParsedCommitment {
        root: commitment.clone(),
        ood_statement,
    })
}

fn build_eq_statement<Ext>(
    statement: &PcsStatement<PoseidonEngine<Ext>>,
    num_variables: usize,
) -> Result<EqStatement<Ext>, SpartanWhirError>
where
    Ext: ExtField,
{
    let claims = statement_point_claims(statement, num_variables)?;
    let mut eq_statement = EqStatement::initialize(num_variables);
    for (point, eval) in claims {
        eq_statement.add_evaluated_constraint(point, eval);
    }
    Ok(eq_statement)
}

fn statement_point_claims<Ext>(
    statement: &PcsStatement<PoseidonEngine<Ext>>,
    num_variables: usize,
) -> Result<Vec<(Point<Ext>, Ext)>, SpartanWhirError>
where
    Ext: ExtField,
{
    if !statement.linear_constraints().is_empty() {
        return Err(SpartanWhirError::UnsupportedStatementType);
    }
    statement
        .point_evals()
        .iter()
        .map(|claim| {
            if claim.point.0.len() != num_variables {
                return Err(SpartanWhirError::InvalidNumVariables);
            }
            Ok((Point::new(claim.point.0.clone()), claim.value))
        })
        .collect()
}

fn validate_user_point_claims<Ext>(
    statement: &PcsStatement<PoseidonEngine<Ext>>,
    polynomial: &[F],
    num_variables: usize,
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
{
    let poly = Poly::new(polynomial.to_vec());
    for (point, value) in statement_point_claims(statement, num_variables)? {
        if poly.eval_base(&point) != value {
            return Err(SpartanWhirError::WhirOpenFailed);
        }
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

pub(crate) fn poseidon_round_log_inv_rates(
    num_variables: usize,
    folding: &crate::WhirFoldingSchedule,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    explicit_round_log_inv_rates: &[usize],
) -> Result<Vec<usize>, SpartanWhirError> {
    let folding = map_poseidon_folding_schedule(folding);
    let (num_rounds, _) = folding.compute_number_of_rounds(num_variables);
    if !explicit_round_log_inv_rates.is_empty() {
        if explicit_round_log_inv_rates.len() != num_rounds {
            return Err(SpartanWhirError::InvalidConfig);
        }
        return Ok(explicit_round_log_inv_rates.to_vec());
    }
    let mut rates = Vec::with_capacity(num_rounds);
    let mut rate = starting_log_inv_rate;
    for round in 0..num_rounds {
        let reduction = if round == 0 {
            rs_domain_initial_reduction_factor
        } else {
            1
        };
        let folding_factor = folding.at_round(round);
        if reduction > rate + folding_factor {
            return Err(SpartanWhirError::InvalidConfig);
        }
        rate += folding_factor - reduction;
        rates.push(rate);
    }
    Ok(rates)
}

pub(crate) fn map_poseidon_folding_schedule(
    schedule: &crate::WhirFoldingSchedule,
) -> Plonky3FoldingFactor {
    match schedule {
        crate::WhirFoldingSchedule::Constant(factor) => Plonky3FoldingFactor::Constant(*factor),
        crate::WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => {
            Plonky3FoldingFactor::ConstantFromSecondRound(*first, *rest)
        }
        crate::WhirFoldingSchedule::PerRound(factors) => {
            Plonky3FoldingFactor::PerRound(factors.clone())
        }
    }
}

const fn map_soundness_assumption(soundness: SoundnessAssumption) -> Plonky3SecurityAssumption {
    match soundness {
        SoundnessAssumption::UniqueDecoding => Plonky3SecurityAssumption::UniqueDecoding,
        SoundnessAssumption::JohnsonBound => Plonky3SecurityAssumption::JohnsonBound,
        SoundnessAssumption::CapacityBound => Plonky3SecurityAssumption::CapacityBound,
    }
}
