use alloc::{rc::Rc, vec::Vec};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{dot_product, Field, PackedValue, PrimeCharacteristicRing};
use p3_matrix::{dense::DenseMatrix, Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    commit::commit_base,
    constraints::{statement::EqStatement, Constraint},
    lagrange::{extrapolate_01inf, lagrange_weights_01inf_multi},
    layout::{Layout, LayoutStrategy},
    product_polynomial::ProductPolynomial,
    strategy::{SumcheckProver, VariableOrder},
    svo::SvoPoint,
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

#[derive(Clone)]
struct SpartanEqLayout<Ext: ExtField> {
    polynomial: Poly<F>,
    claims: Vec<(Point<Ext>, Ext)>,
    folding: usize,
    num_variables: usize,
}

impl<Ext> SpartanEqLayout<Ext>
where
    Ext: ExtField,
{
    fn uses_svo(&self) -> bool {
        if self.folding <= 1 || self.folding >= self.num_variables {
            return false;
        }
        let packing_log = log2_strict_usize(<F as Field>::Packing::WIDTH);
        self.num_variables - self.folding >= packing_log
    }

    fn into_sumcheck_svo<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, Ext>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, Ext>, Point<Ext>)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let _profile = profile_scope("initial_sumcheck_svo");
        let alpha: Ext = challenger.sample_algebra_element();
        let claims = self
            .claims
            .into_iter()
            .zip(alpha.powers())
            .map(|((point, eval), coeff)| {
                let point = SvoPoint::new_packed(self.folding, &point);
                let (actual_eval, partials) = point.eval(&self.polynomial);
                debug_assert_eq!(actual_eval, eval);
                SvoClaim {
                    point,
                    coeff,
                    eval,
                    partials,
                }
            })
            .collect::<Vec<_>>();

        let mut claimed_sum = claims
            .iter()
            .map(|claim| claim.coeff * claim.eval)
            .sum::<Ext>();
        let accumulators = {
            let _profile = profile_scope("svo_accumulators");
            claims
                .iter()
                .map(|claim| calculate_svo_accumulators(claim))
                .collect::<Vec<_>>()
        };

        let mut rs = Vec::with_capacity(self.folding);
        for round_idx in 0..self.folding {
            let weights = lagrange_weights_01inf_multi(&rs);
            let (c0, c_inf) = accumulators.iter().fold(
                (Ext::ZERO, Ext::ZERO),
                |(c0, c_inf), claim_accumulators| {
                    let round = &claim_accumulators[round_idx];
                    (
                        c0 + dot_product::<Ext, _, _>(
                            round[0].iter().copied(),
                            weights.iter().copied(),
                        ),
                        c_inf
                            + dot_product::<Ext, _, _>(
                                round[1].iter().copied(),
                                weights.iter().copied(),
                            ),
                    )
                },
            );
            let r = sumcheck_data.observe_and_sample(challenger, c0, c_inf, pow_bits);
            claimed_sum = extrapolate_01inf(c0, claimed_sum - c0, c_inf, r);
            rs.push(r);
        }

        let rs = Point::new(rs);
        let (compressed_evals, residual_weights) = {
            let _profile = profile_scope("svo_residual_pack");
            let compressed_evals = self.polynomial.compress_prefix_to_packed(&rs, Ext::ONE);
            let residual_variables = self.num_variables - self.folding;
            let packing_log = log2_strict_usize(<F as Field>::Packing::WIDTH);
            let mut residual_weights =
                Ext::ExtensionPacking::zero_vec(1 << (residual_variables - packing_log));
            for claim in &claims {
                claim
                    .point
                    .accumulate_into_packed(&mut residual_weights, &rs, claim.coeff);
            }
            (compressed_evals, Poly::new(residual_weights))
        };

        let product = ProductPolynomial::new_packed(
            VariableOrder::Prefix,
            compressed_evals,
            residual_weights,
        );
        let prover = SumcheckProver::new(product, claimed_sum);
        (prover, rs)
    }

    fn into_sumcheck_packed_extension<Ch>(
        self,
        sumcheck_data: &mut SumcheckData<F, Ext>,
        pow_bits: usize,
        challenger: &mut Ch,
    ) -> (SumcheckProver<F, Ext>, Point<Ext>)
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let _profile = profile_scope("initial_sumcheck_packed_extension");
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

struct SvoClaim<Ext: ExtField> {
    point: SvoPoint<F, Ext>,
    coeff: Ext,
    eval: Ext,
    partials: Vec<Poly<Ext>>,
}

type SvoAccumulators<Ext> = Vec<[Vec<Ext>; 2]>;

// Plonky3's accumulator builder is crate-private. This local helper mirrors the
// prefix case only, which is the layout Spartan uses for caller-supplied claims.
fn calculate_svo_accumulators<Ext>(claim: &SvoClaim<Ext>) -> SvoAccumulators<Ext>
where
    Ext: ExtField,
{
    (0..claim.point.num_variables_svo())
        .map(|round_idx| {
            let active = claim.point.z_svo().get_subpoint_over_range(..round_idx + 1);
            calculate_svo_accumulator(
                claim.partials[round_idx].as_slice(),
                active.as_slice(),
                claim.coeff,
            )
        })
        .collect()
}

fn calculate_svo_accumulator<Ext>(
    partial_evals: &[Ext],
    active_point: &[Ext],
    coeff: Ext,
) -> [Vec<Ext>; 2]
where
    Ext: ExtField,
{
    let l = log2_strict_usize(partial_evals.len());
    debug_assert_eq!(active_point.len(), l);
    debug_assert!(l > 0);

    let eq = Poly::new_from_point(active_point, Ext::ONE);
    let grid_len = 3usize.pow(l as u32);
    let mut eq_grid = Ext::zero_vec(grid_len);
    let mut partial_grid = Ext::zero_vec(grid_len);
    let mut scratch = Ext::zero_vec(grid_len);
    evals_01inf_grid_into(eq.as_slice(), &mut eq_grid, &mut scratch);
    evals_01inf_grid_into(partial_evals, &mut partial_grid, &mut scratch);
    let stride = 3usize.pow((l - 1) as u32);

    let acc0 = eq_grid[..stride]
        .iter()
        .copied()
        .zip(partial_grid[..stride].iter().copied())
        .map(|(eq, eval)| coeff * eq * eval)
        .collect();
    let acc_inf = eq_grid[2 * stride..]
        .iter()
        .copied()
        .zip(partial_grid[2 * stride..].iter().copied())
        .map(|(eq, eval)| coeff * eq * eval)
        .collect();

    [acc0, acc_inf]
}

fn evals_01inf_grid_into<Ext>(boolean_evals: &[Ext], output: &mut [Ext], scratch: &mut [Ext])
where
    Ext: ExtField,
{
    let num_variables = log2_strict_usize(boolean_evals.len());
    let output_len = 3usize.pow(num_variables as u32);

    assert_eq!(output.len(), output_len);
    assert_eq!(scratch.len(), output_len);

    if num_variables == 0 {
        output[0] = boolean_evals[0];
        return;
    }

    let (mut cur, mut next) = if num_variables % 2 == 1 {
        scratch[..boolean_evals.len()].copy_from_slice(boolean_evals);
        (&mut scratch[..], &mut output[..])
    } else {
        output[..boolean_evals.len()].copy_from_slice(boolean_evals);
        (&mut output[..], &mut scratch[..])
    };

    for stage in 0..num_variables {
        let in_stride = 3usize.pow(stage as u32);
        let blocks = 1usize << (num_variables - stage - 1);
        let cur_slice = &cur[..blocks * 2 * in_stride];
        let next_slice = &mut next[..blocks * 3 * in_stride];

        for (c_chunk, n_chunk) in cur_slice
            .chunks_exact(2 * in_stride)
            .zip(next_slice.chunks_exact_mut(3 * in_stride))
        {
            for j in 0..in_stride {
                let f0 = c_chunk[j];
                let f1 = c_chunk[in_stride + j];
                n_chunk[3 * j] = f0;
                n_chunk[3 * j + 1] = f1;
                n_chunk[3 * j + 2] = f1 - f0;
            }
        }

        core::mem::swap(&mut cur, &mut next);
    }
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
        if self.uses_svo() {
            self.into_sumcheck_svo(sumcheck_data, pow_bits, challenger)
        } else {
            self.into_sumcheck_packed_extension(sumcheck_data, pow_bits, challenger)
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
    #[cfg(debug_assertions)]
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

#[cfg(debug_assertions)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{poseidon_challenger, QuarticBinExtension};

    type Ext = QuarticBinExtension;

    fn deterministic_poly(num_variables: usize) -> Poly<F> {
        Poly::new(
            (0..(1usize << num_variables))
                .map(|i| F::from_u32((17 * i as u32 + 5) % 97))
                .collect(),
        )
    }

    fn deterministic_point(num_variables: usize, seed: u32) -> Point<Ext> {
        Point::new(
            (0..num_variables)
                .map(|i| Ext::from(F::from_u32(seed + 11 * i as u32 + 3)))
                .collect(),
        )
    }

    fn deterministic_claims(poly: &Poly<F>, count: usize) -> Vec<(Point<Ext>, Ext)> {
        (0..count)
            .map(|i| {
                let point = deterministic_point(poly.num_variables(), 19 * i as u32 + 7);
                let eval = poly.eval_base(&point);
                (point, eval)
            })
            .collect()
    }

    fn compare_svo_with_packed_extension(
        num_variables: usize,
        folding: usize,
        claims: Vec<(Point<Ext>, Ext)>,
    ) {
        let polynomial = deterministic_poly(num_variables);
        let layout = SpartanEqLayout {
            polynomial,
            claims,
            folding,
            num_variables,
        };
        assert!(layout.uses_svo());

        let mut svo_data = SumcheckData::<F, Ext>::default();
        let mut baseline_data = SumcheckData::<F, Ext>::default();
        let mut svo_challenger = poseidon_challenger();
        let mut baseline_challenger = poseidon_challenger();

        let (mut svo_prover, svo_point) =
            layout
                .clone()
                .into_sumcheck_svo(&mut svo_data, 0, &mut svo_challenger);
        let (mut baseline_prover, baseline_point) =
            layout.into_sumcheck_packed_extension(&mut baseline_data, 0, &mut baseline_challenger);

        assert_eq!(svo_point, baseline_point);
        assert_eq!(
            svo_data.polynomial_evaluations,
            baseline_data.polynomial_evaluations
        );
        assert_eq!(svo_data.pow_witnesses, baseline_data.pow_witnesses);
        assert_eq!(svo_prover.num_variables(), baseline_prover.num_variables());

        let remaining_rounds = svo_prover.num_variables();
        let svo_tail = svo_prover.compute_sumcheck_polynomials(
            &mut svo_data,
            &mut svo_challenger,
            remaining_rounds,
            0,
            None,
        );
        let baseline_tail = baseline_prover.compute_sumcheck_polynomials(
            &mut baseline_data,
            &mut baseline_challenger,
            remaining_rounds,
            0,
            None,
        );

        assert_eq!(svo_tail, baseline_tail);
        assert_eq!(
            svo_data.polynomial_evaluations,
            baseline_data.polynomial_evaluations
        );
        assert_eq!(svo_prover.evals(), baseline_prover.evals());
    }

    #[test]
    fn svo_initial_sumcheck_matches_baseline_for_one_claim() {
        let poly = deterministic_poly(8);
        compare_svo_with_packed_extension(8, 3, deterministic_claims(&poly, 1));
    }

    #[test]
    fn svo_initial_sumcheck_matches_baseline_for_multiple_claims() {
        let poly = deterministic_poly(9);
        compare_svo_with_packed_extension(9, 4, deterministic_claims(&poly, 5));
    }

    #[test]
    fn svo_initial_sumcheck_preserves_user_then_ood_claim_order() {
        let poly = deterministic_poly(9);
        let mut user_claims = deterministic_claims(&poly, 2);
        let ood_claims = deterministic_claims(&poly, 3)
            .into_iter()
            .enumerate()
            .map(|(i, _)| {
                let point = deterministic_point(poly.num_variables(), 101 + 23 * i as u32);
                let eval = poly.eval_base(&point);
                (point, eval)
            });
        user_claims.extend(ood_claims);

        compare_svo_with_packed_extension(9, 4, user_claims);
    }

    #[test]
    fn initial_sumcheck_uses_baseline_when_svo_residual_is_too_small() {
        let num_variables = 3;
        let folding = 2;
        let polynomial = deterministic_poly(num_variables);
        let layout = SpartanEqLayout {
            claims: deterministic_claims(&polynomial, 1),
            polynomial,
            folding,
            num_variables,
        };
        assert!(!layout.uses_svo());

        let mut data = SumcheckData::<F, Ext>::default();
        let mut challenger = poseidon_challenger();
        let (prover, point) = layout.into_sumcheck(&mut data, 0, &mut challenger);

        assert_eq!(point.num_variables(), folding);
        assert_eq!(data.num_rounds(), folding);
        assert_eq!(prover.num_variables(), num_variables - folding);
    }

    #[test]
    fn initial_sumcheck_keeps_single_fold_on_baseline_path() {
        let num_variables = 8;
        let folding = 1;
        let polynomial = deterministic_poly(num_variables);
        let layout = SpartanEqLayout {
            claims: deterministic_claims(&polynomial, 2),
            polynomial,
            folding,
            num_variables,
        };
        assert!(!layout.uses_svo());
    }
}
