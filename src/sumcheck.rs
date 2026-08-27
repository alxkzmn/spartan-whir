use alloc::{vec, vec::Vec};

use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field, HornerIter};
use p3_maybe_rayon::prelude::*;
use p3_sumcheck::generic_degree::RoundPolyInterpolator;
use p3_sumcheck::strategy::sumcheck_coefficients_prefix;
use serde::{Deserialize, Serialize};

use crate::sumcheck_replay::{observe_sumcheck_claim, replay_compact_rounds};
use crate::{CubicRoundPoly, MultilinearPoint, QuadraticRoundPoly, R1csShape, SpartanWhirError};

const SUMCHECK_PARALLEL_ROUND_MIN_PAIRS: usize = 1 << 14;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OuterSumcheckProof<F> {
    pub rounds: Vec<CubicRoundPoly<F>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerSumcheckProof<F> {
    pub rounds: Vec<QuadraticRoundPoly<F>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkOuterSumcheckProof<F> {
    pub mu_tilde: F,
    /// Compact degree-seven rounds: `[h(0), h(2), ..., h(7)]`.
    pub rounds: Vec<Vec<F>>,
}

pub(crate) struct ZkOuterProverOutput<EF> {
    pub proof: ZkOuterSumcheckProof<EF>,
    pub point: MultilinearPoint<EF>,
    pub masked_claims: (EF, EF, EF),
    pub outer_mask_evals: Vec<EF>,
}

pub fn prove_outer<F, EF, C>(
    shape: &R1csShape<F>,
    az: &[EF],
    bz: &[EF],
    cz: &[EF],
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    validate_outer_inputs(shape, az, bz, cz, tau)?;

    prove_outer_with_tables(
        shape,
        az.to_vec(),
        bz.to_vec(),
        cz.to_vec(),
        tau,
        challenger,
    )
}

pub fn prove_outer_split_eq_owned<F, EF, C>(
    shape: &R1csShape<F>,
    az: Vec<EF>,
    bz: Vec<EF>,
    cz: Vec<EF>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    validate_outer_inputs(shape, &az, &bz, &cz, tau)?;

    prove_outer_split_eq_with_tables(shape, az, bz, cz, tau, challenger)
}

pub fn prove_outer_split_eq_base_first_owned<F, EF, C>(
    shape: &R1csShape<F>,
    az: Vec<F>,
    bz: Vec<F>,
    cz: Vec<F>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    prove_outer_split_eq_base_first_owned_unchecked(shape, az, bz, cz, tau, challenger)
}

pub(crate) fn prove_outer_split_eq_base_first_owned_unchecked<F, EF, C>(
    shape: &R1csShape<F>,
    az: Vec<F>,
    bz: Vec<F>,
    cz: Vec<F>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    validate_outer_base_inputs(shape, &az, &bz, &cz, tau)?;

    prove_outer_split_eq_base_first_with_tables(shape, az, bz, cz, tau, challenger)
}

fn prove_outer_with_tables<F, EF, C>(
    _shape: &R1csShape<F>,
    mut az_tab: Vec<EF>,
    mut bz_tab: Vec<EF>,
    mut cz_tab: Vec<EF>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    let mut eq = {
        let _profile = crate::profiling::profile_scope("outer_eq_table_build");
        crate::EqPolynomial::evals_from_point_with_base::<F>(&tau.0)
    };
    let mut rounds = Vec::with_capacity(tau.0.len());
    let mut r_x = Vec::with_capacity(tau.0.len());
    let mut claim = EF::ZERO;
    observe_sumcheck_claim::<F, EF, C>(challenger, claim);

    for _ in 0..tau.0.len() {
        let half = eq.len() / 2;
        let (h0, h2, h3) = if should_parallelize_sumcheck_round(half) {
            (0..half)
                .into_par_iter()
                .map(|i| outer_round_partial(i, half, &eq, &az_tab, &bz_tab, &cz_tab))
                .par_fold_reduce(
                    || (EF::ZERO, EF::ZERO, EF::ZERO),
                    add_cubic_accumulators,
                    add_cubic_accumulators,
                )
        } else {
            (0..half)
                .map(|i| outer_round_partial(i, half, &eq, &az_tab, &bz_tab, &cz_tab))
                .fold((EF::ZERO, EF::ZERO, EF::ZERO), add_cubic_accumulators)
        };

        let round_poly = CubicRoundPoly([h0, h2, h3]);
        challenger.observe_algebra_slice(&round_poly.0);
        let r_i = challenger.sample_algebra_element::<EF>();

        claim = round_poly.evaluate_at(r_i, claim);
        rounds.push(round_poly);
        r_x.push(r_i);

        bind_half(&mut eq, r_i)?;
        bind_half(&mut az_tab, r_i)?;
        bind_half(&mut bz_tab, r_i)?;
        bind_half(&mut cz_tab, r_i)?;
    }

    if az_tab.len() != 1 || bz_tab.len() != 1 || cz_tab.len() != 1 {
        return Err(SpartanWhirError::SumcheckFailed);
    }

    Ok((
        OuterSumcheckProof { rounds },
        MultilinearPoint(r_x),
        (az_tab[0], bz_tab[0], cz_tab[0]),
    ))
}

fn prove_outer_split_eq_with_tables<F, EF, C>(
    _shape: &R1csShape<F>,
    mut az_tab: Vec<EF>,
    mut bz_tab: Vec<EF>,
    mut cz_tab: Vec<EF>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    let mut eq = {
        let _profile = crate::profiling::profile_scope("outer_split_eq_setup");
        SplitEqSumcheck::<EF>::new(&tau.0)
    };
    let mut rounds = Vec::with_capacity(tau.0.len());
    let mut r_x = Vec::with_capacity(tau.0.len());
    let mut claim = EF::ZERO;
    observe_sumcheck_claim::<F, EF, C>(challenger, claim);

    for round_idx in 0..tau.0.len() {
        let (h0, h2, h3) = eq.evaluation_points(round_idx, &az_tab, &bz_tab, &cz_tab);

        let round_poly = CubicRoundPoly([h0, h2, h3]);
        challenger.observe_algebra_slice(&round_poly.0);
        let r_i = challenger.sample_algebra_element::<EF>();

        claim = round_poly.evaluate_at(r_i, claim);
        rounds.push(round_poly);
        r_x.push(r_i);

        bind_half(&mut az_tab, r_i)?;
        bind_half(&mut bz_tab, r_i)?;
        bind_half(&mut cz_tab, r_i)?;
        eq.bind(r_i);
    }

    if az_tab.len() != 1 || bz_tab.len() != 1 || cz_tab.len() != 1 {
        return Err(SpartanWhirError::SumcheckFailed);
    }

    Ok((
        OuterSumcheckProof { rounds },
        MultilinearPoint(r_x),
        (az_tab[0], bz_tab[0], cz_tab[0]),
    ))
}

fn prove_outer_split_eq_base_first_with_tables<F, EF, C>(
    _shape: &R1csShape<F>,
    az_tab: Vec<F>,
    bz_tab: Vec<F>,
    cz_tab: Vec<F>,
    tau: &MultilinearPoint<EF>,
    challenger: &mut C,
) -> Result<(OuterSumcheckProof<EF>, MultilinearPoint<EF>, (EF, EF, EF)), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    observe_sumcheck_claim::<F, EF, C>(challenger, EF::ZERO);

    if tau.0.is_empty() {
        if az_tab.len() != 1 || bz_tab.len() != 1 || cz_tab.len() != 1 {
            return Err(SpartanWhirError::SumcheckFailed);
        }
        return Ok((
            OuterSumcheckProof { rounds: Vec::new() },
            MultilinearPoint(Vec::new()),
            (
                EF::from(az_tab[0]),
                EF::from(bz_tab[0]),
                EF::from(cz_tab[0]),
            ),
        ));
    }

    let mut eq = {
        let _profile = crate::profiling::profile_scope("outer_split_eq_setup");
        SplitEqSumcheck::<EF>::new(&tau.0)
    };
    let mut rounds = Vec::with_capacity(tau.0.len());
    let mut r_x = Vec::with_capacity(tau.0.len());
    let mut claim = EF::ZERO;

    let (h0, h2, h3) = {
        let _profile = crate::profiling::profile_detail_scope("outer_round_coefficients_base");
        eq.evaluation_points_base_first(&az_tab, &bz_tab, &cz_tab)
    };
    let round_poly = CubicRoundPoly([h0, h2, h3]);
    challenger.observe_algebra_slice(&round_poly.0);
    let r_i = challenger.sample_algebra_element::<EF>();

    claim = round_poly.evaluate_at(r_i, claim);
    rounds.push(round_poly);
    r_x.push(r_i);

    let (mut az_tab, mut bz_tab, mut cz_tab) = {
        let _profile = crate::profiling::profile_detail_scope("outer_round_bind_base");
        let (az_tab, bz_tab, cz_tab) =
            bind_three_halves_base_to_extension(&az_tab, &bz_tab, &cz_tab, r_i)?;
        eq.bind(r_i);
        (az_tab, bz_tab, cz_tab)
    };

    for round_idx in 1..tau.0.len() {
        let (h0, h2, h3) = {
            let _profile = crate::profiling::profile_detail_scope("outer_round_coefficients_ext");
            eq.evaluation_points(round_idx, &az_tab, &bz_tab, &cz_tab)
        };

        let round_poly = CubicRoundPoly([h0, h2, h3]);
        challenger.observe_algebra_slice(&round_poly.0);
        let r_i = challenger.sample_algebra_element::<EF>();

        claim = round_poly.evaluate_at(r_i, claim);
        rounds.push(round_poly);
        r_x.push(r_i);

        {
            let _profile = crate::profiling::profile_detail_scope("outer_round_bind_ext");
            bind_three_halves(&mut az_tab, &mut bz_tab, &mut cz_tab, r_i)?;
            eq.bind(r_i);
        }
    }

    if az_tab.len() != 1 || bz_tab.len() != 1 || cz_tab.len() != 1 {
        return Err(SpartanWhirError::SumcheckFailed);
    }

    Ok((
        OuterSumcheckProof { rounds },
        MultilinearPoint(r_x),
        (az_tab[0], bz_tab[0], cz_tab[0]),
    ))
}

pub fn verify_outer<F, EF, C>(
    proof: &OuterSumcheckProof<EF>,
    initial_claim: EF,
    expected_rounds: usize,
    challenger: &mut C,
) -> Result<(MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    replay_compact_rounds::<F, EF, C, _>(
        &proof.rounds,
        initial_claim,
        expected_rounds,
        3,
        challenger,
    )
}

/// Construction 11.4's witness-hiding outer sumcheck.
///
/// `inner_masks` are ordered `A rounds | B rounds | C rounds`. Every mask is
/// cubic and vanishes at zero and one. `outer_masks` contains one degree-seven
/// mask per outer round.
pub(crate) fn prove_outer_zk_base_first_unchecked<F, EF, C>(
    shape: &R1csShape<F>,
    az_tab: Vec<F>,
    bz_tab: Vec<F>,
    cz_tab: Vec<F>,
    inner_masks: &[Vec<EF>],
    outer_masks: &[Vec<EF>],
    challenger: &mut C,
) -> Result<ZkOuterProverOutput<EF>, SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    let num_rounds = shape.num_cons.ilog2() as usize;
    if az_tab.len() != shape.num_cons
        || bz_tab.len() != shape.num_cons
        || cz_tab.len() != shape.num_cons
        || inner_masks.len() != 3 * num_rounds
        || outer_masks.len() != num_rounds
        || inner_masks.iter().any(|mask| {
            mask.len() != 4
                || mask.first().copied() != Some(EF::ZERO)
                || mask.iter().copied().sum::<EF>() != EF::ZERO
        })
        || outer_masks.iter().any(|mask| mask.len() != 8)
    {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let mu_tilde = if num_rounds == 0 {
        EF::ZERO
    } else {
        let endpoint_sum = outer_masks
            .iter()
            .map(|mask| mask[0].double() + mask[1..].iter().copied().sum::<EF>())
            .sum::<EF>();
        EF::TWO.exp_u64((num_rounds - 1) as u64) * endpoint_sum
    };
    challenger.observe_algebra_element(mu_tilde);
    let epsilon = challenger.sample_algebra_element::<EF>();
    let tau = MultilinearPoint(
        (0..num_rounds)
            .map(|_| challenger.sample_algebra_element::<EF>())
            .collect(),
    );

    if num_rounds == 0 {
        return Ok(ZkOuterProverOutput {
            proof: ZkOuterSumcheckProof {
                mu_tilde,
                rounds: Vec::new(),
            },
            point: MultilinearPoint(Vec::new()),
            masked_claims: (
                EF::from(az_tab[0]),
                EF::from(bz_tab[0]),
                EF::from(cz_tab[0]),
            ),
            outer_mask_evals: Vec::new(),
        });
    }

    let mut eq = SplitEqSumcheck::<EF>::new(&tau.0);
    let degree_three = RoundPolyInterpolator::new(3);
    let degree_seven = RoundPolyInterpolator::new(7);
    let nodes = [0usize, 2, 3, 4, 5, 6, 7];
    let mut rounds = Vec::with_capacity(num_rounds);
    let mut point = Vec::with_capacity(num_rounds);
    let mut full_claim = mu_tilde;
    let mut base_claim = EF::ZERO;
    let mut inner_past = [EF::ZERO; 3];
    let mut outer_past = EF::ZERO;
    let mut outer_future_endpoints = outer_masks
        .iter()
        .map(|mask| mask[0].double() + mask[1..].iter().copied().sum::<EF>())
        .sum::<EF>();

    let (base_compact, correction_compact) = {
        let _profile = crate::profiling::profile_scope("zk_outer_first_round_compute");
        let ((h0, h2, h3), moments) = join(
            || eq.evaluation_points_base_first(&az_tab, &bz_tab, &cz_tab),
            || eq.linear_moments_base_first(&az_tab, &bz_tab),
        );
        let base_compact = degree_three.extend_evals(&[h0, h2, h3], base_claim, 7);
        let correction =
            masked_outer_correction_evals(&eq, moments, 0, inner_masks, &inner_past, &nodes);
        (base_compact, correction)
    };
    outer_future_endpoints -=
        outer_masks[0][0].double() + outer_masks[0][1..].iter().copied().sum::<EF>();
    let outer_compact = outer_mask_round_evals(
        &outer_masks[0],
        outer_past,
        outer_future_endpoints,
        num_rounds - 1,
        &nodes,
    );
    let wire = base_compact
        .iter()
        .zip(&correction_compact)
        .zip(&outer_compact)
        .map(|((&base, &correction), &outer)| epsilon * (base + correction) + outer)
        .collect::<Vec<_>>();
    challenger.observe_algebra_slice(&wire);
    let challenge = if num_rounds == 1 {
        sample_non_boolean::<F, EF, C>(challenger)
    } else {
        challenger.sample_algebra_element::<EF>()
    };
    full_claim = degree_seven.eval(&wire, full_claim, challenge);
    base_claim = degree_three.eval(&base_compact[..3], base_claim, challenge);
    update_mask_accumulators(
        0,
        challenge,
        inner_masks,
        outer_masks,
        &mut inner_past,
        &mut outer_past,
    );
    rounds.push(wire);
    point.push(challenge);

    eq.bind(challenge);
    let first_challenge = challenge;
    let (mut az_tab, mut bz_tab, mut cz_tab) = if num_rounds == 1 {
        let _profile = crate::profiling::profile_scope("zk_outer_first_round_bind");
        bind_three_halves_base_to_extension(&az_tab, &bz_tab, &cz_tab, first_challenge)?
    } else {
        let round = 1;
        let (base_compact, wire, challenge) = {
            let _profile = crate::profiling::profile_scope("zk_outer_second_round_compute_base");
            let ((h0, h2, h3), moments) = eq.evaluation_points_and_linear_moments_base_second(
                first_challenge,
                &az_tab,
                &bz_tab,
                &cz_tab,
            );
            let base_compact = degree_three.extend_evals(&[h0, h2, h3], base_claim, 7);
            let correction_compact = masked_outer_correction_evals(
                &eq,
                moments,
                round,
                inner_masks,
                &inner_past,
                &nodes,
            );
            outer_future_endpoints -= outer_masks[round][0].double()
                + outer_masks[round][1..].iter().copied().sum::<EF>();
            let outer_compact = outer_mask_round_evals(
                &outer_masks[round],
                outer_past,
                outer_future_endpoints,
                num_rounds - round - 1,
                &nodes,
            );
            let wire = base_compact
                .iter()
                .zip(&correction_compact)
                .zip(&outer_compact)
                .map(|((&base, &correction), &outer)| epsilon * (base + correction) + outer)
                .collect::<Vec<_>>();
            challenger.observe_algebra_slice(&wire);
            let challenge = if num_rounds == 2 {
                sample_non_boolean::<F, EF, C>(challenger)
            } else {
                challenger.sample_algebra_element::<EF>()
            };
            (base_compact, wire, challenge)
        };
        full_claim = degree_seven.eval(&wire, full_claim, challenge);
        base_claim = degree_three.eval(&base_compact[..3], base_claim, challenge);
        update_mask_accumulators(
            round,
            challenge,
            inner_masks,
            outer_masks,
            &mut inner_past,
            &mut outer_past,
        );
        rounds.push(wire);
        point.push(challenge);

        let _profile = crate::profiling::profile_scope("zk_outer_first_two_rounds_bind");
        let tables = bind_three_quarters_base_to_extension(
            &az_tab,
            &bz_tab,
            &cz_tab,
            first_challenge,
            challenge,
        )?;
        eq.bind(challenge);
        tables
    };

    for round in 2..num_rounds {
        let (base_compact, wire, challenge) = {
            let _profile = crate::profiling::profile_scope("zk_outer_round_compute");
            let ((h0, h2, h3), moments) = join(
                || eq.evaluation_points(round, &az_tab, &bz_tab, &cz_tab),
                || eq.linear_moments(&az_tab, &bz_tab),
            );
            let base_compact = degree_three.extend_evals(&[h0, h2, h3], base_claim, 7);
            let correction_compact = masked_outer_correction_evals(
                &eq,
                moments,
                round,
                inner_masks,
                &inner_past,
                &nodes,
            );
            outer_future_endpoints -= outer_masks[round][0].double()
                + outer_masks[round][1..].iter().copied().sum::<EF>();
            let outer_compact = outer_mask_round_evals(
                &outer_masks[round],
                outer_past,
                outer_future_endpoints,
                num_rounds - round - 1,
                &nodes,
            );
            let wire = base_compact
                .iter()
                .zip(&correction_compact)
                .zip(&outer_compact)
                .map(|((&base, &correction), &outer)| epsilon * (base + correction) + outer)
                .collect::<Vec<_>>();
            challenger.observe_algebra_slice(&wire);
            let challenge = if round + 1 == num_rounds {
                sample_non_boolean::<F, EF, C>(challenger)
            } else {
                challenger.sample_algebra_element::<EF>()
            };
            (base_compact, wire, challenge)
        };
        full_claim = degree_seven.eval(&wire, full_claim, challenge);
        base_claim = degree_three.eval(&base_compact[..3], base_claim, challenge);
        update_mask_accumulators(
            round,
            challenge,
            inner_masks,
            outer_masks,
            &mut inner_past,
            &mut outer_past,
        );
        rounds.push(wire);
        point.push(challenge);

        {
            let _profile = crate::profiling::profile_scope("zk_outer_round_bind");
            bind_three_halves(&mut az_tab, &mut bz_tab, &mut cz_tab, challenge)?;
            eq.bind(challenge);
        }
    }

    let masked_claims = (
        az_tab[0] + inner_past[0],
        bz_tab[0] + inner_past[1],
        cz_tab[0] + inner_past[2],
    );
    let expected = epsilon
        * (masked_claims.0 * masked_claims.1 - masked_claims.2)
        * eq_point_eval_local(&tau.0, &point)
        + outer_past;
    debug_assert_eq!(full_claim, expected);

    Ok(ZkOuterProverOutput {
        proof: ZkOuterSumcheckProof { mu_tilde, rounds },
        point: MultilinearPoint(point.clone()),
        masked_claims,
        outer_mask_evals: outer_masks
            .iter()
            .zip(point)
            .map(|(mask, challenge)| mask.iter().copied().horner::<EF, EF>(challenge))
            .collect(),
    })
}

pub(crate) fn verify_outer_zk<F, EF, C>(
    proof: &ZkOuterSumcheckProof<EF>,
    masked_claims: (EF, EF, EF),
    outer_mask_evals: &[EF],
    expected_rounds: usize,
    challenger: &mut C,
) -> Result<MultilinearPoint<EF>, SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    if proof.rounds.len() != expected_rounds || outer_mask_evals.len() != expected_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }
    challenger.observe_algebra_element(proof.mu_tilde);
    let epsilon = challenger.sample_algebra_element::<EF>();
    let tau = (0..expected_rounds)
        .map(|_| challenger.sample_algebra_element::<EF>())
        .collect::<Vec<_>>();
    let interpolator = RoundPolyInterpolator::new(7);
    let mut claim = proof.mu_tilde;
    let mut point = Vec::with_capacity(expected_rounds);
    for (round, wire) in proof.rounds.iter().enumerate() {
        if wire.len() != 7 {
            return Err(SpartanWhirError::InvalidRoundPolynomial);
        }
        challenger.observe_algebra_slice(wire);
        let challenge = if round + 1 == expected_rounds {
            sample_non_boolean::<F, EF, C>(challenger)
        } else {
            challenger.sample_algebra_element::<EF>()
        };
        claim = interpolator.eval(wire, claim, challenge);
        point.push(challenge);
    }
    let expected = epsilon
        * (masked_claims.0 * masked_claims.1 - masked_claims.2)
        * eq_point_eval_local(&tau, &point)
        + outer_mask_evals.iter().copied().sum::<EF>();
    if claim != expected {
        return Err(SpartanWhirError::SumcheckFailed);
    }
    Ok(MultilinearPoint(point))
}

pub fn prove_inner<F, EF, C>(
    shape: &R1csShape<F>,
    initial_claim: EF,
    poly_abc: &[EF],
    z: &[EF],
    challenger: &mut C,
) -> Result<(InnerSumcheckProof<EF>, MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    if poly_abc.len() != z.len() || poly_abc.is_empty() || !poly_abc.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    prove_inner_with_tables(initial_claim, poly_abc.to_vec(), z.to_vec(), challenger)
}

fn prove_inner_with_tables<F, EF, C>(
    initial_claim: EF,
    mut abc_tab: Vec<EF>,
    mut z_tab: Vec<EF>,
    challenger: &mut C,
) -> Result<(InnerSumcheckProof<EF>, MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    if abc_tab.len() != z_tab.len() || abc_tab.is_empty() || !abc_tab.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let num_rounds = abc_tab.len().ilog2() as usize;

    let mut rounds = Vec::with_capacity(num_rounds);
    let mut r_y = Vec::with_capacity(num_rounds);
    let mut claim = initial_claim;
    observe_sumcheck_claim::<F, EF, C>(challenger, claim);

    for _ in 0..num_rounds {
        let (h0, h2) = inner_round_coefficients::<F, EF>(&z_tab, &abc_tab, claim);

        let round_poly = QuadraticRoundPoly([h0, h2]);
        challenger.observe_algebra_slice(&round_poly.0);
        let r_i = challenger.sample_algebra_element::<EF>();

        claim = round_poly.evaluate_at(r_i, claim);
        rounds.push(round_poly);
        r_y.push(r_i);

        bind_half(&mut abc_tab, r_i)?;
        bind_half(&mut z_tab, r_i)?;
    }

    if z_tab.len() != 1 {
        return Err(SpartanWhirError::SumcheckFailed);
    }

    Ok((
        InnerSumcheckProof { rounds },
        MultilinearPoint(r_y),
        z_tab[0],
    ))
}

pub fn prove_inner_base_first<F, EF, C>(
    shape: &R1csShape<F>,
    initial_claim: EF,
    poly_abc: &[EF],
    z: &[F],
    challenger: &mut C,
) -> Result<(InnerSumcheckProof<EF>, MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    prove_inner_base_first_unchecked(initial_claim, poly_abc.to_vec(), z, challenger)
}

pub(crate) fn prove_inner_base_first_unchecked<F, EF, C>(
    initial_claim: EF,
    poly_abc: Vec<EF>,
    z: &[F],
    challenger: &mut C,
) -> Result<(InnerSumcheckProof<EF>, MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
    C: FieldChallenger<F>,
{
    if poly_abc.len() != z.len() || poly_abc.is_empty() || !poly_abc.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let num_rounds = poly_abc.len().ilog2() as usize;
    let mut abc_tab = poly_abc;

    let mut rounds = Vec::with_capacity(num_rounds);
    let mut r_y = Vec::with_capacity(num_rounds);
    let mut claim = initial_claim;
    observe_sumcheck_claim::<F, EF, C>(challenger, claim);

    if num_rounds == 0 {
        return Ok((
            InnerSumcheckProof { rounds },
            MultilinearPoint(r_y),
            EF::from(z[0]),
        ));
    }

    let (h0, h2) = {
        let _profile = crate::profiling::profile_detail_scope("inner_round_coefficients_base");
        inner_round_coefficients_base::<F, EF>(&z[..], &abc_tab, claim)
    };
    let round_poly = QuadraticRoundPoly([h0, h2]);
    challenger.observe_algebra_slice(&round_poly.0);
    let r_i = challenger.sample_algebra_element::<EF>();

    claim = round_poly.evaluate_at(r_i, claim);
    rounds.push(round_poly);
    r_y.push(r_i);

    let mut z_tab = {
        let _profile = crate::profiling::profile_detail_scope("inner_round_bind_base");
        bind_half_extension_and_base_to_extension(&mut abc_tab, z, r_i)?
    };

    for _ in 1..num_rounds {
        let (h0, h2) = {
            let _profile = crate::profiling::profile_detail_scope("inner_round_coefficients_ext");
            inner_round_coefficients::<F, EF>(&z_tab, &abc_tab, claim)
        };

        let round_poly = QuadraticRoundPoly([h0, h2]);
        challenger.observe_algebra_slice(&round_poly.0);
        let r_i = challenger.sample_algebra_element::<EF>();

        claim = round_poly.evaluate_at(r_i, claim);
        rounds.push(round_poly);
        r_y.push(r_i);

        {
            let _profile = crate::profiling::profile_detail_scope("inner_round_bind_ext");
            bind_two_halves(&mut abc_tab, &mut z_tab, r_i)?;
        }
    }

    if z_tab.len() != 1 {
        return Err(SpartanWhirError::SumcheckFailed);
    }

    Ok((
        InnerSumcheckProof { rounds },
        MultilinearPoint(r_y),
        z_tab[0],
    ))
}

pub fn verify_inner<F, EF, C>(
    proof: &InnerSumcheckProof<EF>,
    initial_claim: EF,
    expected_rounds: usize,
    challenger: &mut C,
) -> Result<(MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    replay_compact_rounds::<F, EF, C, _>(
        &proof.rounds,
        initial_claim,
        expected_rounds,
        2,
        challenger,
    )
}

fn validate_outer_inputs<F, EF>(
    shape: &R1csShape<F>,
    az: &[EF],
    bz: &[EF],
    cz: &[EF],
    tau: &MultilinearPoint<EF>,
) -> Result<(), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let n = shape.num_cons;
    if !n.is_power_of_two() || az.len() != n || bz.len() != n || cz.len() != n {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }
    if tau.0.len() != n.ilog2() as usize {
        return Err(SpartanWhirError::InvalidRoundCount);
    }
    Ok(())
}

fn validate_outer_base_inputs<F, EF>(
    shape: &R1csShape<F>,
    az: &[F],
    bz: &[F],
    cz: &[F],
    tau: &MultilinearPoint<EF>,
) -> Result<(), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let n = shape.num_cons;
    if !n.is_power_of_two() || az.len() != n || bz.len() != n || cz.len() != n {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }
    if tau.0.len() != n.ilog2() as usize {
        return Err(SpartanWhirError::InvalidRoundCount);
    }
    Ok(())
}

fn outer_round_partial<EF>(
    i: usize,
    half: usize,
    eq: &[EF],
    az_tab: &[EF],
    bz_tab: &[EF],
    cz_tab: &[EF],
) -> (EF, EF, EF)
where
    EF: Field,
{
    let eq0 = eq[i];
    let eq1 = eq[i + half];
    let a0 = az_tab[i];
    let a1 = az_tab[i + half];
    let b0 = bz_tab[i];
    let b1 = bz_tab[i + half];
    let c0 = cz_tab[i];
    let c1 = cz_tab[i + half];

    let eq2 = eq1.double() - eq0;
    let a2 = a1.double() - a0;
    let b2 = b1.double() - b0;
    let c2 = c1.double() - c0;

    let eq3 = eq2 + (eq1 - eq0);
    let a3 = a2 + (a1 - a0);
    let b3 = b2 + (b1 - b0);
    let c3 = c2 + (c1 - c0);

    (
        eq0 * (a0 * b0 - c0),
        eq2 * (a2 * b2 - c2),
        eq3 * (a3 * b3 - c3),
    )
}

#[derive(Clone, Copy)]
struct LinearMoments<EF> {
    a0: EF,
    a_delta: EF,
    b0: EF,
    b_delta: EF,
    weight: EF,
}

fn zero_linear_moments<EF: Field>() -> LinearMoments<EF> {
    LinearMoments {
        a0: EF::ZERO,
        a_delta: EF::ZERO,
        b0: EF::ZERO,
        b_delta: EF::ZERO,
        weight: EF::ZERO,
    }
}

fn add_linear_moments<EF: Field>(
    lhs: LinearMoments<EF>,
    rhs: LinearMoments<EF>,
) -> LinearMoments<EF> {
    LinearMoments {
        a0: lhs.a0 + rhs.a0,
        a_delta: lhs.a_delta + rhs.a_delta,
        b0: lhs.b0 + rhs.b0,
        b_delta: lhs.b_delta + rhs.b_delta,
        weight: lhs.weight + rhs.weight,
    }
}

fn scale_linear_moments<EF: Field>(moments: &mut LinearMoments<EF>, scale: EF) {
    moments.a0 *= scale;
    moments.a_delta *= scale;
    moments.b0 *= scale;
    moments.b_delta *= scale;
    moments.weight *= scale;
}

fn linear_moment_partial<EF: Field>(
    i: usize,
    half: usize,
    weight: EF,
    az_tab: &[EF],
    bz_tab: &[EF],
) -> LinearMoments<EF> {
    LinearMoments {
        a0: weight * az_tab[i],
        a_delta: weight * (az_tab[i + half] - az_tab[i]),
        b0: weight * bz_tab[i],
        b_delta: weight * (bz_tab[i + half] - bz_tab[i]),
        weight,
    }
}

fn linear_moment_partial_base<F, EF>(
    i: usize,
    half: usize,
    weight: EF,
    az_tab: &[F],
    bz_tab: &[F],
) -> LinearMoments<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    LinearMoments {
        a0: weight * az_tab[i],
        a_delta: weight * (az_tab[i + half] - az_tab[i]),
        b0: weight * bz_tab[i],
        b_delta: weight * (bz_tab[i + half] - bz_tab[i]),
        weight,
    }
}

fn zero_outer_and_linear_moments<EF: Field>() -> ((EF, EF, EF), LinearMoments<EF>) {
    ((EF::ZERO, EF::ZERO, EF::ZERO), zero_linear_moments())
}

fn add_outer_and_linear_moments<EF: Field>(
    lhs: ((EF, EF, EF), LinearMoments<EF>),
    rhs: ((EF, EF, EF), LinearMoments<EF>),
) -> ((EF, EF, EF), LinearMoments<EF>) {
    (
        (
            lhs.0 .0 + rhs.0 .0,
            lhs.0 .1 + rhs.0 .1,
            lhs.0 .2 + rhs.0 .2,
        ),
        add_linear_moments(lhs.1, rhs.1),
    )
}

fn outer_and_linear_moment_partial_base_second<F, EF>(
    i: usize,
    quarter: usize,
    first_challenge: EF,
    weight: EF,
    az_tab: &[F],
    bz_tab: &[F],
    cz_tab: &[F],
) -> ((EF, EF, EF), LinearMoments<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let half = quarter * 2;
    let a0 = bind_base_pair_to_extension(az_tab, i, half, first_challenge);
    let a1 = bind_base_pair_to_extension(az_tab, i + quarter, half, first_challenge);
    let b0 = bind_base_pair_to_extension(bz_tab, i, half, first_challenge);
    let b1 = bind_base_pair_to_extension(bz_tab, i + quarter, half, first_challenge);
    let c0 = bind_base_pair_to_extension(cz_tab, i, half, first_challenge);
    let c1 = bind_base_pair_to_extension(cz_tab, i + quarter, half, first_challenge);

    let a_delta = a1 - a0;
    let b_delta = b1 - b0;
    let c_delta = c1 - c0;
    let a2 = a1 + a_delta;
    let b2 = b1 + b_delta;
    let c2 = c1 + c_delta;
    let a3 = a2 + a_delta;
    let b3 = b2 + b_delta;
    let c3 = c2 + c_delta;

    (
        (
            weight * (a0 * b0 - c0),
            weight * (a2 * b2 - c2),
            weight * (a3 * b3 - c3),
        ),
        LinearMoments {
            a0: weight * a0,
            a_delta: weight * a_delta,
            b0: weight * b0,
            b_delta: weight * b_delta,
            weight,
        },
    )
}

fn masked_outer_correction_evals<EF: Field + Send + Sync>(
    eq: &SplitEqSumcheck<EF>,
    moments: LinearMoments<EF>,
    round: usize,
    inner_masks: &[Vec<EF>],
    inner_past: &[EF; 3],
    nodes: &[usize],
) -> Vec<EF> {
    let num_rounds = inner_masks.len() / 3;
    nodes
        .iter()
        .map(|&node| {
            let x = EF::from_usize(node);
            let eq_at_x = eq.current_eq_at(x);
            let sum_eq = eq_at_x * moments.weight;
            let sum_eq_a = eq_at_x * (moments.a0 + x * moments.a_delta);
            let sum_eq_b = eq_at_x * (moments.b0 + x * moments.b_delta);
            let offsets: [EF; 3] = core::array::from_fn(|matrix| {
                inner_past[matrix]
                    + inner_masks[matrix * num_rounds + round]
                        .iter()
                        .copied()
                        .horner::<EF, EF>(x)
            });
            offsets[1] * sum_eq_a
                + offsets[0] * sum_eq_b
                + (offsets[0] * offsets[1] - offsets[2]) * sum_eq
        })
        .collect()
}

fn outer_mask_round_evals<EF: Field>(
    mask: &[EF],
    past: EF,
    future_endpoints: EF,
    remaining_rounds: usize,
    nodes: &[usize],
) -> Vec<EF> {
    let live_scale = EF::TWO.exp_u64(remaining_rounds as u64);
    let future = if remaining_rounds == 0 {
        EF::ZERO
    } else {
        EF::TWO.exp_u64((remaining_rounds - 1) as u64) * future_endpoints
    };
    nodes
        .iter()
        .map(|&node| {
            let x = EF::from_usize(node);
            live_scale * (past + mask.iter().copied().horner::<EF, EF>(x)) + future
        })
        .collect()
}

fn update_mask_accumulators<EF: Field>(
    round: usize,
    challenge: EF,
    inner_masks: &[Vec<EF>],
    outer_masks: &[Vec<EF>],
    inner_past: &mut [EF; 3],
    outer_past: &mut EF,
) {
    let num_rounds = outer_masks.len();
    for matrix in 0..3 {
        inner_past[matrix] += inner_masks[matrix * num_rounds + round]
            .iter()
            .copied()
            .horner::<EF, EF>(challenge);
    }
    *outer_past += outer_masks[round]
        .iter()
        .copied()
        .horner::<EF, EF>(challenge);
}

fn sample_non_boolean<F, EF, C>(challenger: &mut C) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    loop {
        let challenge = challenger.sample_algebra_element::<EF>();
        if challenge != EF::ZERO && challenge != EF::ONE {
            return challenge;
        }
    }
}

fn eq_point_eval_local<EF: Field>(a: &[EF], b: &[EF]) -> EF {
    a.iter().zip(b).fold(EF::ONE, |acc, (&x, &y)| {
        acc * ((EF::ONE - x) * (EF::ONE - y) + x * y)
    })
}

struct SplitEqSumcheck<EF> {
    init_num_vars: usize,
    first_half: usize,
    second_half: usize,
    round: usize,
    tau: Vec<EF>,
    eval_eq_left: EF,
    eq_left: Vec<Vec<EF>>,
    eq_right: Vec<Vec<EF>>,
    eq_tau_0_2_3: Vec<(EF, EF, EF)>,
}

impl<EF> SplitEqSumcheck<EF>
where
    EF: Field + Send + Sync,
{
    fn new(tau: &[EF]) -> Self {
        let init_num_vars = tau.len();
        let first_half = init_num_vars / 2;
        let (left_tau, right_tau) = tau.split_at(first_half);
        let left_tau = left_tau.iter().skip(1).rev().copied().collect::<Vec<_>>();
        let right_tau = right_tau.iter().rev().copied().collect::<Vec<_>>();

        let (eq_left, eq_right) = join(
            || compute_eq_prefix_tables(&left_tau),
            || compute_eq_prefix_tables(&right_tau),
        );
        let eq_tau_0_2_3 = tau
            .par_iter()
            .map(|&tau_i| {
                let tau_2 = tau_i.double();
                let tau_3 = tau_2 + tau_i;
                let tau_5 = tau_3 + tau_2;
                (EF::ONE - tau_i, tau_3 - EF::ONE, tau_5 - EF::from_u32(2))
            })
            .collect();

        Self {
            init_num_vars,
            first_half,
            second_half: init_num_vars - first_half,
            round: 1,
            tau: tau.to_vec(),
            eval_eq_left: EF::ONE,
            eq_left,
            eq_right,
            eq_tau_0_2_3,
        }
    }

    fn evaluation_points(
        &self,
        round_idx: usize,
        az_tab: &[EF],
        bz_tab: &[EF],
        cz_tab: &[EF],
    ) -> (EF, EF, EF) {
        debug_assert_eq!(az_tab.len(), bz_tab.len());
        debug_assert_eq!(az_tab.len(), cz_tab.len());
        debug_assert_eq!(az_tab.len() % 2, 0);

        let half = az_tab.len() / 2;
        let in_first_half = self.round < self.first_half;
        let (mut h0, mut h2, mut h3) = if in_first_half {
            let eq_left = &self.eq_left[self.first_half - self.round];
            let eq_right = &self.eq_right[self.second_half];
            let second_half = self.second_half;

            if should_parallelize_sumcheck_round(half) {
                (0..eq_left.len())
                    .into_par_iter()
                    .map(|x_out| {
                        let eq_out = eq_left[x_out];
                        let mut local = (EF::ZERO, EF::ZERO, EF::ZERO);
                        for (x_in, &eq_in) in eq_right.iter().enumerate() {
                            let i = (x_out << second_half) | x_in;
                            let (q0, q2, q3) =
                                outer_round_unweighted(round_idx, i, half, az_tab, bz_tab, cz_tab);
                            local.0 += eq_in * q0;
                            local.1 += eq_in * q2;
                            local.2 += eq_in * q3;
                        }
                        (eq_out * local.0, eq_out * local.1, eq_out * local.2)
                    })
                    .par_fold_reduce(
                        || (EF::ZERO, EF::ZERO, EF::ZERO),
                        add_cubic_accumulators,
                        add_cubic_accumulators,
                    )
            } else {
                let mut acc = (EF::ZERO, EF::ZERO, EF::ZERO);
                for (x_out, &eq_out) in eq_left.iter().enumerate() {
                    let mut local = (EF::ZERO, EF::ZERO, EF::ZERO);
                    for (x_in, &eq_in) in eq_right.iter().enumerate() {
                        let i = (x_out << second_half) | x_in;
                        let (q0, q2, q3) =
                            outer_round_unweighted(round_idx, i, half, az_tab, bz_tab, cz_tab);
                        local.0 += eq_in * q0;
                        local.1 += eq_in * q2;
                        local.2 += eq_in * q3;
                    }
                    acc.0 += eq_out * local.0;
                    acc.1 += eq_out * local.1;
                    acc.2 += eq_out * local.2;
                }
                acc
            }
        } else {
            let eq_right = &self.eq_right[self.init_num_vars - self.round];

            if should_parallelize_sumcheck_round(half) {
                (0..half)
                    .into_par_iter()
                    .map(|i| {
                        let (q0, q2, q3) =
                            outer_round_unweighted(round_idx, i, half, az_tab, bz_tab, cz_tab);
                        let eq = eq_right[i];
                        (eq * q0, eq * q2, eq * q3)
                    })
                    .par_fold_reduce(
                        || (EF::ZERO, EF::ZERO, EF::ZERO),
                        add_cubic_accumulators,
                        add_cubic_accumulators,
                    )
            } else {
                (0..half)
                    .map(|i| {
                        let (q0, q2, q3) =
                            outer_round_unweighted(round_idx, i, half, az_tab, bz_tab, cz_tab);
                        let eq = eq_right[i];
                        (eq * q0, eq * q2, eq * q3)
                    })
                    .fold((EF::ZERO, EF::ZERO, EF::ZERO), add_cubic_accumulators)
            }
        };

        self.scale_current_round(&mut h0, &mut h2, &mut h3);
        (h0, h2, h3)
    }

    fn evaluation_points_base_first<F>(
        &self,
        az_tab: &[F],
        bz_tab: &[F],
        cz_tab: &[F],
    ) -> (EF, EF, EF)
    where
        F: Field + Send + Sync,
        EF: ExtensionField<F>,
    {
        debug_assert_eq!(az_tab.len(), bz_tab.len());
        debug_assert_eq!(az_tab.len(), cz_tab.len());
        debug_assert_eq!(az_tab.len() % 2, 0);

        let half = az_tab.len() / 2;
        let in_first_half = self.round < self.first_half;
        let (mut h0, mut h2, mut h3) = if in_first_half {
            let eq_left = &self.eq_left[self.first_half - self.round];
            let eq_right = &self.eq_right[self.second_half];
            let second_half = self.second_half;

            if should_parallelize_sumcheck_round(half) {
                (0..eq_left.len())
                    .into_par_iter()
                    .map(|x_out| {
                        let eq_out = eq_left[x_out];
                        let mut local_h2 = EF::ZERO;
                        let mut local_h3 = EF::ZERO;
                        for (x_in, &eq_in) in eq_right.iter().enumerate() {
                            let i = (x_out << second_half) | x_in;
                            let (q2, q3) =
                                outer_round_unweighted_base_first(i, half, az_tab, bz_tab, cz_tab);
                            local_h2 += eq_in * q2;
                            local_h3 += eq_in * q3;
                        }
                        (EF::ZERO, eq_out * local_h2, eq_out * local_h3)
                    })
                    .par_fold_reduce(
                        || (EF::ZERO, EF::ZERO, EF::ZERO),
                        add_cubic_accumulators,
                        add_cubic_accumulators,
                    )
            } else {
                let mut acc = (EF::ZERO, EF::ZERO, EF::ZERO);
                for (x_out, &eq_out) in eq_left.iter().enumerate() {
                    let mut local_h2 = EF::ZERO;
                    let mut local_h3 = EF::ZERO;
                    for (x_in, &eq_in) in eq_right.iter().enumerate() {
                        let i = (x_out << second_half) | x_in;
                        let (q2, q3) =
                            outer_round_unweighted_base_first(i, half, az_tab, bz_tab, cz_tab);
                        local_h2 += eq_in * q2;
                        local_h3 += eq_in * q3;
                    }
                    acc.1 += eq_out * local_h2;
                    acc.2 += eq_out * local_h3;
                }
                acc
            }
        } else {
            let eq_right = &self.eq_right[self.init_num_vars - self.round];

            if should_parallelize_sumcheck_round(half) {
                (0..half)
                    .into_par_iter()
                    .map(|i| {
                        let (q2, q3) =
                            outer_round_unweighted_base_first(i, half, az_tab, bz_tab, cz_tab);
                        let eq = eq_right[i];
                        (EF::ZERO, eq * q2, eq * q3)
                    })
                    .par_fold_reduce(
                        || (EF::ZERO, EF::ZERO, EF::ZERO),
                        add_cubic_accumulators,
                        add_cubic_accumulators,
                    )
            } else {
                (0..half)
                    .map(|i| {
                        let (q2, q3) =
                            outer_round_unweighted_base_first(i, half, az_tab, bz_tab, cz_tab);
                        let eq = eq_right[i];
                        (EF::ZERO, eq * q2, eq * q3)
                    })
                    .fold((EF::ZERO, EF::ZERO, EF::ZERO), add_cubic_accumulators)
            }
        };

        self.scale_current_round(&mut h0, &mut h2, &mut h3);
        (h0, h2, h3)
    }

    fn linear_moments(&self, az_tab: &[EF], bz_tab: &[EF]) -> LinearMoments<EF> {
        debug_assert_eq!(az_tab.len(), bz_tab.len());
        debug_assert_eq!(az_tab.len() % 2, 0);
        let half = az_tab.len() / 2;
        let mut moments = if self.round < self.first_half {
            let eq_left = &self.eq_left[self.first_half - self.round];
            let eq_right = &self.eq_right[self.second_half];
            let second_half = self.second_half;
            if should_parallelize_sumcheck_round(half) {
                (0..eq_left.len())
                    .into_par_iter()
                    .map(|x_out| {
                        let eq_out = eq_left[x_out];
                        eq_right
                            .iter()
                            .enumerate()
                            .map(|(x_in, &eq_in)| {
                                let i = (x_out << second_half) | x_in;
                                linear_moment_partial(i, half, eq_out * eq_in, az_tab, bz_tab)
                            })
                            .fold(zero_linear_moments(), add_linear_moments)
                    })
                    .par_fold_reduce(zero_linear_moments, add_linear_moments, add_linear_moments)
            } else {
                eq_left
                    .iter()
                    .enumerate()
                    .flat_map(|(x_out, &eq_out)| {
                        eq_right.iter().enumerate().map(move |(x_in, &eq_in)| {
                            let i = (x_out << second_half) | x_in;
                            linear_moment_partial(i, half, eq_out * eq_in, az_tab, bz_tab)
                        })
                    })
                    .fold(zero_linear_moments(), add_linear_moments)
            }
        } else {
            let eq_right = &self.eq_right[self.init_num_vars - self.round];
            if should_parallelize_sumcheck_round(half) {
                (0..half)
                    .into_par_iter()
                    .map(|i| linear_moment_partial(i, half, eq_right[i], az_tab, bz_tab))
                    .par_fold_reduce(zero_linear_moments, add_linear_moments, add_linear_moments)
            } else {
                (0..half)
                    .map(|i| linear_moment_partial(i, half, eq_right[i], az_tab, bz_tab))
                    .fold(zero_linear_moments(), add_linear_moments)
            }
        };
        scale_linear_moments(&mut moments, self.eval_eq_left);
        moments
    }

    fn linear_moments_base_first<F>(&self, az_tab: &[F], bz_tab: &[F]) -> LinearMoments<EF>
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        debug_assert_eq!(az_tab.len(), bz_tab.len());
        debug_assert_eq!(az_tab.len() % 2, 0);
        let half = az_tab.len() / 2;
        let mut moments = if self.round < self.first_half {
            let eq_left = &self.eq_left[self.first_half - self.round];
            let eq_right = &self.eq_right[self.second_half];
            let second_half = self.second_half;
            if should_parallelize_sumcheck_round(half) {
                (0..eq_left.len())
                    .into_par_iter()
                    .map(|x_out| {
                        let eq_out = eq_left[x_out];
                        eq_right
                            .iter()
                            .enumerate()
                            .map(|(x_in, &eq_in)| {
                                let i = (x_out << second_half) | x_in;
                                linear_moment_partial_base(i, half, eq_out * eq_in, az_tab, bz_tab)
                            })
                            .fold(zero_linear_moments(), add_linear_moments)
                    })
                    .par_fold_reduce(zero_linear_moments, add_linear_moments, add_linear_moments)
            } else {
                eq_left
                    .iter()
                    .enumerate()
                    .flat_map(|(x_out, &eq_out)| {
                        eq_right.iter().enumerate().map(move |(x_in, &eq_in)| {
                            let i = (x_out << second_half) | x_in;
                            linear_moment_partial_base(i, half, eq_out * eq_in, az_tab, bz_tab)
                        })
                    })
                    .fold(zero_linear_moments(), add_linear_moments)
            }
        } else {
            let eq_right = &self.eq_right[self.init_num_vars - self.round];
            if should_parallelize_sumcheck_round(half) {
                (0..half)
                    .into_par_iter()
                    .map(|i| linear_moment_partial_base(i, half, eq_right[i], az_tab, bz_tab))
                    .par_fold_reduce(zero_linear_moments, add_linear_moments, add_linear_moments)
            } else {
                (0..half)
                    .map(|i| linear_moment_partial_base(i, half, eq_right[i], az_tab, bz_tab))
                    .fold(zero_linear_moments(), add_linear_moments)
            }
        };
        scale_linear_moments(&mut moments, self.eval_eq_left);
        moments
    }

    fn evaluation_points_and_linear_moments_base_second<F>(
        &self,
        first_challenge: EF,
        az_tab: &[F],
        bz_tab: &[F],
        cz_tab: &[F],
    ) -> ((EF, EF, EF), LinearMoments<EF>)
    where
        F: Field + Send + Sync,
        EF: ExtensionField<F>,
    {
        debug_assert_eq!(self.round, 2);
        debug_assert_eq!(az_tab.len(), bz_tab.len());
        debug_assert_eq!(az_tab.len(), cz_tab.len());
        debug_assert_eq!(az_tab.len() % 4, 0);

        let quarter = az_tab.len() / 4;
        let partial = |i, weight| {
            outer_and_linear_moment_partial_base_second(
                i,
                quarter,
                first_challenge,
                weight,
                az_tab,
                bz_tab,
                cz_tab,
            )
        };
        let mut accum = if self.round < self.first_half {
            let eq_left = &self.eq_left[self.first_half - self.round];
            let eq_right = &self.eq_right[self.second_half];
            let second_half = self.second_half;
            let inner_mask = (1 << second_half) - 1;
            if should_parallelize_sumcheck_round(quarter) {
                (0..quarter)
                    .into_par_iter()
                    .map(|i| {
                        let weight = eq_left[i >> second_half] * eq_right[i & inner_mask];
                        partial(i, weight)
                    })
                    .par_fold_reduce(
                        zero_outer_and_linear_moments,
                        add_outer_and_linear_moments,
                        add_outer_and_linear_moments,
                    )
            } else {
                (0..quarter)
                    .map(|i| {
                        let weight = eq_left[i >> second_half] * eq_right[i & inner_mask];
                        partial(i, weight)
                    })
                    .fold(
                        zero_outer_and_linear_moments(),
                        add_outer_and_linear_moments,
                    )
            }
        } else {
            let eq_right = &self.eq_right[self.init_num_vars - self.round];
            if should_parallelize_sumcheck_round(quarter) {
                (0..quarter)
                    .into_par_iter()
                    .map(|i| partial(i, eq_right[i]))
                    .par_fold_reduce(
                        zero_outer_and_linear_moments,
                        add_outer_and_linear_moments,
                        add_outer_and_linear_moments,
                    )
            } else {
                (0..quarter).map(|i| partial(i, eq_right[i])).fold(
                    zero_outer_and_linear_moments(),
                    add_outer_and_linear_moments,
                )
            }
        };

        self.scale_current_round(&mut accum.0 .0, &mut accum.0 .1, &mut accum.0 .2);
        scale_linear_moments(&mut accum.1, self.eval_eq_left);
        accum
    }

    fn current_eq_at(&self, x: EF) -> EF {
        let tau = self.tau[self.round - 1];
        EF::ONE - tau - x + (tau * x).double()
    }

    fn scale_current_round(&self, h0: &mut EF, h2: &mut EF, h3: &mut EF) {
        let p = self.eval_eq_left;
        let (eq0, eq2, eq3) = self.eq_tau_0_2_3[self.round - 1];
        *h0 *= eq0 * p;
        *h2 *= eq2 * p;
        *h3 *= eq3 * p;
    }

    fn bind(&mut self, r: EF) {
        let tau_i = self.tau[self.round - 1];
        self.eval_eq_left *= EF::ONE - tau_i - r + (r * tau_i).double();
        self.round += 1;
    }
}

fn compute_eq_prefix_tables<EF>(point: &[EF]) -> Vec<Vec<EF>>
where
    EF: Field + Send + Sync,
{
    let mut out = Vec::with_capacity(point.len() + 1);
    out.push(vec![EF::ONE]);
    for &r_i in point {
        let prev = out.last().expect("non-empty");
        let mut next = vec![EF::ZERO; prev.len() * 2];
        let (lo, hi) = next.split_at_mut(prev.len());
        if should_parallelize_sumcheck_round(prev.len()) {
            lo.par_iter_mut()
                .zip(hi.par_iter_mut())
                .zip(prev.par_iter())
                .for_each(|((lo, hi), &v)| {
                    *hi = v * r_i;
                    *lo = v - *hi;
                });
        } else {
            for ((lo, hi), &v) in lo.iter_mut().zip(hi.iter_mut()).zip(prev.iter()) {
                *hi = v * r_i;
                *lo = v - *hi;
            }
        }
        out.push(next);
    }
    out
}

fn outer_round_unweighted<EF>(
    round_idx: usize,
    i: usize,
    half: usize,
    az_tab: &[EF],
    bz_tab: &[EF],
    cz_tab: &[EF],
) -> (EF, EF, EF)
where
    EF: Field,
{
    let a0 = az_tab[i];
    let a1 = az_tab[i + half];
    let b0 = bz_tab[i];
    let b1 = bz_tab[i + half];
    let c0 = cz_tab[i];
    let c1 = cz_tab[i + half];

    let h0 = if round_idx == 0 {
        EF::ZERO
    } else {
        a0 * b0 - c0
    };

    let a2 = a1.double() - a0;
    let b2 = b1.double() - b0;
    let c2 = c1.double() - c0;
    let h2 = a2 * b2 - c2;

    let a3 = a2 + (a1 - a0);
    let b3 = b2 + (b1 - b0);
    let c3 = c2 + (c1 - c0);
    let h3 = a3 * b3 - c3;

    (h0, h2, h3)
}

fn outer_round_unweighted_base_first<F>(
    i: usize,
    half: usize,
    az_tab: &[F],
    bz_tab: &[F],
    cz_tab: &[F],
) -> (F, F)
where
    F: Field,
{
    let a0 = az_tab[i];
    let a1 = az_tab[i + half];
    let b0 = bz_tab[i];
    let b1 = bz_tab[i + half];
    let c0 = cz_tab[i];
    let c1 = cz_tab[i + half];

    let a2 = a1.double() - a0;
    let b2 = b1.double() - b0;
    let c2 = c1.double() - c0;
    let h2 = a2 * b2 - c2;

    let a3 = a2 + (a1 - a0);
    let b3 = b2 + (b1 - b0);
    let c3 = c2 + (c1 - c0);
    let h3 = a3 * b3 - c3;

    (h2, h3)
}

fn inner_round_coefficients<F, EF>(z_tab: &[EF], abc_tab: &[EF], claim: EF) -> (EF, EF)
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
{
    let (h0, h_inf) = sumcheck_coefficients_prefix::<EF, EF>(z_tab, abc_tab);
    (h0, quadratic_h2_from_hinf(h0, h_inf, claim))
}

fn inner_round_coefficients_base<F, EF>(z_tab: &[F], abc_tab: &[EF], claim: EF) -> (EF, EF)
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    let (h0, h_inf) = sumcheck_coefficients_prefix::<F, EF>(z_tab, abc_tab);
    (h0, quadratic_h2_from_hinf(h0, h_inf, claim))
}

fn quadratic_h2_from_hinf<EF: Field>(h0: EF, h_inf: EF, claim: EF) -> EF {
    let h1 = claim - h0;
    h1.double() - h0 + h_inf.double()
}

fn add_cubic_accumulators<EF: Field>(
    (a0, a2, a3): (EF, EF, EF),
    (b0, b2, b3): (EF, EF, EF),
) -> (EF, EF, EF) {
    (a0 + b0, a2 + b2, a3 + b3)
}

fn should_parallelize_sumcheck_round(pair_count: usize) -> bool {
    cfg!(feature = "parallel") && pair_count >= SUMCHECK_PARALLEL_ROUND_MIN_PAIRS
}

fn bind_half<F: Field, EF: ExtensionField<F> + Send + Sync>(
    table: &mut Vec<EF>,
    r: EF,
) -> Result<(), SpartanWhirError> {
    if table.len() < 2 || !table.len().is_multiple_of(2) {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = table.len() / 2;
    {
        let (lo, hi) = table.split_at_mut(half);
        if should_parallelize_sumcheck_round(half) {
            lo.par_iter_mut()
                .zip(hi.par_iter())
                .for_each(|(lo, &hi)| *lo += r * (hi - *lo));
        } else {
            for (lo, &hi) in lo.iter_mut().zip(hi.iter()) {
                *lo += r * (hi - *lo);
            }
        }
    }
    table.truncate(half);
    Ok(())
}

fn bind_three_halves<EF>(
    a: &mut Vec<EF>,
    b: &mut Vec<EF>,
    c: &mut Vec<EF>,
    r: EF,
) -> Result<(), SpartanWhirError>
where
    EF: Field + Send + Sync,
{
    if a.len() < 2 || !a.len().is_multiple_of(2) || b.len() != a.len() || c.len() != a.len() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = a.len() / 2;
    {
        let (a_lo, a_hi) = a.split_at_mut(half);
        let (b_lo, b_hi) = b.split_at_mut(half);
        let (c_lo, c_hi) = c.split_at_mut(half);

        if should_parallelize_sumcheck_round(half) {
            a_lo.par_iter_mut()
                .zip(a_hi.par_iter())
                .zip(b_lo.par_iter_mut())
                .zip(b_hi.par_iter())
                .zip(c_lo.par_iter_mut())
                .zip(c_hi.par_iter())
                .for_each(|(((((a_lo, &a_hi), b_lo), &b_hi), c_lo), &c_hi)| {
                    *a_lo += r * (a_hi - *a_lo);
                    *b_lo += r * (b_hi - *b_lo);
                    *c_lo += r * (c_hi - *c_lo);
                });
        } else {
            for (((a_lo, &a_hi), (b_lo, &b_hi)), (c_lo, &c_hi)) in a_lo
                .iter_mut()
                .zip(a_hi.iter())
                .zip(b_lo.iter_mut().zip(b_hi.iter()))
                .zip(c_lo.iter_mut().zip(c_hi.iter()))
            {
                *a_lo += r * (a_hi - *a_lo);
                *b_lo += r * (b_hi - *b_lo);
                *c_lo += r * (c_hi - *c_lo);
            }
        }
    }
    a.truncate(half);
    b.truncate(half);
    c.truncate(half);
    Ok(())
}

fn bind_two_halves<EF>(a: &mut Vec<EF>, b: &mut Vec<EF>, r: EF) -> Result<(), SpartanWhirError>
where
    EF: Field + Send + Sync,
{
    if a.len() < 2 || !a.len().is_multiple_of(2) || b.len() != a.len() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = a.len() / 2;
    {
        let (a_lo, a_hi) = a.split_at_mut(half);
        let (b_lo, b_hi) = b.split_at_mut(half);

        if should_parallelize_sumcheck_round(half) {
            a_lo.par_iter_mut()
                .zip(a_hi.par_iter())
                .zip(b_lo.par_iter_mut())
                .zip(b_hi.par_iter())
                .for_each(|(((a_lo, &a_hi), b_lo), &b_hi)| {
                    *a_lo += r * (a_hi - *a_lo);
                    *b_lo += r * (b_hi - *b_lo);
                });
        } else {
            for ((a_lo, &a_hi), (b_lo, &b_hi)) in a_lo
                .iter_mut()
                .zip(a_hi.iter())
                .zip(b_lo.iter_mut().zip(b_hi.iter()))
            {
                *a_lo += r * (a_hi - *a_lo);
                *b_lo += r * (b_hi - *b_lo);
            }
        }
    }
    a.truncate(half);
    b.truncate(half);
    Ok(())
}

fn bind_three_halves_base_to_extension<F, EF>(
    a: &[F],
    b: &[F],
    c: &[F],
    r: EF,
) -> Result<(Vec<EF>, Vec<EF>, Vec<EF>), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if a.len() < 2 || !a.len().is_multiple_of(2) || b.len() != a.len() || c.len() != a.len() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = a.len() / 2;
    let mut a_out = vec![EF::ZERO; half];
    let mut b_out = vec![EF::ZERO; half];
    let mut c_out = vec![EF::ZERO; half];

    if should_parallelize_sumcheck_round(half) {
        a_out
            .par_iter_mut()
            .zip(b_out.par_iter_mut())
            .zip(c_out.par_iter_mut())
            .enumerate()
            .for_each(|(i, ((a_out, b_out), c_out))| {
                *a_out = bind_base_pair_to_extension(a, i, half, r);
                *b_out = bind_base_pair_to_extension(b, i, half, r);
                *c_out = bind_base_pair_to_extension(c, i, half, r);
            });
    } else {
        for i in 0..half {
            a_out[i] = bind_base_pair_to_extension(a, i, half, r);
            b_out[i] = bind_base_pair_to_extension(b, i, half, r);
            c_out[i] = bind_base_pair_to_extension(c, i, half, r);
        }
    }

    Ok((a_out, b_out, c_out))
}

fn bind_three_quarters_base_to_extension<F, EF>(
    a: &[F],
    b: &[F],
    c: &[F],
    first_challenge: EF,
    second_challenge: EF,
) -> Result<(Vec<EF>, Vec<EF>, Vec<EF>), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if a.len() < 4 || !a.len().is_multiple_of(4) || b.len() != a.len() || c.len() != a.len() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let quarter = a.len() / 4;
    let half = quarter * 2;
    let mut a_out = vec![EF::ZERO; quarter];
    let mut b_out = vec![EF::ZERO; quarter];
    let mut c_out = vec![EF::ZERO; quarter];
    let bind = |table: &[F], i| {
        let lo = bind_base_pair_to_extension(table, i, half, first_challenge);
        let hi = bind_base_pair_to_extension(table, i + quarter, half, first_challenge);
        lo + second_challenge * (hi - lo)
    };

    if should_parallelize_sumcheck_round(quarter) {
        a_out
            .par_iter_mut()
            .zip(b_out.par_iter_mut())
            .zip(c_out.par_iter_mut())
            .enumerate()
            .for_each(|(i, ((a_out, b_out), c_out))| {
                *a_out = bind(a, i);
                *b_out = bind(b, i);
                *c_out = bind(c, i);
            });
    } else {
        for i in 0..quarter {
            a_out[i] = bind(a, i);
            b_out[i] = bind(b, i);
            c_out[i] = bind(c, i);
        }
    }

    Ok((a_out, b_out, c_out))
}

fn bind_half_extension_and_base_to_extension<F, EF>(
    extension_table: &mut Vec<EF>,
    base_table: &[F],
    r: EF,
) -> Result<Vec<EF>, SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if extension_table.len() < 2
        || !extension_table.len().is_multiple_of(2)
        || base_table.len() != extension_table.len()
    {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = extension_table.len() / 2;
    let mut base_out = vec![EF::ZERO; half];
    {
        let (lo, hi) = extension_table.split_at_mut(half);
        if should_parallelize_sumcheck_round(half) {
            lo.par_iter_mut()
                .zip(hi.par_iter())
                .zip(base_out.par_iter_mut())
                .enumerate()
                .for_each(|(i, ((lo, &hi), base_out))| {
                    *lo += r * (hi - *lo);
                    *base_out = bind_base_pair_to_extension(base_table, i, half, r);
                });
        } else {
            for (i, ((lo, &hi), base_out)) in lo
                .iter_mut()
                .zip(hi.iter())
                .zip(base_out.iter_mut())
                .enumerate()
            {
                *lo += r * (hi - *lo);
                *base_out = bind_base_pair_to_extension(base_table, i, half, r);
            }
        }
    }
    extension_table.truncate(half);
    Ok(base_out)
}

fn bind_base_pair_to_extension<F, EF>(table: &[F], i: usize, half: usize, r: EF) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let lo = table[i];
    let delta = table[i + half] - lo;
    if delta.is_zero() {
        EF::from(lo)
    } else {
        EF::from(lo) + r * delta
    }
}

#[cfg(test)]
mod zk_outer_tests {
    use super::*;
    use crate::engine::{poseidon_challenger, F};
    use crate::{QuarticBinExtension as EF, SparseMatrix};
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    fn shape(num_cons: usize) -> R1csShape<F> {
        let matrix = SparseMatrix {
            num_rows: num_cons,
            num_cols: 1,
            entries: Vec::new(),
        };
        R1csShape {
            num_cons,
            num_vars: 1,
            num_io: 0,
            a: matrix.clone(),
            b: matrix.clone(),
            c: matrix,
        }
    }

    fn inner_mask(seed: u32) -> Vec<EF> {
        let a = EF::from_u32(seed);
        let b = EF::from_u32(seed + 1);
        vec![EF::ZERO, a, b, -a - b]
    }

    fn outer_mask(seed: u32) -> Vec<EF> {
        (0..8).map(|i| EF::from_u32(seed + i)).collect()
    }

    #[test]
    fn zk_outer_optimized_rounds_match_naive_definition() {
        let num_rounds = 3;
        let az = (0..8).map(|i| F::from_u32(i + 2)).collect::<Vec<_>>();
        let bz = (0..8).map(|i| F::from_u32(3 * i + 1)).collect::<Vec<_>>();
        let cz = az.iter().zip(&bz).map(|(&a, &b)| a * b).collect::<Vec<_>>();
        let inner_masks = (0..3 * num_rounds)
            .map(|i| inner_mask(11 + i as u32 * 5))
            .collect::<Vec<_>>();
        let outer_masks = (0..num_rounds)
            .map(|i| outer_mask(71 + i as u32 * 11))
            .collect::<Vec<_>>();

        let mut prover_challenger = poseidon_challenger();
        let output = prove_outer_zk_base_first_unchecked::<F, EF, _>(
            &shape(8),
            az.clone(),
            bz.clone(),
            cz.clone(),
            &inner_masks,
            &outer_masks,
            &mut prover_challenger,
        )
        .unwrap();

        let mut transcript = poseidon_challenger();
        transcript.observe_algebra_element(output.proof.mu_tilde);
        let epsilon = transcript.sample_algebra_element::<EF>();
        let tau = (0..num_rounds)
            .map(|_| transcript.sample_algebra_element::<EF>())
            .collect::<Vec<_>>();
        let mut a = az.into_iter().map(EF::from).collect::<Vec<_>>();
        let mut b = bz.into_iter().map(EF::from).collect::<Vec<_>>();
        let mut c = cz.into_iter().map(EF::from).collect::<Vec<_>>();
        let mut eq = crate::EqPolynomial::evals_from_point_with_base::<F>(&tau);
        let mut prefix = Vec::new();

        for round in 0..num_rounds {
            let half = a.len() / 2;
            for (wire_idx, node) in [0usize, 2, 3, 4, 5, 6, 7].into_iter().enumerate() {
                let x = EF::from_usize(node);
                let mut expected = EF::ZERO;
                for suffix in 0..half {
                    let av = a[suffix] + x * (a[suffix + half] - a[suffix]);
                    let bv = b[suffix] + x * (b[suffix + half] - b[suffix]);
                    let cv = c[suffix] + x * (c[suffix + half] - c[suffix]);
                    let eqv = eq[suffix] + x * (eq[suffix + half] - eq[suffix]);
                    let offsets: [EF; 3] = core::array::from_fn(|matrix| {
                        let mut value = inner_masks[matrix * num_rounds + round]
                            .iter()
                            .copied()
                            .horner::<EF, EF>(x);
                        for (prior, &challenge) in prefix.iter().enumerate() {
                            value += inner_masks[matrix * num_rounds + prior]
                                .iter()
                                .copied()
                                .horner::<EF, EF>(challenge);
                        }
                        value
                    });
                    let mut outer = outer_masks[round].iter().copied().horner::<EF, EF>(x);
                    for (prior, &challenge) in prefix.iter().enumerate() {
                        outer += outer_masks[prior]
                            .iter()
                            .copied()
                            .horner::<EF, EF>(challenge);
                    }
                    let remaining = num_rounds - round - 1;
                    for future in 0..remaining {
                        let bit = (suffix >> (remaining - future - 1)) & 1;
                        outer += outer_masks[round + future + 1]
                            .iter()
                            .copied()
                            .horner::<EF, EF>(EF::from_usize(bit));
                    }
                    expected +=
                        epsilon * eqv * ((av + offsets[0]) * (bv + offsets[1]) - (cv + offsets[2]))
                            + outer;
                }
                assert_eq!(output.proof.rounds[round][wire_idx], expected);
            }

            transcript.observe_algebra_slice(&output.proof.rounds[round]);
            let challenge = if round + 1 == num_rounds {
                sample_non_boolean::<F, EF, _>(&mut transcript)
            } else {
                transcript.sample_algebra_element::<EF>()
            };
            assert_eq!(challenge, output.point.0[round]);
            prefix.push(challenge);
            bind_half::<F, EF>(&mut a, challenge).unwrap();
            bind_half::<F, EF>(&mut b, challenge).unwrap();
            bind_half::<F, EF>(&mut c, challenge).unwrap();
            bind_half::<F, EF>(&mut eq, challenge).unwrap();
        }

        let mut verifier_challenger = poseidon_challenger();
        let point = verify_outer_zk::<F, EF, _>(
            &output.proof,
            output.masked_claims,
            &output.outer_mask_evals,
            num_rounds,
            &mut verifier_challenger,
        )
        .unwrap();
        assert_eq!(point, output.point);
    }

    #[test]
    fn zk_outer_witness_free_simulator_produces_accepting_view() {
        let num_rounds = 3;
        let mut rng = StdRng::seed_from_u64(0x5A17_51A7);
        let mu_tilde = rng.random::<EF>();
        let mut simulator_challenger = poseidon_challenger();
        simulator_challenger.observe_algebra_element(mu_tilde);
        let epsilon = simulator_challenger.sample_algebra_element::<EF>();
        let tau = (0..num_rounds)
            .map(|_| simulator_challenger.sample_algebra_element::<EF>())
            .collect::<Vec<_>>();
        let interpolator = RoundPolyInterpolator::new(7);
        let mut claim = mu_tilde;
        let mut point = Vec::with_capacity(num_rounds);
        let mut rounds = Vec::with_capacity(num_rounds);
        for round in 0..num_rounds {
            let wire = (0..7).map(|_| rng.random::<EF>()).collect::<Vec<_>>();
            simulator_challenger.observe_algebra_slice(&wire);
            let challenge = if round + 1 == num_rounds {
                sample_non_boolean::<F, EF, _>(&mut simulator_challenger)
            } else {
                simulator_challenger.sample_algebra_element::<EF>()
            };
            claim = interpolator.eval(&wire, claim, challenge);
            point.push(challenge);
            rounds.push(wire);
        }

        let masked_claims = (rng.random::<EF>(), rng.random::<EF>(), rng.random::<EF>());
        let mut outer_mask_evals = (0..num_rounds)
            .map(|_| rng.random::<EF>())
            .collect::<Vec<_>>();
        let product_term = epsilon
            * (masked_claims.0 * masked_claims.1 - masked_claims.2)
            * eq_point_eval_local(&tau, &point);
        let prior_outer_sum = outer_mask_evals[..num_rounds - 1]
            .iter()
            .copied()
            .sum::<EF>();
        outer_mask_evals[num_rounds - 1] = claim - product_term - prior_outer_sum;
        let proof = ZkOuterSumcheckProof { mu_tilde, rounds };

        let mut verifier_challenger = poseidon_challenger();
        let verified_point = verify_outer_zk::<F, EF, _>(
            &proof,
            masked_claims,
            &outer_mask_evals,
            num_rounds,
            &mut verifier_challenger,
        )
        .expect("witness-free simulated view verifies");
        assert_eq!(verified_point.0, point);
    }
}
