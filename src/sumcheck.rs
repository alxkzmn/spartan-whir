use alloc::{vec, vec::Vec};

use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;
use p3_sumcheck::strategy::sumcheck_coefficients_prefix;
use serde::{Deserialize, Serialize};

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
        crate::EqPolynomial::evals_from_point_parallel(&tau.0)
    };
    let mut rounds = Vec::with_capacity(tau.0.len());
    let mut r_x = Vec::with_capacity(tau.0.len());
    let mut claim = EF::ZERO;

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
    if proof.rounds.len() != expected_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }

    let mut claim = initial_claim;
    let mut r_x = Vec::with_capacity(expected_rounds);

    for round in &proof.rounds {
        challenger.observe_algebra_slice(&round.0);
        let r_i = challenger.sample_algebra_element::<EF>();
        claim = round.evaluate_at(r_i, claim);
        r_x.push(r_i);
    }

    Ok((MultilinearPoint(r_x), claim))
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

    let mut abc_tab = poly_abc.to_vec();
    let mut z_tab = z.to_vec();
    let num_rounds = poly_abc.len().ilog2() as usize;

    let mut rounds = Vec::with_capacity(num_rounds);
    let mut r_y = Vec::with_capacity(num_rounds);
    let mut claim = initial_claim;

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
    prove_inner_base_first_unchecked(initial_claim, poly_abc, z, challenger)
}

pub(crate) fn prove_inner_base_first_unchecked<F, EF, C>(
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
    if poly_abc.len() != z.len() || poly_abc.is_empty() || !poly_abc.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let mut abc_tab = poly_abc.to_vec();
    let num_rounds = poly_abc.len().ilog2() as usize;

    let mut rounds = Vec::with_capacity(num_rounds);
    let mut r_y = Vec::with_capacity(num_rounds);
    let mut claim = initial_claim;

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
    if proof.rounds.len() != expected_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }

    let mut claim = initial_claim;
    let mut r_y = Vec::with_capacity(expected_rounds);

    for round in &proof.rounds {
        challenger.observe_algebra_slice(&round.0);
        let r_i = challenger.sample_algebra_element::<EF>();
        claim = round.evaluate_at(r_i, claim);
        r_y.push(r_i);
    }

    Ok((MultilinearPoint(r_y), claim))
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
