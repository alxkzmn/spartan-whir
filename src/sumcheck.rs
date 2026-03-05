use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field};

use crate::{CubicRoundPoly, MultilinearPoint, QuadraticRoundPoly, R1csShape, SpartanWhirError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterSumcheckProof<F> {
    pub rounds: Vec<CubicRoundPoly<F>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    shape.validate()?;
    validate_outer_inputs(shape, az, bz, cz, tau)?;

    let mut eq = crate::EqPolynomial::evals_from_point(&tau.0);
    let mut az_tab = az.to_vec();
    let mut bz_tab = bz.to_vec();
    let mut cz_tab = cz.to_vec();
    let mut rounds = Vec::with_capacity(tau.0.len());
    let mut r_x = Vec::with_capacity(tau.0.len());
    let mut claim = EF::ZERO;

    for _ in 0..tau.0.len() {
        let half = eq.len() / 2;
        let mut h0 = EF::ZERO;
        let mut h2 = EF::ZERO;
        let mut h3 = EF::ZERO;

        for i in 0..half {
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

            h0 += eq0 * (a0 * b0 - c0);
            h2 += eq2 * (a2 * b2 - c2);
            h3 += eq3 * (a3 * b3 - c3);
        }

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
        let half = abc_tab.len() / 2;
        let mut h0 = EF::ZERO;
        let mut h2 = EF::ZERO;

        for i in 0..half {
            let a0 = abc_tab[i];
            let a1 = abc_tab[i + half];
            let z0 = z_tab[i];
            let z1 = z_tab[i + half];

            let a2 = a1.double() - a0;
            let z2 = z1.double() - z0;

            h0 += a0 * z0;
            h2 += a2 * z2;
        }

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

fn bind_half<F: Field, EF: ExtensionField<F>>(
    table: &mut Vec<EF>,
    r: EF,
) -> Result<(), SpartanWhirError> {
    if table.len() < 2 || !table.len().is_multiple_of(2) {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let half = table.len() / 2;
    for i in 0..half {
        let lo = table[i];
        let hi = table[i + half];
        table[i] = lo + r * (hi - lo);
    }
    table.truncate(half);
    Ok(())
}
