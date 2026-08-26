use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field};

use crate::{MultilinearPoint, SpartanWhirError};

// Same compact round encoding as P3 generic-degree sumcheck:
// [h(0), h(2), ..., h(degree)], with h(1) recovered from the running claim.
pub(crate) fn observe_sumcheck_claim<F, EF, C>(challenger: &mut C, claim: EF)
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
{
    challenger.observe_algebra_element(claim);
}

pub(crate) fn replay_compact_rounds<F, EF, C, R>(
    rounds: &[R],
    initial_claim: EF,
    expected_rounds: usize,
    degree: usize,
    challenger: &mut C,
) -> Result<(MultilinearPoint<EF>, EF), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
    C: FieldChallenger<F>,
    R: AsRef<[EF]>,
{
    if rounds.len() != expected_rounds {
        return Err(SpartanWhirError::InvalidRoundCount);
    }
    if degree == 0 {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    observe_sumcheck_claim::<F, EF, C>(challenger, initial_claim);

    let denominator_inverses = compact_round_denominator_inverses::<EF>(degree);
    let _profile = crate::profiling::profile_detail_scope("replay_compact_rounds");
    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(expected_rounds);
    for round in rounds {
        let evals = round.as_ref();
        if evals.len() != degree {
            return Err(SpartanWhirError::InvalidRoundPolynomial);
        }
        challenger.observe_algebra_slice(evals);
        let challenge = challenger.sample_algebra_element::<EF>();
        claim = evaluate_compact_round(evals, claim, challenge, &denominator_inverses);
        point.push(challenge);
    }

    Ok((MultilinearPoint(point), claim))
}

fn compact_round_denominator_inverses<EF>(degree: usize) -> Vec<EF>
where
    EF: Field,
{
    let point_count = degree + 1;
    let mut out = Vec::with_capacity(point_count);
    for i in 0..point_count {
        let x_i = EF::from_u32(i as u32);
        let mut den = EF::ONE;
        for j in 0..point_count {
            if i == j {
                continue;
            }
            let x_j = EF::from_u32(j as u32);
            den *= x_i - x_j;
        }
        out.push(den.inverse());
    }
    out
}

fn evaluate_compact_round<EF>(
    evals: &[EF],
    claim: EF,
    challenge: EF,
    denominator_inverses: &[EF],
) -> EF
where
    EF: Field,
{
    let point_count = evals.len() + 1;
    debug_assert_eq!(denominator_inverses.len(), point_count);
    let mut out = EF::ZERO;

    for i in 0..point_count {
        let y_i = match i {
            0 => evals[0],
            1 => claim - evals[0],
            _ => evals[i - 1],
        };
        let mut num = EF::ONE;
        for j in 0..point_count {
            if i == j {
                continue;
            }
            let x_j = EF::from_u32(j as u32);
            num *= challenge - x_j;
        }
        out += y_i * num * denominator_inverses[i];
    }

    out
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use p3_challenger::FieldChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_sumcheck::generic_degree::GenericDegreeProof;

    use super::*;
    use crate::{engine::F, poseidon_challenger, OcticBinExtension as EF};

    fn ef(value: u32) -> EF {
        EF::from(F::from_u32(value))
    }

    fn evaluate_polynomial(coefficients: &[EF], point: EF) -> EF {
        coefficients
            .iter()
            .rev()
            .fold(EF::ZERO, |acc, &coefficient| acc * point + coefficient)
    }

    fn valid_rounds(
        degree: usize,
        round_count: usize,
        initial_claim: EF,
    ) -> (Vec<Vec<EF>>, Vec<EF>, EF) {
        let mut challenger = poseidon_challenger();
        challenger.observe_algebra_element(initial_claim);

        let mut claim = initial_claim;
        let mut rounds = Vec::with_capacity(round_count);
        let mut challenges = Vec::with_capacity(round_count);
        for round in 0..round_count {
            let mut coefficients = vec![EF::ZERO; degree + 1];
            coefficients[0] = ef((round + 2) as u32);
            for (power, coefficient) in coefficients.iter_mut().enumerate().skip(2) {
                *coefficient = ef((round * (degree + 1) + power + 3) as u32);
            }
            let higher_sum = coefficients
                .iter()
                .skip(2)
                .copied()
                .fold(EF::ZERO, |acc, value| acc + value);
            coefficients[1] = claim - coefficients[0] - coefficients[0] - higher_sum;

            let compact_evals = (0..=degree)
                .filter(|&point| point != 1)
                .map(|point| evaluate_polynomial(&coefficients, EF::from_usize(point)))
                .collect::<Vec<_>>();
            challenger.observe_algebra_slice(&compact_evals);
            let challenge = challenger.sample_algebra_element::<EF>();
            claim = evaluate_polynomial(&coefficients, challenge);
            rounds.push(compact_evals);
            challenges.push(challenge);
        }

        (rounds, challenges, claim)
    }

    #[test]
    fn compact_replay_matches_polynomials_and_p3_for_supported_degrees() {
        for degree in [2, 3, 4] {
            let initial_claim = ef((degree * 11) as u32);
            let (rounds, expected_point, expected_claim) = valid_rounds(degree, 5, initial_claim);

            let mut replay_challenger = poseidon_challenger();
            let (point, claim) = replay_compact_rounds::<F, EF, _, _>(
                &rounds,
                initial_claim,
                rounds.len(),
                degree,
                &mut replay_challenger,
            )
            .unwrap();
            assert_eq!(point.0, expected_point);
            assert_eq!(claim, expected_claim);

            let p3_proof = GenericDegreeProof::<F, EF> {
                claimed_sum: initial_claim,
                round_polys: rounds,
                pow_witnesses: Vec::new(),
            };
            let mut p3_challenger = poseidon_challenger();
            let (p3_point, p3_claim) = p3_proof.verify(&mut p3_challenger, 5, degree, 0).unwrap();
            assert_eq!(p3_point.as_slice(), expected_point);
            assert_eq!(p3_claim, expected_claim);
        }
    }

    #[test]
    fn compact_replay_rejects_invalid_shapes() {
        let mut challenger = poseidon_challenger();
        let rounds = vec![vec![ef(1), ef(2), ef(3)]];
        assert_eq!(
            replay_compact_rounds::<F, EF, _, _>(&rounds, ef(7), 2, 3, &mut challenger),
            Err(SpartanWhirError::InvalidRoundCount)
        );

        let mut challenger = poseidon_challenger();
        let mixed_width = vec![vec![ef(1), ef(2), ef(3)], vec![ef(4), ef(5)]];
        assert_eq!(
            replay_compact_rounds::<F, EF, _, _>(
                &mixed_width,
                ef(7),
                mixed_width.len(),
                3,
                &mut challenger,
            ),
            Err(SpartanWhirError::InvalidRoundPolynomial)
        );

        let mut challenger = poseidon_challenger();
        let no_rounds: Vec<Vec<EF>> = Vec::new();
        assert_eq!(
            replay_compact_rounds::<F, EF, _, _>(
                &no_rounds,
                ef(7),
                no_rounds.len(),
                0,
                &mut challenger,
            ),
            Err(SpartanWhirError::InvalidRoundPolynomial)
        );
    }
}
