use alloc::{vec, vec::Vec};

use p3_field::Field;
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::SpartanWhirError;

pub type Evaluations<F> = Vec<F>;

const EQ_EVALS_PARALLEL_MIN_LEN: usize = 1 << 14;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultilinearPoint<F>(pub Vec<F>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EqPolynomial<F> {
    pub point: MultilinearPoint<F>,
}

impl<F> EqPolynomial<F> {
    pub fn new(point: MultilinearPoint<F>) -> Self {
        Self { point }
    }
}

impl<EF: Field> EqPolynomial<EF> {
    pub fn evals_from_point(point: &[EF]) -> Vec<EF> {
        let mut evals = vec![EF::ONE];
        for &r_i in point.iter().rev() {
            let half = evals.len();
            let mut next = Vec::with_capacity(half * 2);
            for &v in &evals {
                next.push(v * (EF::ONE - r_i));
            }
            for &v in &evals {
                next.push(v * r_i);
            }
            evals = next;
        }
        evals
    }
}

impl<EF: Field + Send + Sync> EqPolynomial<EF> {
    pub fn evals_from_point_parallel(point: &[EF]) -> Vec<EF> {
        let final_len = 1usize << point.len();
        let mut evals = vec![EF::ZERO; final_len];
        evals[0] = EF::ONE;
        let mut active = 1usize;

        for &r_i in point.iter().rev() {
            let (lo, rest) = evals.split_at_mut(active);
            let hi = &mut rest[..active];
            let one_minus_r_i = EF::ONE - r_i;

            if cfg!(feature = "parallel") && active >= EQ_EVALS_PARALLEL_MIN_LEN {
                lo.par_iter_mut()
                    .zip(hi.par_iter_mut())
                    .for_each(|(lo, hi)| {
                        let v = *lo;
                        *lo = v * one_minus_r_i;
                        *hi = v * r_i;
                    });
            } else {
                for (lo, hi) in lo.iter_mut().zip(hi.iter_mut()) {
                    let v = *lo;
                    *lo = v * one_minus_r_i;
                    *hi = v * r_i;
                }
            }

            active *= 2;
        }
        evals
    }
}

pub fn evaluate_mle_table<EF: Field>(table: &[EF], point: &[EF]) -> Result<EF, SpartanWhirError> {
    if table.is_empty() || !table.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }
    if table.len() != (1usize << point.len()) {
        return Err(SpartanWhirError::InvalidRoundPolynomial);
    }

    let mut layer = table.to_vec();
    let mut active = layer.len();
    for &r_i in point {
        if active < 2 {
            return Err(SpartanWhirError::InvalidRoundPolynomial);
        }
        let half = active / 2;
        for i in 0..half {
            let lo = layer[i];
            let hi = layer[i + half];
            layer[i] = lo + r_i * (hi - lo);
        }
        active = half;
    }

    Ok(layer[0])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CubicRoundPoly<F>(pub [F; 3]); // [h(0), h(2), h(3)]

impl<F: Field> CubicRoundPoly<F> {
    pub fn eval_at_zero(&self) -> F {
        self.0[0]
    }

    pub fn eval_at_two(&self) -> F {
        self.0[1]
    }

    pub fn eval_at_three(&self) -> F {
        self.0[2]
    }

    pub fn eval_at_one_from_claim(&self, claim: F) -> F {
        claim - self.eval_at_zero()
    }

    pub fn evaluate_at(&self, r: F, claim: F) -> F {
        let h0 = self.eval_at_zero();
        let h1 = self.eval_at_one_from_claim(claim);
        let h2 = self.eval_at_two();
        let h3 = self.eval_at_three();

        let inv_two = F::TWO.inverse();
        let inv_six = F::from_u64(6).inverse();

        let l0 = -(r - F::ONE) * (r - F::from_u32(2)) * (r - F::from_u32(3)) * inv_six;
        let l1 = r * (r - F::from_u32(2)) * (r - F::from_u32(3)) * inv_two;
        let l2 = -r * (r - F::ONE) * (r - F::from_u32(3)) * inv_two;
        let l3 = r * (r - F::ONE) * (r - F::from_u32(2)) * inv_six;

        h0 * l0 + h1 * l1 + h2 * l2 + h3 * l3
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuadraticRoundPoly<F>(pub [F; 2]); // [h(0), h(2)]

impl<F: Field> QuadraticRoundPoly<F> {
    pub fn eval_at_zero(&self) -> F {
        self.0[0]
    }

    pub fn eval_at_two(&self) -> F {
        self.0[1]
    }

    pub fn eval_at_one_from_claim(&self, claim: F) -> F {
        claim - self.eval_at_zero()
    }

    pub fn evaluate_at(&self, r: F, claim: F) -> F {
        let h0 = self.eval_at_zero();
        let h1 = self.eval_at_one_from_claim(claim);
        let h2 = self.eval_at_two();

        let inv_two = F::TWO.inverse();
        let l0 = (r - F::ONE) * (r - F::from_u32(2)) * inv_two;
        let l1 = -r * (r - F::from_u32(2));
        let l2 = r * (r - F::ONE) * inv_two;

        h0 * l0 + h1 * l1 + h2 * l2
    }
}
