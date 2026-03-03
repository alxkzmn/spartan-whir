use alloc::vec::Vec;

use crate::{CubicRoundPoly, MultilinearPoint, QuadraticRoundPoly, R1csShape, SpartanWhirError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterSumcheckProof<F> {
    pub rounds: Vec<CubicRoundPoly<F>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerSumcheckProof<F> {
    pub rounds: Vec<QuadraticRoundPoly<F>>,
}

pub fn prove_outer<F, C>(
    _shape: &R1csShape<F>,
    _az: &[F],
    _bz: &[F],
    _cz: &[F],
    _tau: &MultilinearPoint<F>,
    _challenger: &mut C,
) -> Result<(OuterSumcheckProof<F>, (F, F, F), MultilinearPoint<F>), SpartanWhirError> {
    Err(SpartanWhirError::Unimplemented("sumcheck::prove_outer"))
}

pub fn verify_outer<F>(
    _proof: &OuterSumcheckProof<F>,
    _claims: &(F, F, F),
    _r_x: &MultilinearPoint<F>,
) -> Result<(), SpartanWhirError> {
    Err(SpartanWhirError::Unimplemented("sumcheck::verify_outer"))
}

pub fn prove_inner<F, C>(
    _shape: &R1csShape<F>,
    _poly_abc_eval: &[F],
    _z: &[F],
    _r_x: &MultilinearPoint<F>,
    _challenger: &mut C,
) -> Result<(InnerSumcheckProof<F>, F, MultilinearPoint<F>), SpartanWhirError> {
    Err(SpartanWhirError::Unimplemented("sumcheck::prove_inner"))
}

pub fn verify_inner<F>(
    _proof: &InnerSumcheckProof<F>,
    _eval_w: &F,
    _r_y: &MultilinearPoint<F>,
) -> Result<(), SpartanWhirError> {
    Err(SpartanWhirError::Unimplemented("sumcheck::verify_inner"))
}
