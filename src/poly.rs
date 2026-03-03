use alloc::vec::Vec;

pub type Evaluations<F> = Vec<F>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultilinearPoint<F>(pub Vec<F>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqPolynomial<F> {
    pub point: MultilinearPoint<F>,
}

impl<F> EqPolynomial<F> {
    pub fn new(point: MultilinearPoint<F>) -> Self {
        Self { point }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CubicRoundPoly<F>(pub [F; 3]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuadraticRoundPoly<F>(pub [F; 2]);
