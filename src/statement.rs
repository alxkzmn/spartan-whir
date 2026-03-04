use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{Evaluations, MultilinearPoint, SpartanWhirEngine, SpartanWhirError};

pub struct PointEvalClaim<E: SpartanWhirEngine> {
    pub point: MultilinearPoint<E::EF>,
    pub value: E::EF,
}

pub struct LinearConstraintClaim<E: SpartanWhirEngine> {
    pub coefficients: Evaluations<E::F>,
    pub expected: E::EF,
}

/// Build statements incrementally, then finalize into `PcsStatement`.
///
/// ```compile_fail
/// use spartan_whir::{PcsStatement, PcsStatementBuilder, SpartanWhirEngine};
///
/// struct DummyEngine;
/// impl SpartanWhirEngine for DummyEngine {
///     type F = u64;
///     type EF = u64;
///     type Challenger = ();
///     type Hash = ();
///     type Compress = ();
///     type W = u64;
///     const DIGEST_ELEMS: usize = 4;
/// }
///
/// fn needs_finalized(_stmt: &PcsStatement<DummyEngine>) {}
///
/// let builder = PcsStatementBuilder::<DummyEngine>::new();
/// needs_finalized(&builder);
/// ```
pub struct PcsStatementBuilder<E: SpartanWhirEngine> {
    point_evals: Vec<PointEvalClaim<E>>,
    linear_constraints: Vec<LinearConstraintClaim<E>>,
    marker: PhantomData<E>,
}

impl<E: SpartanWhirEngine> Default for PcsStatementBuilder<E> {
    fn default() -> Self {
        Self {
            point_evals: Vec::new(),
            linear_constraints: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<E: SpartanWhirEngine> PcsStatementBuilder<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_point_eval(mut self, claim: PointEvalClaim<E>) -> Self {
        self.point_evals.push(claim);
        self
    }

    pub fn add_linear_constraint(mut self, claim: LinearConstraintClaim<E>) -> Self {
        self.linear_constraints.push(claim);
        self
    }

    pub fn finalize(self) -> Result<PcsStatement<E>, SpartanWhirError> {
        if self.point_evals.is_empty() && self.linear_constraints.is_empty() {
            return Err(SpartanWhirError::InvalidConfig);
        }

        Ok(PcsStatement {
            point_evals: self.point_evals,
            linear_constraints: self.linear_constraints,
            marker: PhantomData,
        })
    }
}

pub struct PcsStatement<E: SpartanWhirEngine> {
    point_evals: Vec<PointEvalClaim<E>>,
    linear_constraints: Vec<LinearConstraintClaim<E>>,
    marker: PhantomData<E>,
}

impl<E: SpartanWhirEngine> PcsStatement<E> {
    pub fn point_evals(&self) -> &[PointEvalClaim<E>] {
        &self.point_evals
    }

    pub fn linear_constraints(&self) -> &[LinearConstraintClaim<E>] {
        &self.linear_constraints
    }
}
