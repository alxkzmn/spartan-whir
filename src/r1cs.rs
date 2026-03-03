use alloc::vec::Vec;

use crate::{Evaluations, SpartanWhirError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatEntry<F> {
    pub row: usize,
    pub col: usize,
    pub val: F,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix<F> {
    pub num_rows: usize,
    pub num_cols: usize,
    pub entries: Vec<SparseMatEntry<F>>,
}

impl<F> SparseMatrix<F> {
    pub fn nnz(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1csShape<F> {
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub a: SparseMatrix<F>,
    pub b: SparseMatrix<F>,
    pub c: SparseMatrix<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1csWitness<F> {
    pub w: Vec<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1csInstance<F, C> {
    pub public_inputs: Vec<F>,
    pub witness_commitment: C,
}

impl<F> R1csShape<F> {
    pub fn validate(&self) -> Result<(), SpartanWhirError> {
        if self.num_cons == 0 {
            return Err(SpartanWhirError::InvalidR1csShape);
        }

        let expected_cols = self
            .num_vars
            .checked_add(self.num_io)
            .and_then(|n| n.checked_add(1))
            .ok_or(SpartanWhirError::InvalidR1csShape)?;

        validate_matrix_dimensions(&self.a, self.num_cons, expected_cols)?;
        validate_matrix_dimensions(&self.b, self.num_cons, expected_cols)?;
        validate_matrix_dimensions(&self.c, self.num_cons, expected_cols)?;

        validate_matrix_entries(&self.a)?;
        validate_matrix_entries(&self.b)?;
        validate_matrix_entries(&self.c)?;

        Ok(())
    }

    pub fn pad_regular(&self) -> Result<Self, SpartanWhirError>
    where
        Self: Clone,
    {
        Err(SpartanWhirError::Unimplemented("r1cs::pad_regular"))
    }

    pub fn multiply_vec(
        &self,
        _z: &[F],
    ) -> Result<(Evaluations<F>, Evaluations<F>, Evaluations<F>), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("r1cs::multiply_vec"))
    }

    pub fn evaluate_with_tables(&self, _z: &[F]) -> Result<(F, F, F), SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented(
            "r1cs::evaluate_with_tables",
        ))
    }

    pub fn witness_to_mle(&self, _witness: &[F]) -> Result<Evaluations<F>, SpartanWhirError> {
        Err(SpartanWhirError::Unimplemented("r1cs::witness_to_mle"))
    }
}

fn validate_matrix_dimensions<F>(
    mat: &SparseMatrix<F>,
    expected_rows: usize,
    expected_cols: usize,
) -> Result<(), SpartanWhirError> {
    if mat.num_rows != expected_rows || mat.num_cols != expected_cols {
        return Err(SpartanWhirError::InvalidR1csShape);
    }
    Ok(())
}

fn validate_matrix_entries<F>(mat: &SparseMatrix<F>) -> Result<(), SpartanWhirError> {
    for entry in &mat.entries {
        if entry.row >= mat.num_rows || entry.col >= mat.num_cols {
            return Err(SpartanWhirError::InvalidR1csShape);
        }
    }
    Ok(())
}
