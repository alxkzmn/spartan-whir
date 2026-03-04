use alloc::{vec, vec::Vec};
use core::cmp::max;

use p3_field::{ExtensionField, Field};

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
        F: Clone,
    {
        self.validate()?;

        let num_vars_target = max(
            self.num_vars,
            self.num_io
                .checked_add(1)
                .ok_or(SpartanWhirError::PaddingError)?,
        );
        let num_vars_padded = num_vars_target
            .checked_next_power_of_two()
            .ok_or(SpartanWhirError::PaddingError)?;
        let num_cons_padded = self
            .num_cons
            .checked_next_power_of_two()
            .ok_or(SpartanWhirError::PaddingError)?;

        if self.num_io >= num_vars_padded {
            return Err(SpartanWhirError::PaddingError);
        }

        let vars_delta = num_vars_padded.saturating_sub(self.num_vars);
        let num_cols_padded = num_vars_padded
            .checked_add(self.num_io)
            .and_then(|n| n.checked_add(1))
            .ok_or(SpartanWhirError::PaddingError)?;

        let pad_matrix = |m: &SparseMatrix<F>| -> SparseMatrix<F> {
            let mut entries = m.entries.clone();
            if vars_delta > 0 {
                for entry in &mut entries {
                    // Preserve layout [W | 1 | X] while adding witness columns.
                    if entry.col >= self.num_vars {
                        entry.col += vars_delta;
                    }
                }
            }
            SparseMatrix {
                num_rows: num_cons_padded,
                num_cols: num_cols_padded,
                entries,
            }
        };

        Ok(Self {
            num_cons: num_cons_padded,
            num_vars: num_vars_padded,
            num_io: self.num_io,
            a: pad_matrix(&self.a),
            b: pad_matrix(&self.b),
            c: pad_matrix(&self.c),
        })
    }
}

impl<F: Field> R1csShape<F> {
    pub fn multiply_vec(
        &self,
        z: &[F],
    ) -> Result<(Evaluations<F>, Evaluations<F>, Evaluations<F>), SpartanWhirError> {
        self.validate()?;

        let expected_len = self
            .num_vars
            .checked_add(self.num_io)
            .and_then(|n| n.checked_add(1))
            .ok_or(SpartanWhirError::InvalidWitnessLength)?;
        if z.len() != expected_len {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        let az = multiply_sparse_matrix_vector(&self.a, z)?;
        let bz = multiply_sparse_matrix_vector(&self.b, z)?;
        let cz = multiply_sparse_matrix_vector(&self.c, z)?;
        Ok((az, bz, cz))
    }

    pub fn witness_to_mle(&self, witness: &[F]) -> Result<Evaluations<F>, SpartanWhirError> {
        self.validate()?;

        if witness.len() > self.num_vars {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        let mut out = witness.to_vec();
        if out.len() < self.num_vars {
            out.resize(self.num_vars, F::ZERO);
        }
        Ok(out)
    }

    pub fn bind_row_vars<EF>(
        &self,
        eq_rx: &[EF],
    ) -> Result<(Vec<EF>, Vec<EF>, Vec<EF>), SpartanWhirError>
    where
        EF: ExtensionField<F>,
    {
        self.validate()?;

        if eq_rx.len() != self.num_cons {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        let width = self
            .num_vars
            .checked_mul(2)
            .ok_or(SpartanWhirError::InvalidR1csShape)?;

        let mut a_evals = vec![EF::ZERO; width];
        let mut b_evals = vec![EF::ZERO; width];
        let mut c_evals = vec![EF::ZERO; width];

        accumulate_bound_rows(&self.a, eq_rx, &mut a_evals)?;
        accumulate_bound_rows(&self.b, eq_rx, &mut b_evals)?;
        accumulate_bound_rows(&self.c, eq_rx, &mut c_evals)?;

        Ok((a_evals, b_evals, c_evals))
    }

    pub fn evaluate_with_tables<EF>(
        &self,
        t_x: &[EF],
        t_y: &[EF],
    ) -> Result<(EF, EF, EF), SpartanWhirError>
    where
        EF: ExtensionField<F>,
    {
        self.validate()?;

        if t_x.len() != self.num_cons || t_y.len() < self.a.num_cols {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        Ok((
            evaluate_sparse_matrix_with_tables(&self.a, t_x, t_y)?,
            evaluate_sparse_matrix_with_tables(&self.b, t_x, t_y)?,
            evaluate_sparse_matrix_with_tables(&self.c, t_x, t_y)?,
        ))
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

fn multiply_sparse_matrix_vector<F: Field>(
    mat: &SparseMatrix<F>,
    z: &[F],
) -> Result<Vec<F>, SpartanWhirError> {
    if z.len() != mat.num_cols {
        return Err(SpartanWhirError::InvalidWitnessLength);
    }

    let mut out = vec![F::ZERO; mat.num_rows];
    for entry in &mat.entries {
        out[entry.row] += entry.val * z[entry.col];
    }
    Ok(out)
}

fn accumulate_bound_rows<F, EF>(
    mat: &SparseMatrix<F>,
    eq_rx: &[EF],
    out: &mut [EF],
) -> Result<(), SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    if out.len() < mat.num_cols {
        return Err(SpartanWhirError::InvalidR1csShape);
    }

    for entry in &mat.entries {
        out[entry.col] += eq_rx[entry.row] * EF::from(entry.val);
    }
    Ok(())
}

fn evaluate_sparse_matrix_with_tables<F, EF>(
    mat: &SparseMatrix<F>,
    t_x: &[EF],
    t_y: &[EF],
) -> Result<EF, SpartanWhirError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    if t_x.len() != mat.num_rows || t_y.len() < mat.num_cols {
        return Err(SpartanWhirError::InvalidWitnessLength);
    }

    let mut acc = EF::ZERO;
    for entry in &mat.entries {
        acc += t_x[entry.row] * t_y[entry.col] * EF::from(entry.val);
    }
    Ok(acc)
}
