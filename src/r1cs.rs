use alloc::{vec, vec::Vec};
use core::cmp::max;

use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{Evaluations, SpartanWhirError};

const R1CS_PARALLEL_MATRIX_MIN_NNZ: usize = 1 << 14;
const R1CS_PARALLEL_BIND_MIN_NNZ: usize = 1 << 15;
const R1CS_PARALLEL_BIND_CHUNKS_PER_THREAD: usize = 4;
const R1CS_PARALLEL_BIND_FALLBACK_MAX_SHARDS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMatEntry<F> {
    pub row: usize,
    pub col: usize,
    pub val: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csShape<F> {
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub a: SparseMatrix<F>,
    pub b: SparseMatrix<F>,
    pub c: SparseMatrix<F>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csWitness<F> {
    pub w: Vec<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBindLayout {
    width: usize,
    a: ColumnBindMatrixLayout,
    b: ColumnBindMatrixLayout,
    c: ColumnBindMatrixLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnBindMatrixLayout {
    entry_indices_by_col: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub(crate) fn direct_bind_layout(&self) -> Result<DirectBindLayout, SpartanWhirError> {
        self.validate()?;
        DirectBindLayout::new(self)
    }
}

impl<F: Field> R1csShape<F> {
    pub fn multiply_vec(
        &self,
        z: &[F],
    ) -> Result<(Evaluations<F>, Evaluations<F>, Evaluations<F>), SpartanWhirError> {
        self.validate_matrix_vector_input(z)?;
        let az = multiply_sparse_matrix_vector(&self.a, z)?;
        let bz = multiply_sparse_matrix_vector(&self.b, z)?;
        let cz = multiply_sparse_matrix_vector(&self.c, z)?;
        Ok((az, bz, cz))
    }

    pub fn multiply_vec_parallel(
        &self,
        z: &[F],
    ) -> Result<(Evaluations<F>, Evaluations<F>, Evaluations<F>), SpartanWhirError>
    where
        F: Send + Sync,
    {
        self.validate_matrix_vector_input(z)?;

        let total_nnz = self
            .a
            .nnz()
            .checked_add(self.b.nnz())
            .and_then(|n| n.checked_add(self.c.nnz()))
            .ok_or(SpartanWhirError::InvalidR1csShape)?;

        if !(cfg!(feature = "parallel") && total_nnz >= R1CS_PARALLEL_MATRIX_MIN_NNZ) {
            return self.multiply_vec(z);
        }

        let (az, (bz, cz)) = join(
            || multiply_sparse_matrix_vector(&self.a, z),
            || {
                join(
                    || multiply_sparse_matrix_vector(&self.b, z),
                    || multiply_sparse_matrix_vector(&self.c, z),
                )
            },
        );
        Ok((az?, bz?, cz?))
    }

    fn validate_matrix_vector_input(&self, z: &[F]) -> Result<(), SpartanWhirError> {
        self.validate()?;

        let expected_len = self
            .num_vars
            .checked_add(self.num_io)
            .and_then(|n| n.checked_add(1))
            .ok_or(SpartanWhirError::InvalidWitnessLength)?;
        if z.len() != expected_len {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        Ok(())
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

    pub fn bind_row_vars_joint<EF>(&self, eq_rx: &[EF], r: EF) -> Result<Vec<EF>, SpartanWhirError>
    where
        F: Send + Sync,
        EF: ExtensionField<F> + Send + Sync,
    {
        self.validate()?;

        if eq_rx.len() != self.num_cons {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        let width = self
            .num_vars
            .checked_mul(2)
            .ok_or(SpartanWhirError::InvalidR1csShape)?;

        let mut out = vec![EF::ZERO; width];
        let r_squared = r * r;
        let (eq_b, eq_c) = join(
            || scale_eq_table(eq_rx, r),
            || scale_eq_table(eq_rx, r_squared),
        );

        accumulate_bound_rows_for_joint(&self.a, eq_rx, &mut out)?;
        accumulate_bound_rows_for_joint(&self.b, &eq_b, &mut out)?;
        accumulate_bound_rows_for_joint(&self.c, &eq_c, &mut out)?;

        Ok(out)
    }

    pub(crate) fn bind_row_vars_joint_with_layout<EF>(
        &self,
        layout: &DirectBindLayout,
        eq_rx: &[EF],
        r: EF,
    ) -> Result<Vec<EF>, SpartanWhirError>
    where
        F: Send + Sync,
        EF: ExtensionField<F> + Send + Sync,
    {
        self.validate()?;

        if eq_rx.len() != self.num_cons {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        let width = self
            .num_vars
            .checked_mul(2)
            .ok_or(SpartanWhirError::InvalidR1csShape)?;
        if layout.width != width {
            return Err(SpartanWhirError::InvalidR1csShape);
        }

        let mut out = vec![EF::ZERO; width];
        let r_squared = r * r;
        let (eq_b, eq_c) = join(
            || scale_eq_table(eq_rx, r),
            || scale_eq_table(eq_rx, r_squared),
        );

        accumulate_bound_rows_for_joint_column_layout(self, layout, eq_rx, &eq_b, &eq_c, &mut out)?;

        Ok(out)
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

impl DirectBindLayout {
    fn new<F>(shape: &R1csShape<F>) -> Result<Self, SpartanWhirError> {
        let width = shape
            .num_vars
            .checked_mul(2)
            .ok_or(SpartanWhirError::InvalidR1csShape)?;

        let layout = Self {
            width,
            a: ColumnBindMatrixLayout::new(&shape.a),
            b: ColumnBindMatrixLayout::new(&shape.b),
            c: ColumnBindMatrixLayout::new(&shape.c),
        };
        layout.validate_for(shape, width)?;
        Ok(layout)
    }

    fn validate_for<F>(&self, shape: &R1csShape<F>, width: usize) -> Result<(), SpartanWhirError> {
        if self.width != width {
            return Err(SpartanWhirError::InvalidR1csShape);
        }
        self.a.validate_for(&shape.a)?;
        self.b.validate_for(&shape.b)?;
        self.c.validate_for(&shape.c)?;
        Ok(())
    }
}

impl ColumnBindMatrixLayout {
    fn new<F>(mat: &SparseMatrix<F>) -> Self {
        let mut entry_indices_by_col: Vec<usize> = (0..mat.entries.len()).collect();
        entry_indices_by_col.sort_unstable_by_key(|&idx| mat.entries[idx].col);
        Self {
            entry_indices_by_col,
        }
    }

    fn validate_for<F>(&self, mat: &SparseMatrix<F>) -> Result<(), SpartanWhirError> {
        if self.entry_indices_by_col.len() != mat.entries.len() {
            return Err(SpartanWhirError::InvalidR1csShape);
        }

        let mut seen = vec![false; mat.entries.len()];
        let mut prev_col = None;
        for &idx in &self.entry_indices_by_col {
            if idx >= mat.entries.len() || seen[idx] {
                return Err(SpartanWhirError::InvalidR1csShape);
            }
            seen[idx] = true;

            let col = mat.entries[idx].col;
            if prev_col.is_some_and(|prev| col < prev) {
                return Err(SpartanWhirError::InvalidR1csShape);
            }
            prev_col = Some(col);
        }
        Ok(())
    }

    fn range_for_cols<F>(
        &self,
        mat: &SparseMatrix<F>,
        col_start: usize,
        col_end: usize,
    ) -> &[usize] {
        let start = self
            .entry_indices_by_col
            .partition_point(|&idx| mat.entries[idx].col < col_start);
        let end = self
            .entry_indices_by_col
            .partition_point(|&idx| mat.entries[idx].col < col_end);
        &self.entry_indices_by_col[start..end]
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
        if entry.val.is_one() {
            out[entry.col] += eq_rx[entry.row];
        } else {
            out[entry.col] += eq_rx[entry.row] * entry.val;
        }
    }
    Ok(())
}

fn scale_eq_table<EF>(eq_rx: &[EF], scale: EF) -> Vec<EF>
where
    EF: Field + Send + Sync,
{
    if cfg!(feature = "parallel") && eq_rx.len() >= R1CS_PARALLEL_BIND_MIN_NNZ {
        eq_rx.par_iter().map(|&v| scale * v).collect()
    } else {
        eq_rx.iter().map(|&v| scale * v).collect()
    }
}

fn accumulate_bound_rows_for_joint<F, EF>(
    mat: &SparseMatrix<F>,
    eq_rx: &[EF],
    out: &mut [EF],
) -> Result<(), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if out.len() < mat.num_cols {
        return Err(SpartanWhirError::InvalidR1csShape);
    }

    if !(cfg!(feature = "parallel") && mat.entries.len() >= R1CS_PARALLEL_BIND_MIN_NNZ) {
        return accumulate_bound_rows(mat, eq_rx, out);
    }

    let shard_count = current_num_threads()
        .min(R1CS_PARALLEL_BIND_FALLBACK_MAX_SHARDS)
        .min(mat.entries.len())
        .max(1);
    let chunk_len = mat.entries.len().div_ceil(shard_count);
    let out_len = out.len();
    let partials: Vec<Vec<EF>> = mat
        .entries
        .par_chunks(chunk_len)
        .map(|entries| {
            let mut local = vec![EF::ZERO; out_len];
            for entry in entries {
                if entry.val.is_one() {
                    local[entry.col] += eq_rx[entry.row];
                } else {
                    local[entry.col] += eq_rx[entry.row] * entry.val;
                }
            }
            local
        })
        .collect();

    for partial in partials {
        for (dst, value) in out.iter_mut().zip(partial) {
            *dst += value;
        }
    }

    Ok(())
}

fn accumulate_bound_rows_for_joint_column_layout<F, EF>(
    shape: &R1csShape<F>,
    layout: &DirectBindLayout,
    eq_a: &[EF],
    eq_b: &[EF],
    eq_c: &[EF],
    out: &mut [EF],
) -> Result<(), SpartanWhirError>
where
    F: Field + Send + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    let total_nnz = shape
        .a
        .nnz()
        .checked_add(shape.b.nnz())
        .and_then(|n| n.checked_add(shape.c.nnz()))
        .ok_or(SpartanWhirError::InvalidR1csShape)?;

    if !(cfg!(feature = "parallel") && total_nnz >= R1CS_PARALLEL_BIND_MIN_NNZ) {
        accumulate_bound_rows(&shape.a, eq_a, out)?;
        accumulate_bound_rows(&shape.b, eq_b, out)?;
        accumulate_bound_rows(&shape.c, eq_c, out)?;
        return Ok(());
    }

    let shard_count = current_num_threads()
        .saturating_mul(R1CS_PARALLEL_BIND_CHUNKS_PER_THREAD)
        .min(out.len())
        .max(1);
    let chunk_len = out.len().div_ceil(shard_count).max(1);

    out.par_chunks_mut(chunk_len)
        .enumerate()
        .for_each(|(chunk_idx, out_chunk)| {
            let col_start = chunk_idx * chunk_len;
            let col_end = col_start + out_chunk.len();

            accumulate_bound_rows_for_column_range(
                &shape.a, &layout.a, eq_a, col_start, col_end, out_chunk,
            );
            accumulate_bound_rows_for_column_range(
                &shape.b, &layout.b, eq_b, col_start, col_end, out_chunk,
            );
            accumulate_bound_rows_for_column_range(
                &shape.c, &layout.c, eq_c, col_start, col_end, out_chunk,
            );
        });

    Ok(())
}

fn accumulate_bound_rows_for_column_range<F, EF>(
    mat: &SparseMatrix<F>,
    layout: &ColumnBindMatrixLayout,
    eq_rx: &[EF],
    col_start: usize,
    col_end: usize,
    out_chunk: &mut [EF],
) where
    F: Field,
    EF: ExtensionField<F>,
{
    for &entry_idx in layout.range_for_cols(mat, col_start, col_end) {
        let entry = &mat.entries[entry_idx];
        let dst = &mut out_chunk[entry.col - col_start];
        if entry.val.is_one() {
            *dst += eq_rx[entry.row];
        } else {
            *dst += eq_rx[entry.row] * entry.val;
        }
    }
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

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{engine::F, EqPolynomial, QuarticBinExtension as EF};

    fn repeated_entries(seed: usize, num_rows: usize, num_cols: usize) -> Vec<SparseMatEntry<F>> {
        let entry_count = (R1CS_PARALLEL_BIND_MIN_NNZ / 3) + 257;
        (0..entry_count)
            .map(|idx| {
                let val = if idx % 5 == 0 {
                    F::ONE
                } else {
                    F::from_u32(((idx + seed) % 17) as u32 + 2)
                };
                SparseMatEntry {
                    row: (idx * 7 + seed) % num_rows,
                    col: (idx * 11 + seed * 3) % num_cols,
                    val,
                }
            })
            .collect()
    }

    #[test]
    fn direct_bind_layout_matches_joint_bind() {
        let num_cons = 64;
        let num_vars = 64;
        let num_io = 0;
        let num_cols = num_vars + num_io + 1;
        let shape = R1csShape {
            num_cons,
            num_vars,
            num_io,
            a: SparseMatrix {
                num_rows: num_cons,
                num_cols,
                entries: repeated_entries(1, num_cons, num_cols),
            },
            b: SparseMatrix {
                num_rows: num_cons,
                num_cols,
                entries: repeated_entries(2, num_cons, num_cols),
            },
            c: SparseMatrix {
                num_rows: num_cons,
                num_cols,
                entries: repeated_entries(3, num_cons, num_cols),
            },
        };
        let point: Vec<EF> = [2, 3, 5, 7, 11, 13]
            .into_iter()
            .map(|v| EF::from(F::from_u32(v)))
            .collect();
        let eq_rx = EqPolynomial::evals_from_point(&point);
        let r = EF::from(F::from_u32(19));

        let layout = shape.direct_bind_layout().expect("layout builds");
        let expected = shape
            .bind_row_vars_joint(&eq_rx, r)
            .expect("joint bind succeeds");
        let actual = shape
            .bind_row_vars_joint_with_layout(&layout, &eq_rx, r)
            .expect("layout bind succeeds");

        assert_eq!(actual, expected);
    }

    #[test]
    fn direct_bind_layout_validation_rejects_bad_indices() {
        let shape = R1csShape {
            num_cons: 2,
            num_vars: 2,
            num_io: 0,
            a: SparseMatrix {
                num_rows: 2,
                num_cols: 3,
                entries: vec![
                    SparseMatEntry {
                        row: 0,
                        col: 1,
                        val: F::ONE,
                    },
                    SparseMatEntry {
                        row: 1,
                        col: 0,
                        val: F::ONE,
                    },
                ],
            },
            b: SparseMatrix {
                num_rows: 2,
                num_cols: 3,
                entries: vec![],
            },
            c: SparseMatrix {
                num_rows: 2,
                num_cols: 3,
                entries: vec![],
            },
        };
        let mut layout = shape.direct_bind_layout().expect("layout builds");
        layout.a.entry_indices_by_col = vec![0, 1];

        assert_eq!(
            layout.validate_for(&shape, 4),
            Err(SpartanWhirError::InvalidR1csShape)
        );

        layout.a.entry_indices_by_col = vec![1, 1];
        assert_eq!(
            layout.validate_for(&shape, 4),
            Err(SpartanWhirError::InvalidR1csShape)
        );
    }
}
