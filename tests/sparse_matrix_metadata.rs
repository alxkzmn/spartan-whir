mod common;

use spartan_whir::{SparseMatEntry, SparseMatrix, SpartanWhirError};

#[test]
fn sparse_matrix_helpers_report_expected_counts() {
    let empty: SparseMatrix<u64> = SparseMatrix {
        num_rows: 2,
        num_cols: 3,
        entries: vec![],
    };
    assert!(empty.is_empty());
    assert_eq!(empty.nnz(), 0);

    let non_empty: SparseMatrix<u64> = SparseMatrix {
        num_rows: 2,
        num_cols: 3,
        entries: vec![SparseMatEntry {
            row: 1,
            col: 2,
            val: 5,
        }],
    };
    assert!(!non_empty.is_empty());
    assert_eq!(non_empty.nnz(), 1);
}

#[test]
fn shape_validate_rejects_dimension_mismatch() {
    let mut shape = common::sample_shape();
    shape.a.num_cols = 999;

    assert_eq!(shape.validate(), Err(SpartanWhirError::InvalidR1csShape));
}

#[test]
fn shape_validate_rejects_out_of_bounds_entries() {
    let mut shape = common::sample_shape();
    shape.a.entries.push(SparseMatEntry {
        row: 7,
        col: 0,
        val: 1,
    });

    assert_eq!(shape.validate(), Err(SpartanWhirError::InvalidR1csShape));
}

#[test]
fn shape_validate_rejects_zero_constraints() {
    let mut shape = common::sample_shape();
    shape.num_cons = 0;
    shape.a.num_rows = 0;
    shape.b.num_rows = 0;
    shape.c.num_rows = 0;

    assert_eq!(shape.validate(), Err(SpartanWhirError::InvalidR1csShape));
}

#[test]
fn shape_validate_rejects_column_count_overflow() {
    let shape = spartan_whir::R1csShape {
        num_cons: 1,
        num_vars: usize::MAX,
        num_io: 1,
        a: SparseMatrix::<u64> {
            num_rows: 1,
            num_cols: 1,
            entries: vec![],
        },
        b: SparseMatrix::<u64> {
            num_rows: 1,
            num_cols: 1,
            entries: vec![],
        },
        c: SparseMatrix::<u64> {
            num_rows: 1,
            num_cols: 1,
            entries: vec![],
        },
    };

    assert_eq!(shape.validate(), Err(SpartanWhirError::InvalidR1csShape));
}
