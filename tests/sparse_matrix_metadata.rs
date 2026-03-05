mod common;

use p3_field::PrimeCharacteristicRing;

use spartan_whir::{engine::F, SparseMatEntry, SparseMatrix, SpartanWhirError};

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

#[test]
fn pad_regular_renumbers_constant_and_io_columns() {
    let shape = common::koala_shape_single_constraint(2);
    let padded = shape.pad_regular().expect("padding succeeds");

    assert_eq!(padded.num_vars, 2);
    assert_eq!(padded.a.num_cols, 4);
    assert_eq!(padded.b.entries[0].col, 2); // shifted const column
    assert_eq!(padded.c.entries[0].col, 3); // shifted public input column
}

#[test]
fn multiply_vec_matches_expected_constraint_values() {
    let shape = common::koala_shape_single_constraint(2)
        .pad_regular()
        .expect("padding succeeds");
    let z = vec![F::from_u32(4), F::ZERO, F::ONE, F::from_u32(4)];

    let (az, bz, cz) = shape.multiply_vec(&z).expect("multiply succeeds");
    assert_eq!(az.len(), 2);
    assert_eq!(bz.len(), 2);
    assert_eq!(cz.len(), 2);
    assert_eq!(az[0], F::from_u32(4));
    assert_eq!(bz[0], F::ONE);
    assert_eq!(cz[0], F::from_u32(4));
}

#[test]
fn bind_row_vars_and_evaluate_with_tables_are_consistent() {
    let shape = common::koala_shape_single_constraint(2)
        .pad_regular()
        .expect("padding succeeds");

    let r_x = vec![spartan_whir::EF::from(F::from_u32(3))];
    let r_y = vec![
        spartan_whir::EF::from(F::from_u32(2)),
        spartan_whir::EF::from(F::from_u32(5)),
    ];
    let t_x = spartan_whir::EqPolynomial::evals_from_point(&r_x);
    let t_y = spartan_whir::EqPolynomial::evals_from_point(&r_y);

    let (bound_a, bound_b, bound_c) = shape.bind_row_vars(&t_x).expect("bind succeeds");
    let (eval_a, eval_b, eval_c) = shape
        .evaluate_with_tables(&t_x, &t_y)
        .expect("table evaluation succeeds");

    let dot = |v: &[spartan_whir::EF]| {
        v.iter()
            .zip(t_y.iter())
            .fold(spartan_whir::EF::ZERO, |acc, (&x, &y)| acc + x * y)
    };
    assert_eq!(eval_a, dot(&bound_a));
    assert_eq!(eval_b, dot(&bound_b));
    assert_eq!(eval_c, dot(&bound_c));
}
