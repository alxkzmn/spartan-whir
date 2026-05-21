use p3_field::{PrimeCharacteristicRing, PrimeField32};

use spartan_whir::{
    check_spark_memory_product_equations, compare_spark_layout_profile, compare_spark_layouts,
    compute_spark_read_tables, engine::F, evaluate_mle_table, new_keccak_challenger,
    preprocess_joint_spark_tables, preprocess_shared_union_spark_tables, preprocess_spark_tables,
    prove_spark_batched_memory_products, prove_spark_batched_product, prove_spark_grand_product,
    prove_spark_memory_grand_products, prove_spark_memory_products, prove_spark_value_sumcheck,
    prove_spark_value_sumcheck_with_reads, spark_selector_from_high_bits,
    verify_spark_batched_memory_product_claims, verify_spark_batched_memory_products_with_tables,
    verify_spark_batched_product, verify_spark_grand_product_with_values,
    verify_spark_memory_grand_product_claims, verify_spark_memory_grand_products_with_tables,
    verify_spark_memory_leaf_claims_with_tables, verify_spark_memory_products_with_tables,
    verify_spark_value_sumcheck, verify_spark_value_sumcheck_with_openings,
    verify_spark_value_sumcheck_with_tables, EqPolynomial, MultilinearPoint, R1csShape,
    SparkDotProductCircuit, SparkGrandProductTree, SparkLayoutDecision, SparkLayoutKind,
    SparkMatrixSlot, SparkShapeProfile, SparkSolidityGasModel, SparkValueFinalEvals,
    SparseMatEntry, SparseMatrix, SpartanWhirError,
};

fn fe(value: u32) -> F {
    F::from_u32(value)
}

fn q(value: u32) -> spartan_whir::QuinticExtension {
    spartan_whir::QuinticExtension::from(fe(value))
}

fn dotproduct_claim(
    dotproduct: &SparkDotProductCircuit<spartan_whir::QuinticExtension>,
) -> spartan_whir::QuinticExtension {
    dotproduct
        .left
        .iter()
        .zip(&dotproduct.right)
        .zip(&dotproduct.weight)
        .fold(
            spartan_whir::QuinticExtension::ZERO,
            |acc, ((&l, &r), &w)| acc + l * r * w,
        )
}

fn direct_matrix_eval(
    vals: &[F],
    erow: &[spartan_whir::QuinticExtension],
    ecol: &[spartan_whir::QuinticExtension],
) -> spartan_whir::QuinticExtension {
    vals.iter().zip(erow).zip(ecol).fold(
        spartan_whir::QuinticExtension::ZERO,
        |acc, ((&val, &row), &col)| acc + spartan_whir::QuinticExtension::from(val) * row * col,
    )
}

fn entry(row: usize, col: usize, val: u32) -> SparseMatEntry<F> {
    SparseMatEntry {
        row,
        col,
        val: fe(val),
    }
}

fn shape(
    num_rows: usize,
    num_cols: usize,
    a: Vec<SparseMatEntry<F>>,
    b: Vec<SparseMatEntry<F>>,
    c: Vec<SparseMatEntry<F>>,
) -> R1csShape<F> {
    R1csShape {
        num_cons: num_rows,
        num_vars: num_cols - 1,
        num_io: 0,
        a: SparseMatrix {
            num_rows,
            num_cols,
            entries: a,
        },
        b: SparseMatrix {
            num_rows,
            num_cols,
            entries: b,
        },
        c: SparseMatrix {
            num_rows,
            num_cols,
            entries: c,
        },
    }
}

fn canonical_shape_with_public(
    a: Vec<SparseMatEntry<F>>,
    b: Vec<SparseMatEntry<F>>,
    c: Vec<SparseMatEntry<F>>,
) -> R1csShape<F> {
    R1csShape {
        num_cons: 2,
        num_vars: 2,
        num_io: 1,
        a: SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: a,
        },
        b: SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: b,
        },
        c: SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: c,
        },
    }
}

#[test]
fn joint_tables_support_zero_matrix_slot() {
    let shape = shape(4, 4, vec![entry(0, 0, 3)], vec![entry(1, 1, 5)], vec![]);

    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");

    assert_eq!(tables.slot_mapping[2], SparkMatrixSlot::C);
    assert_eq!(tables.vals[2], F::ZERO);
    assert_eq!(tables.vals[3], F::ZERO);
}

#[test]
fn joint_tables_preserve_duplicate_entries() {
    let shape = shape(4, 4, vec![entry(1, 2, 3), entry(1, 2, 4)], vec![], vec![]);

    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");

    assert_eq!(tables.rows[0], fe(1));
    assert_eq!(tables.rows[1], fe(1));
    assert_eq!(tables.cols[0], fe(2));
    assert_eq!(tables.cols[1], fe(2));
    assert_eq!(tables.vals[0], fe(3));
    assert_eq!(tables.vals[1], fe(4));
}

#[test]
fn shared_union_tables_aggregate_duplicates_and_sort_lexicographically() {
    let shape = shape(
        4,
        4,
        vec![entry(2, 1, 3), entry(0, 0, 4), entry(2, 1, 5)],
        vec![entry(0, 0, 7)],
        vec![entry(3, 2, 11)],
    );

    let tables = preprocess_shared_union_spark_tables(&shape).expect("preprocess succeeds");

    assert_eq!(tables.layout, SparkLayoutKind::SharedUnion);
    assert_eq!(tables.value_domain_size, 4);
    assert_eq!(tables.union_nnz, 3);
    assert_eq!(tables.raw_nnz, [3, 1, 1]);
    assert_eq!(tables.aggregated_nnz, [2, 1, 1]);
    assert_eq!((tables.rows[0], tables.cols[0]), (fe(0), fe(0)));
    assert_eq!(
        (tables.val_a[0], tables.val_b[0], tables.val_c[0]),
        (fe(4), fe(7), F::ZERO)
    );
    assert_eq!((tables.rows[1], tables.cols[1]), (fe(2), fe(1)));
    assert_eq!(
        (tables.val_a[1], tables.val_b[1], tables.val_c[1]),
        (fe(8), F::ZERO, F::ZERO)
    );
    assert_eq!((tables.rows[2], tables.cols[2]), (fe(3), fe(2)));
    assert_eq!(
        (tables.val_a[2], tables.val_b[2], tables.val_c[2]),
        (F::ZERO, F::ZERO, fe(11))
    );
    assert_eq!((tables.rows[3], tables.cols[3]), (F::ZERO, F::ZERO));
    assert_eq!(
        (tables.val_a[3], tables.val_b[3], tables.val_c[3]),
        (F::ZERO, F::ZERO, F::ZERO)
    );

    let report = tables
        .verifier_operation_report(5)
        .expect("operation report succeeds");
    assert_eq!(report.setup_commitments, 2);
    assert_eq!(report.per_proof_commitments, 1);
    assert_eq!(report.padded_value_domain_size, tables.value_domain_size);
    assert_eq!(
        report.padded_memory_domain_size,
        tables
            .row_memory_size
            .max(tables.col_memory_size)
            .next_power_of_two()
    );
    assert_eq!(
        report.proof_ops_layers,
        tables.value_domain_size.ilog2() as usize
    );
    assert_eq!(
        report.proof_ops_sumcheck_rounds,
        report.proof_ops_layers * (report.proof_ops_layers - 1) / 2
    );
    assert_eq!(
        report.proof_mem_sumcheck_rounds,
        report.proof_mem_layers * (report.proof_mem_layers - 1) / 2
    );
    assert_eq!(
        report.total_product_sumcheck_rounds,
        report.proof_ops_sumcheck_rounds + report.proof_mem_sumcheck_rounds
    );
    assert_eq!(report.proof_ops_product_count, 4);
    assert_eq!(report.proof_ops_dotproduct_count, 6);
    assert_eq!(report.proof_mem_product_count, 4);
    assert_eq!(report.proof_mem_dotproduct_count, 0);
    assert_eq!(
        report.fixed_value_domain_slots,
        8 * tables.value_domain_size
    );
    assert_eq!(report.proof_time_read_columns, 16);
    assert_eq!(
        report.proof_time_read_domain_slots,
        16 * tables.value_domain_size
    );
    assert_eq!(report.extension_element_bytes, 20);
    assert_eq!(
        report.product_round_poly_ext_elements,
        3 * report.total_product_sumcheck_rounds
    );
    assert_eq!(
        report.product_layer_eval_ext_elements,
        8 * report.proof_ops_layers + 18 + 8 * report.proof_mem_layers
    );
    assert_eq!(report.product_root_claim_ext_elements, 14);
    assert_eq!(report.product_wrapper_ext_elements, 13);
    assert_eq!(
        report.product_proof_ext_elements,
        report.product_round_poly_ext_elements
            + report.product_layer_eval_ext_elements
            + report.product_root_claim_ext_elements
            + report.product_wrapper_ext_elements
    );
    assert_eq!(report.fixed_opening_eval_ext_elements, 12);
    assert_eq!(report.read_opening_eval_ext_elements, 30);
    assert_eq!(report.opening_eval_ext_elements, 42);
    assert_eq!(report.duplicate_commitment_bytes, 96);
    assert_eq!(
        report.estimated_spark_payload_bytes_excluding_whir,
        report.estimated_product_proof_bytes
            + report.estimated_opening_eval_bytes
            + report.duplicate_commitment_bytes
    );
}

#[test]
fn disjoint_shape_falls_back_to_per_matrix_layout() {
    let shape = shape(
        4,
        4,
        vec![entry(0, 0, 1), entry(1, 0, 1)],
        vec![entry(0, 1, 2), entry(1, 1, 2)],
        vec![entry(0, 2, 3), entry(1, 2, 3)],
    );

    let report = compare_spark_layouts(&shape).expect("layout comparison succeeds");
    assert_eq!(report.decision, SparkLayoutDecision::PerMatrix);

    let tables = preprocess_spark_tables(&shape).expect("preprocess succeeds");
    assert_eq!(tables.layout, SparkLayoutKind::PerMatrix);
    assert_eq!(tables.value_domain_size, 8);
    assert_eq!(tables.val_a[0], fe(1));
    assert_eq!(tables.val_b[tables.matrix_nnz_padded], fe(2));
    assert_eq!(tables.val_c[2 * tables.matrix_nnz_padded], fe(3));
}

#[test]
fn layout_report_exposes_imbalanced_wasted_slots() {
    let shape = shape(
        16,
        16,
        vec![entry(0, 0, 1)],
        (0..9).map(|i| entry(i, i, 2)).collect(),
        vec![entry(10, 10, 3)],
    );

    let report = compare_spark_layouts(&shape).expect("layout comparison succeeds");

    assert_eq!(report.decision, SparkLayoutDecision::SharedUnion);
    assert!(report.joint.wasted_value_slots > 0);
    assert!(report.per_matrix.wasted_value_slots > 0);
    assert_eq!(report.joint.setup_commitments, 2);
    assert_eq!(report.per_matrix.setup_commitments, 2);
}

#[test]
fn profile_layout_report_supports_provekit_sha_2k_shape_without_entries() {
    let report = compare_spark_layout_profile(SparkShapeProfile {
        num_rows: 345_399,
        num_cols: 612_724,
        nnz_a: 700_000,
        nnz_b: 700_000,
        nnz_c: 658_122,
        union_nnz: 760_000,
    })
    .expect("profile comparison succeeds");

    assert_eq!(report.joint.setup_commitments, 2);
    assert_eq!(report.joint.per_proof_commitments, 1);
    assert_eq!(report.per_matrix.setup_commitments, 2);
    assert_eq!(report.per_matrix.per_proof_commitments, 1);

    let operation_report = report
        .joint
        .verifier_operation_report(345_399, 612_724, 5)
        .expect("operation report succeeds");
    assert_eq!(operation_report.setup_commitments, 2);
    assert_eq!(operation_report.per_proof_commitments, 1);
    assert_eq!(operation_report.padded_value_domain_size, 1_048_576);
    assert_eq!(operation_report.padded_memory_domain_size, 1_048_576);
    assert_eq!(operation_report.proof_ops_layers, 20);
    assert_eq!(operation_report.proof_mem_layers, 20);
    assert_eq!(operation_report.proof_ops_sumcheck_rounds, 190);
    assert_eq!(operation_report.proof_mem_sumcheck_rounds, 190);
    assert_eq!(operation_report.total_product_sumcheck_rounds, 380);
    assert_eq!(operation_report.proof_time_read_columns, 16);
    assert_eq!(operation_report.estimated_opening_eval_bytes, 840);

    let gas = operation_report
        .estimate_solidity_gas(SparkSolidityGasModel {
            cubic_sumcheck_round_replay_gas: 1_000,
            whir_opening_execution_gas: 1_000_000,
            whir_opening_calldata_bytes: 10_000,
            calldata_gas_per_nonzero_byte: 16,
        })
        .expect("gas estimate succeeds");
    assert_eq!(gas.whir_opening_count, 3);
    assert_eq!(gas.product_sumcheck_replay_gas, 380_000);
    assert_eq!(gas.whir_opening_execution_gas, 3_000_000);
    assert_eq!(gas.spark_payload_calldata_gas_upper_bound, 496_576);
    assert_eq!(gas.whir_opening_calldata_gas_upper_bound, 480_000);
    assert_eq!(gas.total_gas_upper_bound, 4_356_576);
}

#[test]
fn packed_index_guard_rejects_base_field_overflow() {
    let bad_rows = R1csShape {
        num_cons: F::ORDER_U32 as usize,
        num_vars: 1,
        num_io: 0,
        a: SparseMatrix {
            num_rows: F::ORDER_U32 as usize,
            num_cols: 2,
            entries: vec![],
        },
        b: SparseMatrix {
            num_rows: F::ORDER_U32 as usize,
            num_cols: 2,
            entries: vec![],
        },
        c: SparseMatrix {
            num_rows: F::ORDER_U32 as usize,
            num_cols: 2,
            entries: vec![],
        },
    };

    assert_eq!(
        preprocess_joint_spark_tables(&bad_rows),
        Err(SpartanWhirError::InvalidR1csShape)
    );
}

#[test]
fn selector_slot_mapping_is_explicit() {
    let r = fe(9);

    assert_eq!(spark_selector_from_high_bits(F::ZERO, F::ZERO, r), F::ONE);
    assert_eq!(spark_selector_from_high_bits(F::ZERO, F::ONE, r), r);
    assert_eq!(spark_selector_from_high_bits(F::ONE, F::ZERO, r), r * r);
    assert_eq!(spark_selector_from_high_bits(F::ONE, F::ONE, r), F::ZERO);
}

#[test]
fn value_sumcheck_matches_direct_matrix_evaluation() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);
    let r = spartan_whir::QuinticExtension::from(fe(9));
    let read_tables = compute_spark_read_tables(&tables, &r_x, &r_y).expect("read tables compute");

    let t_x = EqPolynomial::evals_from_point(&r_x.0);
    let t_y = EqPolynomial::evals_from_point(&r_y.0);
    let (eval_a, eval_b, eval_c) = shape
        .evaluate_with_tables(&t_x, &t_y)
        .expect("direct evaluation succeeds");
    let expected = eval_a + r * eval_b + r * r * eval_c;

    let mut prover_challenger = new_keccak_challenger();
    let (proof, _, initial_claim) =
        prove_spark_value_sumcheck_with_reads(&tables, &read_tables, r, &mut prover_challenger)
            .expect("value sumcheck proves");
    assert!(proof.rounds.iter().all(|round| round.0.len() == 4));

    assert_eq!(initial_claim, expected);

    let mut verifier_challenger = new_keccak_challenger();
    let (alpha, final_claim) = verify_spark_value_sumcheck_with_tables(
        &tables,
        &proof,
        initial_claim,
        r,
        &mut verifier_challenger,
    )
    .expect("value sumcheck verifies");
    assert_eq!(alpha.0.len(), tables.value_domain_size.ilog2() as usize);
    assert_eq!(
        final_claim,
        proof.final_evals.selector
            * proof.final_evals.val
            * proof.final_evals.erow
            * proof.final_evals.ecol
    );
}

#[test]
fn shared_union_value_sumcheck_uses_cubic_rounds() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 0, 7), entry(1, 2, 11)],
        vec![entry(0, 0, 13), entry(1, 2, 17)],
    );
    let tables = preprocess_shared_union_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);
    let r = spartan_whir::QuinticExtension::from(fe(9));
    let read_tables = compute_spark_read_tables(&tables, &r_x, &r_y).expect("read tables compute");

    let mut prover_challenger = new_keccak_challenger();
    let (proof, _, initial_claim) =
        prove_spark_value_sumcheck_with_reads(&tables, &read_tables, r, &mut prover_challenger)
            .expect("value sumcheck proves");
    assert!(proof.rounds.iter().all(|round| round.0.len() == 3));

    let mut verifier_challenger = new_keccak_challenger();
    let _ = verify_spark_value_sumcheck_with_tables(
        &tables,
        &proof,
        initial_claim,
        r,
        &mut verifier_challenger,
    )
    .expect("shared-union value sumcheck verifies");
}

#[test]
fn value_sumcheck_verifies_against_opening_claims() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);
    let r = spartan_whir::QuinticExtension::from(fe(9));
    let read_tables = compute_spark_read_tables(&tables, &r_x, &r_y).expect("read tables compute");

    let mut prover_challenger = new_keccak_challenger();
    let (proof, _, initial_claim) =
        prove_spark_value_sumcheck_with_reads(&tables, &read_tables, r, &mut prover_challenger)
            .expect("value sumcheck proves");

    let openings = SparkValueFinalEvals {
        selector: proof.final_evals.selector,
        val: proof.final_evals.val,
        val_a: proof.final_evals.val_a,
        val_b: proof.final_evals.val_b,
        val_c: proof.final_evals.val_c,
        erow: proof.final_evals.erow,
        ecol: proof.final_evals.ecol,
    };
    let mut verifier_challenger = new_keccak_challenger();
    let (_point, _claim) = verify_spark_value_sumcheck_with_openings(
        tables.layout,
        tables.slot_mapping,
        &proof,
        initial_claim,
        tables.value_domain_size,
        r,
        openings,
        &mut verifier_challenger,
    )
    .expect("opening-backed value sumcheck verifies");

    let mut bad_openings = openings;
    bad_openings.val += spartan_whir::QuinticExtension::ONE;
    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_value_sumcheck_with_openings(
            tables.layout,
            tables.slot_mapping,
            &proof,
            initial_claim,
            tables.value_domain_size,
            r,
            bad_openings,
            &mut verifier_challenger,
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn value_sumcheck_rejects_tampered_round() {
    let shape = canonical_shape_with_public(vec![entry(0, 0, 3)], vec![entry(0, 1, 7)], vec![]);
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);
    let r = spartan_whir::QuinticExtension::from(fe(9));

    let mut prover_challenger = new_keccak_challenger();
    let (mut proof, _, initial_claim) =
        prove_spark_value_sumcheck(&tables, &r_x, &r_y, r, &mut prover_challenger)
            .expect("value sumcheck proves");
    proof.rounds[0].0[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_value_sumcheck(
            &proof,
            initial_claim,
            tables.value_domain_size.ilog2() as usize,
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn grand_product_tree_verifies_and_rejects_tampering() {
    let values = vec![
        spartan_whir::QuinticExtension::from(fe(3)),
        spartan_whir::QuinticExtension::from(fe(5)),
        spartan_whir::QuinticExtension::from(fe(7)),
        spartan_whir::QuinticExtension::from(fe(11)),
    ];
    let gamma = spartan_whir::QuinticExtension::from(fe(13));
    let mut tree = SparkGrandProductTree::build(&values, gamma).expect("tree builds");

    tree.verify_tree().expect("tree verifies");
    let root = tree.root().expect("root exists");
    let expected = values
        .iter()
        .fold(spartan_whir::QuinticExtension::ONE, |acc, &value| {
            acc * (value - gamma)
        });
    assert_eq!(root, expected);

    tree.layers[1][0] += spartan_whir::QuinticExtension::ONE;
    assert_eq!(tree.verify_tree(), Err(SpartanWhirError::SumcheckFailed));
}

#[test]
fn batched_product_proof_verifies_products_and_dotproducts() {
    let product_a = vec![q(3), q(5), q(7), q(11)];
    let product_b = vec![q(13), q(17), q(19), q(23)];
    let dotproduct = SparkDotProductCircuit {
        left: vec![q(29), q(31)],
        right: vec![q(37), q(41)],
        weight: vec![q(43), q(47)],
    };
    let claim = dotproduct_claim(&dotproduct);

    let mut prover_challenger = new_keccak_challenger();
    let (proof, leaf_claims) = prove_spark_batched_product(
        &[product_a.clone(), product_b.clone()],
        core::slice::from_ref(&dotproduct),
        &mut prover_challenger,
    )
    .expect("batched product proves");

    let expected_roots = proof.product_roots.clone();
    let mut verifier_challenger = new_keccak_challenger();
    let verified_leaf_claims = verify_spark_batched_product(
        &proof,
        &expected_roots,
        &[claim],
        product_a.len(),
        &mut verifier_challenger,
    )
    .expect("batched product verifies");

    assert_eq!(verified_leaf_claims, leaf_claims);
    assert_eq!(
        verified_leaf_claims.product_evals[0],
        evaluate_mle_table(&product_a, &verified_leaf_claims.product_point.0)
            .expect("product A leaf evaluates")
    );
    assert_eq!(
        verified_leaf_claims.product_evals[1],
        evaluate_mle_table(&product_b, &verified_leaf_claims.product_point.0)
            .expect("product B leaf evaluates")
    );
    assert_eq!(
        verified_leaf_claims.dotproduct_left_evals[0],
        evaluate_mle_table(&dotproduct.left, &verified_leaf_claims.dotproduct_point.0)
            .expect("dotproduct left evaluates")
    );
    assert_eq!(
        verified_leaf_claims.dotproduct_right_evals[0],
        evaluate_mle_table(&dotproduct.right, &verified_leaf_claims.dotproduct_point.0)
            .expect("dotproduct right evaluates")
    );
    assert_eq!(
        verified_leaf_claims.dotproduct_weight_evals[0],
        evaluate_mle_table(&dotproduct.weight, &verified_leaf_claims.dotproduct_point.0)
            .expect("dotproduct weight evaluates")
    );
}

#[test]
fn batched_product_proof_accepts_empty_dotproducts_at_n2() {
    let product = vec![q(3), q(5)];

    let mut prover_challenger = new_keccak_challenger();
    let (proof, leaf_claims) =
        prove_spark_batched_product(std::slice::from_ref(&product), &[], &mut prover_challenger)
            .expect("batched product proves");

    let mut verifier_challenger = new_keccak_challenger();
    let verified_leaf_claims = verify_spark_batched_product(
        &proof,
        &proof.product_roots,
        &[],
        product.len(),
        &mut verifier_challenger,
    )
    .expect("batched product verifies");

    assert_eq!(verified_leaf_claims, leaf_claims);
    assert!(verified_leaf_claims.dotproduct_point.0.is_empty());
    assert!(verified_leaf_claims.dotproduct_left_evals.is_empty());
    assert_eq!(
        verified_leaf_claims.product_evals[0],
        evaluate_mle_table(&product, &verified_leaf_claims.product_point.0)
            .expect("product leaf evaluates")
    );
}

#[test]
fn batched_product_proof_verifies_multiple_dotproducts() {
    let product_a = vec![q(3), q(5), q(7), q(11)];
    let product_b = vec![q(13), q(17), q(19), q(23)];
    let dotproduct_a = SparkDotProductCircuit {
        left: vec![q(29), q(31)],
        right: vec![q(37), q(41)],
        weight: vec![q(43), q(47)],
    };
    let dotproduct_b = SparkDotProductCircuit {
        left: vec![q(53), q(59)],
        right: vec![q(61), q(67)],
        weight: vec![q(71), q(73)],
    };
    let claims = [
        dotproduct_claim(&dotproduct_a),
        dotproduct_claim(&dotproduct_b),
    ];

    let mut prover_challenger = new_keccak_challenger();
    let (proof, _) = prove_spark_batched_product(
        &[product_a.clone(), product_b],
        &[dotproduct_a, dotproduct_b],
        &mut prover_challenger,
    )
    .expect("batched product proves");

    let mut verifier_challenger = new_keccak_challenger();
    let leaf_claims = verify_spark_batched_product(
        &proof,
        &proof.product_roots,
        &claims,
        product_a.len(),
        &mut verifier_challenger,
    )
    .expect("batched product verifies");

    assert_eq!(leaf_claims.dotproduct_left_evals.len(), 2);
    assert_eq!(leaf_claims.dotproduct_right_evals.len(), 2);
    assert_eq!(leaf_claims.dotproduct_weight_evals.len(), 2);
}

#[test]
fn batched_product_proof_rejects_tampered_layer_claim() {
    let product_a = vec![q(3), q(5), q(7), q(11)];
    let product_b = vec![q(13), q(17), q(19), q(23)];

    let mut prover_challenger = new_keccak_challenger();
    let (mut proof, _) =
        prove_spark_batched_product(&[product_a.clone(), product_b], &[], &mut prover_challenger)
            .expect("batched product proves");
    let expected_roots = proof.product_roots.clone();
    proof.layers[0].product_left_evals[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_product(
            &proof,
            &expected_roots,
            &[],
            product_a.len(),
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_product_proof_rejects_dotproduct_claim_mismatch() {
    let product = vec![q(3), q(5), q(7), q(11)];
    let dotproduct = SparkDotProductCircuit {
        left: vec![q(13), q(17)],
        right: vec![q(19), q(23)],
        weight: vec![q(29), q(31)],
    };
    let mut expected_claim = dotproduct_claim(&dotproduct);
    expected_claim += spartan_whir::QuinticExtension::ONE;

    let mut prover_challenger = new_keccak_challenger();
    let (proof, _) = prove_spark_batched_product(
        std::slice::from_ref(&product),
        &[dotproduct],
        &mut prover_challenger,
    )
    .expect("batched product proves");

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_product(
            &proof,
            &proof.product_roots,
            &[expected_claim],
            product.len(),
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_product_proof_rejects_tampered_dotproduct_leaf_eval() {
    let product = vec![q(3), q(5), q(7), q(11)];
    let dotproduct = SparkDotProductCircuit {
        left: vec![q(13), q(17)],
        right: vec![q(19), q(23)],
        weight: vec![q(29), q(31)],
    };
    let claim = dotproduct_claim(&dotproduct);

    let mut prover_challenger = new_keccak_challenger();
    let (mut proof, _) = prove_spark_batched_product(
        std::slice::from_ref(&product),
        &[dotproduct],
        &mut prover_challenger,
    )
    .expect("batched product proves");
    proof
        .layers
        .last_mut()
        .expect("leaf-adjacent layer exists")
        .dotproduct_left_evals[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_product(
            &proof,
            &proof.product_roots,
            &[claim],
            product.len(),
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_product_proof_rejects_tampered_round_poly() {
    let product_a = vec![q(3), q(5), q(7), q(11)];
    let product_b = vec![q(13), q(17), q(19), q(23)];

    let mut prover_challenger = new_keccak_challenger();
    let (mut proof, _) =
        prove_spark_batched_product(&[product_a.clone(), product_b], &[], &mut prover_challenger)
            .expect("batched product proves");
    let expected_roots = proof.product_roots.clone();
    proof.layers[1].rounds[0].0[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_product(
            &proof,
            &expected_roots,
            &[],
            product_a.len(),
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_product_proof_rejects_product_root_mismatch() {
    let product_a = vec![q(3), q(5), q(7), q(11)];
    let product_b = vec![q(13), q(17), q(19), q(23)];

    let mut prover_challenger = new_keccak_challenger();
    let (mut proof, _) =
        prove_spark_batched_product(&[product_a.clone(), product_b], &[], &mut prover_challenger)
            .expect("batched product proves");
    let expected_roots = proof.product_roots.clone();
    proof.product_roots[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_product(
            &proof,
            &expected_roots,
            &[],
            product_a.len(),
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn grand_product_sumcheck_reduces_to_leaf_opening() {
    let values = vec![
        spartan_whir::QuinticExtension::from(fe(3)),
        spartan_whir::QuinticExtension::from(fe(5)),
        spartan_whir::QuinticExtension::from(fe(7)),
        spartan_whir::QuinticExtension::from(fe(11)),
        spartan_whir::QuinticExtension::from(fe(13)),
        spartan_whir::QuinticExtension::from(fe(17)),
        spartan_whir::QuinticExtension::from(fe(19)),
        spartan_whir::QuinticExtension::from(fe(23)),
    ];
    let gamma = spartan_whir::QuinticExtension::from(fe(29));

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_grand_product(&values, gamma, &mut prover_challenger)
        .expect("grand product proves");

    let expected_root = values
        .iter()
        .fold(spartan_whir::QuinticExtension::ONE, |acc, &value| {
            acc * (value - gamma)
        });
    assert_eq!(proof.root, expected_root);

    let mut verifier_challenger = new_keccak_challenger();
    let (leaf_point, leaf_eval) =
        verify_spark_grand_product_with_values(&values, gamma, &proof, &mut verifier_challenger)
            .expect("grand product verifies");
    assert_eq!(leaf_point.0.len(), values.len().ilog2() as usize);
    assert_eq!(leaf_eval, proof.leaf_eval);
}

#[test]
fn grand_product_sumcheck_rejects_tampered_round() {
    let values = vec![
        spartan_whir::QuinticExtension::from(fe(3)),
        spartan_whir::QuinticExtension::from(fe(5)),
        spartan_whir::QuinticExtension::from(fe(7)),
        spartan_whir::QuinticExtension::from(fe(11)),
    ];
    let gamma = spartan_whir::QuinticExtension::from(fe(13));

    let mut prover_challenger = new_keccak_challenger();
    let mut proof = prove_spark_grand_product(&values, gamma, &mut prover_challenger)
        .expect("grand product proves");
    proof.layers[1].rounds[0].0[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_grand_product_with_values(&values, gamma, &proof, &mut verifier_challenger),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn grand_product_sumcheck_rejects_tampered_leaf_claim() {
    let values = vec![
        spartan_whir::QuinticExtension::from(fe(3)),
        spartan_whir::QuinticExtension::from(fe(5)),
        spartan_whir::QuinticExtension::from(fe(7)),
        spartan_whir::QuinticExtension::from(fe(11)),
    ];
    let gamma = spartan_whir::QuinticExtension::from(fe(13));

    let mut prover_challenger = new_keccak_challenger();
    let mut proof = prove_spark_grand_product(&values, gamma, &mut prover_challenger)
        .expect("grand product proves");
    proof.leaf_eval += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_grand_product_with_values(&values, gamma, &proof, &mut verifier_challenger),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn memory_product_claims_match_joint_tables() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory products prove");

    check_spark_memory_product_equations(&proof).expect("product equations hold");

    let mut verifier_challenger = new_keccak_challenger();
    verify_spark_memory_products_with_tables(&tables, &proof, &r_x, &r_y, &mut verifier_challenger)
        .expect("memory products verify");
}

#[test]
fn memory_product_claims_reject_tampered_root() {
    let shape = canonical_shape_with_public(vec![entry(0, 0, 3)], vec![entry(0, 1, 7)], vec![]);
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);

    let mut prover_challenger = new_keccak_challenger();
    let mut proof = prove_spark_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory products prove");
    proof.row.read_root += spartan_whir::QuinticExtension::ONE;

    assert_eq!(
        check_spark_memory_product_equations(&proof),
        Err(SpartanWhirError::SumcheckFailed)
    );

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_memory_products_with_tables(
            &tables,
            &proof,
            &r_x,
            &r_y,
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn memory_product_claims_reject_tampered_timestamps() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let mut tampered_tables = tables.clone();
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory products prove");
    tampered_tables.read_ts_row[0] += F::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_memory_products_with_tables(
            &tampered_tables,
            &proof,
            &r_x,
            &r_y,
            &mut verifier_challenger
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn memory_grand_products_verify_against_joint_tables() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_memory_grand_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory grand products prove");

    let mut verifier_challenger = new_keccak_challenger();
    verify_spark_memory_grand_products_with_tables(
        &tables,
        &proof,
        &r_x,
        &r_y,
        &mut verifier_challenger,
    )
    .expect("memory grand products verify");
}

#[test]
fn batched_memory_products_verify_against_joint_tables() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![q(3)]);
    let r_y = MultilinearPoint(vec![q(4), q(6)]);
    let read_tables = compute_spark_read_tables(&tables, &r_x, &r_y).expect("read tables compute");

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_batched_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("batched memory products prove");

    assert_eq!(proof.proof_ops.product_roots.len(), 4);
    assert_eq!(proof.proof_ops.dotproduct_claims.len(), 6);
    assert_eq!(proof.proof_mem.product_roots.len(), 4);
    assert_eq!(proof.proof_mem.dotproduct_claims.len(), 0);
    assert_eq!(
        proof.matrix_evals,
        [
            direct_matrix_eval(&tables.val_a, &read_tables.erow, &read_tables.ecol),
            direct_matrix_eval(&tables.val_b, &read_tables.erow, &read_tables.ecol),
            direct_matrix_eval(&tables.val_c, &read_tables.erow, &read_tables.ecol),
        ]
    );

    let mut verifier_challenger = new_keccak_challenger();
    verify_spark_batched_memory_products_with_tables(
        &tables,
        &proof,
        &r_x,
        &r_y,
        &mut verifier_challenger,
    )
    .expect("batched memory products verify");
}

#[test]
fn batched_memory_product_claims_reject_tampered_ops_layer() {
    let shape = canonical_shape_with_public(vec![entry(0, 0, 3)], vec![entry(0, 1, 7)], vec![]);
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![q(3)]);
    let r_y = MultilinearPoint(vec![q(4), q(6)]);

    let mut prover_challenger = new_keccak_challenger();
    let mut proof =
        prove_spark_batched_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
            .expect("batched memory products prove");
    proof.proof_ops.layers[1].rounds[0].0[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_memory_product_claims(&tables, &proof, &mut verifier_challenger),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_memory_product_claims_reject_tampered_dotproduct_claim() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![q(3)]);
    let r_y = MultilinearPoint(vec![q(4), q(6)]);

    let mut prover_challenger = new_keccak_challenger();
    let mut proof =
        prove_spark_batched_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
            .expect("batched memory products prove");
    proof.proof_ops.dotproduct_claims[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_memory_product_claims(&tables, &proof, &mut verifier_challenger),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn batched_memory_product_claims_reject_tampered_matrix_eval() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![q(3)]);
    let r_y = MultilinearPoint(vec![q(4), q(6)]);

    let mut prover_challenger = new_keccak_challenger();
    let mut proof =
        prove_spark_batched_memory_products(&tables, &r_x, &r_y, &mut prover_challenger)
            .expect("batched memory products prove");
    proof.matrix_evals[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_batched_memory_product_claims(&tables, &proof, &mut verifier_challenger),
        Err(SpartanWhirError::SumcheckFailed)
    );
}

#[test]
fn memory_grand_product_claims_expose_leaf_opening_obligations() {
    let shape = canonical_shape_with_public(
        vec![entry(0, 0, 3), entry(1, 2, 5)],
        vec![entry(0, 1, 7)],
        vec![entry(1, 3, 11)],
    );
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);
    let read_tables = compute_spark_read_tables(&tables, &r_x, &r_y).expect("read tables compute");

    let mut prover_challenger = new_keccak_challenger();
    let proof = prove_spark_memory_grand_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory grand products prove");

    let mut verifier_challenger = new_keccak_challenger();
    let claims =
        verify_spark_memory_grand_product_claims(&tables, &proof, &mut verifier_challenger)
            .expect("memory grand product claims verify");

    verify_spark_memory_leaf_claims_with_tables(&tables, &read_tables, &claims, &r_x, &r_y)
        .expect("leaf opening obligations match table oracle");
}

#[test]
fn memory_grand_products_reject_tampered_nested_product() {
    let shape = canonical_shape_with_public(vec![entry(0, 0, 3)], vec![entry(0, 1, 7)], vec![]);
    let tables = preprocess_joint_spark_tables(&shape).expect("preprocess succeeds");
    let r_x = MultilinearPoint(vec![spartan_whir::QuinticExtension::from(fe(3))]);
    let r_y = MultilinearPoint(vec![
        spartan_whir::QuinticExtension::from(fe(4)),
        spartan_whir::QuinticExtension::from(fe(6)),
    ]);

    let mut prover_challenger = new_keccak_challenger();
    let mut proof = prove_spark_memory_grand_products(&tables, &r_x, &r_y, &mut prover_challenger)
        .expect("memory grand products prove");
    proof.row.read.layers[1].rounds[0].0[0] += spartan_whir::QuinticExtension::ONE;

    let mut verifier_challenger = new_keccak_challenger();
    assert_eq!(
        verify_spark_memory_grand_products_with_tables(
            &tables,
            &proof,
            &r_x,
            &r_y,
            &mut verifier_challenger,
        ),
        Err(SpartanWhirError::SumcheckFailed)
    );
}
