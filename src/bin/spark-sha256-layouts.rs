//! Reports Spark PCS table dimensions for SHA256 benchmark `.r1cs` fixtures.
//!
//! The size label is parsed from the existing `sha256_<bytes>b.r1cs` fixture
//! naming convention; this is not intended as a general R1CS labeling tool.

use std::{env, error::Error, path::Path};

use p3_field::TwoAdicField;
use spartan_whir::{
    compare_spark_layouts,
    engine::F,
    import_circom_r1cs_path,
    protocol::{fixed_audit_column_count, fixed_value_column_bits, read_column_bits},
    spark::spark_col_memory_size,
    OcticBinExtension, QuarticBinExtension, SparkLayoutDecision,
};

const DEFAULT_STARTING_LOG_INV_RATE: usize = 1;

#[derive(Debug)]
struct Row {
    size_bytes: usize,
    constraints: usize,
    vars: usize,
    decision: SparkLayoutDecision,
    value_domain_size: usize,
    value_vars: usize,
    row_memory_size: usize,
    col_memory_size: usize,
    fixed_value_vars: usize,
    fixed_audit_vars: usize,
    read_vars_quartic: usize,
    read_vars_octic: usize,
    max_vars_quartic: usize,
    max_vars_octic: usize,
    min_first_fold_lir1_quartic: usize,
    min_first_fold_lir1_octic: usize,
    union_nnz: usize,
    max_matrix_nnz_padded: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rows = env::args()
        .skip(1)
        .map(|path| layout_row(Path::new(&path)))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| row.size_bytes);

    println!(
        "size_bytes,constraints,vars,decision,value_domain,value_vars,row_memory,col_memory,fixed_value_vars,fixed_audit_vars,read_vars_quartic,read_vars_octic,max_vars_quartic,max_vars_octic,min_first_fold_lir1_quartic,min_first_fold_lir1_octic,union_nnz,max_matrix_nnz_padded"
    );
    for row in rows {
        println!(
            "{},{},{},{:?},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            row.size_bytes,
            row.constraints,
            row.vars,
            row.decision,
            row.value_domain_size,
            row.value_vars,
            row.row_memory_size,
            row.col_memory_size,
            row.fixed_value_vars,
            row.fixed_audit_vars,
            row.read_vars_quartic,
            row.read_vars_octic,
            row.max_vars_quartic,
            row.max_vars_octic,
            row.min_first_fold_lir1_quartic,
            row.min_first_fold_lir1_octic,
            row.union_nnz,
            row.max_matrix_nnz_padded
        );
    }
    Ok(())
}

fn layout_row(path: &Path) -> Result<Row, Box<dyn Error>> {
    let size_bytes = parse_size_bytes(path)?;
    let circom = import_circom_r1cs_path(path)?;
    let shape = circom.shape;
    let padded_shape = shape
        .pad_regular()
        .map_err(|err| format!("padding failed for {}: {err}", path.display()))?;
    let comparison = compare_spark_layouts(&padded_shape)
        .map_err(|err| format!("Spark layout failed for {}: {err}", path.display()))?;
    let selected = match comparison.decision {
        SparkLayoutDecision::SharedUnion => &comparison.joint,
        SparkLayoutDecision::PerMatrix => &comparison.per_matrix,
    };

    let row_memory_size = padded_shape.num_cons;
    let col_memory_size = spark_col_memory_size(&padded_shape)
        .map_err(|err| format!("Spark column memory failed for {}: {err}", path.display()))?;
    let audit_domain_size = row_memory_size
        .max(col_memory_size)
        .checked_next_power_of_two()
        .and_then(|n| n.checked_mul(fixed_audit_column_count()))
        .ok_or("audit domain size overflow")?;
    let value_vars = log2_power_of_two(selected.value_domain_size)?;
    let fixed_value_vars = value_vars + fixed_value_column_bits();
    let fixed_audit_vars = log2_power_of_two(audit_domain_size)?;
    let read_vars_quartic = value_vars + read_column_bits::<QuarticBinExtension>();
    let read_vars_octic = value_vars + read_column_bits::<OcticBinExtension>();
    let max_vars_quartic = fixed_value_vars
        .max(fixed_audit_vars)
        .max(read_vars_quartic);
    let max_vars_octic = fixed_value_vars.max(fixed_audit_vars).max(read_vars_octic);
    let min_first_fold_lir1_quartic = min_first_fold_lir1(max_vars_quartic);
    let min_first_fold_lir1_octic = min_first_fold_lir1(max_vars_octic);

    Ok(Row {
        size_bytes,
        constraints: shape.num_cons,
        vars: shape.num_vars,
        decision: comparison.decision,
        value_domain_size: selected.value_domain_size,
        value_vars,
        row_memory_size,
        col_memory_size,
        fixed_value_vars,
        fixed_audit_vars,
        read_vars_quartic,
        read_vars_octic,
        max_vars_quartic,
        max_vars_octic,
        min_first_fold_lir1_quartic,
        min_first_fold_lir1_octic,
        union_nnz: selected.union_nnz,
        max_matrix_nnz_padded: selected.max_matrix_nnz_padded,
    })
}

fn min_first_fold_lir1(max_vars: usize) -> usize {
    max_vars
        .checked_add(DEFAULT_STARTING_LOG_INV_RATE)
        .and_then(|n| n.checked_sub(F::TWO_ADICITY))
        .unwrap_or(1)
        .max(1)
}

fn log2_power_of_two(value: usize) -> Result<usize, Box<dyn Error>> {
    if value == 0 || !value.is_power_of_two() {
        return Err(format!("{value} is not a non-zero power of two").into());
    }
    Ok(value.ilog2() as usize)
}

fn parse_size_bytes(path: &Path) -> Result<usize, Box<dyn Error>> {
    let text = path.to_string_lossy();
    let marker = "sha256_";
    let Some(start) = text.find(marker).map(|offset| offset + marker.len()) else {
        return Err(format!("could not parse size from {}", path.display()).into());
    };
    let tail = &text[start..];
    let Some(end) = tail.find('b') else {
        return Err(format!("could not parse size from {}", path.display()).into());
    };
    Ok(tail[..end].parse()?)
}
