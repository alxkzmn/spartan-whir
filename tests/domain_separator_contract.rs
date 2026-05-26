mod common;

use spartan_whir::{
    DomainSeparator, MatrixClosingMode, SecurityConfig, WhirFoldingSchedule, WhirParams,
};

#[test]
fn domain_separator_encoding_is_deterministic() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();

    let a = DomainSeparator::new(&shape, &security, &whir);
    let b = DomainSeparator::new(&shape, &security, &whir);

    assert_eq!(a, b);
    assert_eq!(a.to_bytes(), b.to_bytes());
    // Byte budget for the current stable encoding:
    // protocol_id (15)
    // + matrix closing mode tag (1)
    // + shape dims: num_cons/num_vars/num_io as u64 (3 * 8)
    // + security bits: security_level_bits/merkle_security_bits as u32 (2 * 4)
    // + soundness enum tag (1)
    // + WHIR params: pow_bits as u32 (4)
    // + folding_factor/starting_log_inv_rate/rs_domain_initial_reduction_factor as u64 (3 * 8)
    // = 77 bytes total.
    assert_eq!(a.to_bytes().len(), 77);
}

#[test]
fn domain_separator_changes_when_shape_changes() {
    let mut shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();

    let a = DomainSeparator::new(&shape, &security, &whir);
    shape.num_cons = 2;
    let b = DomainSeparator::new(&shape, &security, &whir);

    assert_ne!(a.to_bytes(), b.to_bytes());
}

#[test]
fn domain_separator_changes_when_matrix_closing_changes() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();

    let direct = DomainSeparator::new_with_matrix_closing(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::DirectSparse,
    );
    let spark = DomainSeparator::new_with_matrix_closing(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::Spark,
    );

    assert_ne!(direct.to_bytes(), spark.to_bytes());
    assert_eq!(direct.to_bytes()[15], 0);
    assert_eq!(spark.to_bytes()[15], 1);
}

#[test]
fn domain_separator_canonicalizes_legacy_constant_schedule() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let legacy = WhirParams::default();
    let explicit = WhirParams {
        folding_schedule: Some(WhirFoldingSchedule::Constant(legacy.folding_factor)),
        ..legacy.clone()
    };

    let legacy_bytes = DomainSeparator::new(&shape, &security, &legacy).to_bytes();
    let explicit_bytes = DomainSeparator::new(&shape, &security, &explicit).to_bytes();

    assert_eq!(legacy_bytes, explicit_bytes);
}
