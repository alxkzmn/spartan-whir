mod common;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::PrimeCharacteristicRing;
use spartan_whir::{
    engine::F, DomainSeparator, MatrixClosingMode, QuarticBinExtension, SecurityConfig,
    SparkWhirParams, WhirFoldingSchedule, WhirParams, FULL_ZK_PROTOCOL_ID, NO_ZK_PROTOCOL_ID,
    SPARK_MATRIX_CLOSING_VERSION,
};

fn expected_shared_direct_body() -> Vec<u8> {
    vec![
        0, // DirectSparse
        1, 0, 0, 0, 0, 0, 0, 0, // num_cons
        1, 0, 0, 0, 0, 0, 0, 0, // num_vars
        1, 0, 0, 0, 0, 0, 0, 0, // num_io
        100, 0, 0, 0, // security_level_bits
        100, 0, 0, 0, // merkle_security_bits
        2, // CapacityBound
        0, 0, 0, 0, // pow_bits
        4, 0, 0, 0, 0, 0, 0, 0, // folding_factor
        1, 0, 0, 0, 0, 0, 0, 0, // starting_log_inv_rate
        1, 0, 0, 0, 0, 0, 0, 0, // rs_domain_initial_reduction_factor
    ]
}

fn absorb_separator(separator: &DomainSeparator) -> QuarticBinExtension {
    let mut challenger = spartan_whir::poseidon_challenger();
    for byte in separator.to_bytes() {
        challenger.observe(F::from_u8(byte));
    }
    challenger.sample_algebra_element::<QuarticBinExtension>()
}

#[test]
fn domain_separator_encoding_is_deterministic() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();

    let a = DomainSeparator::new(&shape, &security, &whir);
    let b = DomainSeparator::new(&shape, &security, &whir);

    assert_eq!(a, b);
    assert_eq!(a.to_bytes(), b.to_bytes());
    let expected = [
        b"spartan-whir-no-zk-v0".as_slice(),
        &expected_shared_direct_body(),
    ]
    .concat();
    assert_eq!(a.to_bytes(), expected);
}

#[test]
fn no_zk_and_full_zk_separators_share_only_the_canonical_body() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();
    let no_zk = DomainSeparator::new(&shape, &security, &whir);
    let full_zk = DomainSeparator::new_full_zk(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::DirectSparse,
        None,
    );

    let expected_full_zk = [
        b"spartan-whir-full-zk-v0".as_slice(),
        &expected_shared_direct_body(),
    ]
    .concat();
    assert_eq!(full_zk.to_bytes(), expected_full_zk);
    assert_eq!(
        &no_zk.to_bytes()[NO_ZK_PROTOCOL_ID.len()..],
        &full_zk.to_bytes()[FULL_ZK_PROTOCOL_ID.len()..]
    );
    assert_ne!(absorb_separator(&no_zk), absorb_separator(&full_zk));
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
    assert_eq!(direct.to_bytes()[NO_ZK_PROTOCOL_ID.len()], 0);
    assert_eq!(spark.to_bytes()[NO_ZK_PROTOCOL_ID.len()], 1);
    assert_eq!(
        spark.to_bytes()[NO_ZK_PROTOCOL_ID.len() + 1],
        SPARK_MATRIX_CLOSING_VERSION
    );
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

#[test]
fn domain_separator_ignores_spark_params_in_direct_mode() {
    let shape = common::sample_shape();
    let security = SecurityConfig::default();
    let whir = WhirParams::default();
    let spark_whir_params = SparkWhirParams {
        fixed_value: WhirParams {
            starting_log_inv_rate: 2,
            ..whir.clone()
        },
        fixed_audit: WhirParams {
            starting_log_inv_rate: 3,
            ..whir.clone()
        },
        read: WhirParams {
            starting_log_inv_rate: 4,
            ..whir.clone()
        },
    };

    let direct = DomainSeparator::new_with_matrix_closing(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::DirectSparse,
    );
    let direct_with_spark_params = DomainSeparator::new_with_matrix_closing_and_spark_whir_params(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::DirectSparse,
        Some(spark_whir_params.clone()),
    );
    let spark_with_spark_params = DomainSeparator::new_with_matrix_closing_and_spark_whir_params(
        &shape,
        &security,
        &whir,
        MatrixClosingMode::Spark,
        Some(spark_whir_params),
    );

    assert_eq!(direct_with_spark_params.spark_whir_params, None);
    assert_eq!(direct.to_bytes(), direct_with_spark_params.to_bytes());
    assert_ne!(direct.to_bytes(), spark_with_spark_params.to_bytes());
}
