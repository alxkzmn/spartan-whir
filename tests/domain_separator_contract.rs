mod common;

use spartan_whir::{DomainSeparator, SecurityConfig, WhirParams};

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
    // + shape dims: num_cons/num_vars/num_io as u64 (3 * 8)
    // + security bits: security_level_bits/merkle_security_bits as u32 (2 * 4)
    // + soundness enum tag (1)
    // + WHIR params: pow_bits as u32 (4)
    // + folding_factor/starting_log_inv_rate/rs_domain_initial_reduction_factor as u64 (3 * 8)
    // = 76 bytes total.
    assert_eq!(a.to_bytes().len(), 76);
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
