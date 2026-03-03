use spartan_whir::{effective_digest_bytes, ProofCodecConfig};

#[test]
fn codec_defaults_match_phase_one_contract() {
    let cfg = ProofCodecConfig::default();
    assert_eq!(cfg.proof_blob_version, 0);
    assert!(cfg.compact_query_encoding);
    assert_eq!(cfg.digest_bytes_override, None);
}

#[test]
fn digest_bytes_override_wins_when_present() {
    assert_eq!(effective_digest_bytes(100, Some(16)), 16);
}

#[test]
fn digest_bytes_override_is_clamped() {
    assert_eq!(effective_digest_bytes(100, Some(0)), 1);
    assert_eq!(effective_digest_bytes(100, Some(255)), 32);
}

#[test]
fn digest_bytes_uses_conservative_security_derivation_without_override() {
    // Conservative birthday-bound mapping: 100-bit collision security -> 25 bytes.
    assert_eq!(effective_digest_bytes(100, None), 25);
    assert_eq!(effective_digest_bytes(80, None), 20);
}
