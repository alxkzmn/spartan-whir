mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use spartan_whir::{
    decode_spartan_blob, decode_spartan_blob_v1, encode_spartan_blob, encode_spartan_blob_v1,
    encode_spartan_blob_v1_with_report, engine::F, profile_spartan_blob_v1, KeccakEngine,
    ProofCodecConfig, R1csShape, SpartanBlobDecodeContext, SpartanProtocol, SpartanWhirError,
    WhirPcs,
};
use whir_p3::whir::proof::SumcheckData;

fn regular_shape_two_constraints() -> R1csShape<F> {
    let one = F::ONE;
    R1csShape {
        num_cons: 2,
        num_vars: 2,
        num_io: 1,
        a: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 0,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 0,
                    val: one,
                },
            ],
        },
        b: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 2,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 2,
                    val: one,
                },
            ],
        },
        c: spartan_whir::SparseMatrix {
            num_rows: 2,
            num_cols: 4,
            entries: vec![
                spartan_whir::SparseMatEntry {
                    row: 0,
                    col: 3,
                    val: one,
                },
                spartan_whir::SparseMatEntry {
                    row: 1,
                    col: 3,
                    val: one,
                },
            ],
        },
    }
}

fn large_round_shape(num_vars: usize) -> R1csShape<F> {
    let one = F::ONE;
    R1csShape {
        num_cons: 1,
        num_vars,
        num_io: 1,
        a: spartan_whir::SparseMatrix {
            num_rows: 1,
            num_cols: num_vars + 2,
            entries: vec![spartan_whir::SparseMatEntry {
                row: 0,
                col: 0,
                val: one,
            }],
        },
        b: spartan_whir::SparseMatrix {
            num_rows: 1,
            num_cols: num_vars + 2,
            entries: vec![spartan_whir::SparseMatEntry {
                row: 0,
                col: num_vars,
                val: one,
            }],
        },
        c: spartan_whir::SparseMatrix {
            num_rows: 1,
            num_cols: num_vars + 2,
            entries: vec![spartan_whir::SparseMatEntry {
                row: 0,
                col: num_vars + 1,
                val: one,
            }],
        },
    }
}

type Pk = spartan_whir::ProvingKey<KeccakEngine, WhirPcs>;
type Vk = spartan_whir::VerifyingKey<KeccakEngine, WhirPcs>;
type Instance = spartan_whir::R1csInstance<F, [u64; 4]>;
type Proof = spartan_whir::SpartanProof<KeccakEngine, WhirPcs>;

fn setup_keys(shape: &R1csShape<F>) -> (Pk, Vk) {
    SpartanProtocol::<KeccakEngine, WhirPcs>::setup(
        shape,
        &common::phase3_security(),
        &common::phase3_whir_params(),
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds")
}

fn prove(
    shape: &R1csShape<F>,
    public_inputs: &[F],
    witness: &[F],
) -> (Vk, Instance, Proof, spartan_whir::WhirPcsConfig) {
    let (pk, vk) = setup_keys(shape);
    let mut challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove(
        &pk,
        public_inputs,
        &spartan_whir::R1csWitness {
            w: witness.to_vec(),
        },
        &mut challenger,
    )
    .expect("prove succeeds");
    let pcs_config = vk.pcs_config;
    (vk, instance, proof, pcs_config)
}

fn regular_fixture() -> (Vk, Instance, Proof, spartan_whir::WhirPcsConfig) {
    let shape = regular_shape_two_constraints();
    let witness = vec![F::from_u32(7), F::ZERO];
    let public_inputs = common::koala_public_inputs(7);
    prove(&shape, &public_inputs, &witness)
}

fn irregular_fixture() -> (Vk, Instance, Proof, spartan_whir::WhirPcsConfig) {
    let shape = common::koala_shape_single_constraint(2);
    let witness = common::koala_witness(9).w;
    let public_inputs = common::koala_public_inputs(9);
    prove(&shape, &public_inputs, &witness)
}

fn multi_round_fixture() -> (Vk, Instance, Proof, spartan_whir::WhirPcsConfig) {
    let shape = large_round_shape(256);
    let mut witness = vec![F::ZERO; 256];
    witness[0] = F::from_u32(13);
    let public_inputs = common::koala_public_inputs(13);
    prove(&shape, &public_inputs, &witness)
}

#[test]
fn codec_v1_roundtrip_regular_shape() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = regular_fixture();

    let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();
    let (decoded_instance, decoded_proof) = decode_spartan_blob_v1(&codec, &ctx, &blob).unwrap();

    assert_eq!(decoded_instance.public_inputs, instance.public_inputs);
    assert_eq!(
        decoded_instance.witness_commitment,
        instance.witness_commitment
    );
    assert_eq!(decoded_proof.outer_claims, proof.outer_claims);
    assert_eq!(decoded_proof.witness_eval, proof.witness_eval);

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verified = SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
        &vk,
        &decoded_instance,
        &decoded_proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn codec_v1_roundtrip_irregular_shape() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = irregular_fixture();

    let blob = encode_spartan_blob(&codec, &pcs_config, &instance, &proof).unwrap();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();
    let (decoded_instance, decoded_proof) = decode_spartan_blob(&codec, &ctx, &blob).unwrap();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verified = SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
        &vk,
        &decoded_instance,
        &decoded_proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn codec_v1_roundtrip_multi_round_shape() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = multi_round_fixture();

    let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();
    let (decoded_instance, decoded_proof) = decode_spartan_blob_v1(&codec, &ctx, &blob).unwrap();

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let verified = SpartanProtocol::<KeccakEngine, WhirPcs>::verify(
        &vk,
        &decoded_instance,
        &decoded_proof,
        &mut verifier_challenger,
    );
    assert_eq!(verified, Ok(()));
}

#[test]
fn codec_v1_reject_bad_magic_version_flags_section_count_and_trailing_bytes() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = regular_fixture();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();
    let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();

    let mut bad_magic = blob.clone();
    bad_magic[0] ^= 0x80;
    assert!(matches!(
        decode_spartan_blob_v1(&codec, &ctx, &bad_magic),
        Err(SpartanWhirError::InvalidBlobHeader)
    ));

    let mut bad_version = blob.clone();
    bad_version[5] = 2;
    assert!(matches!(
        decode_spartan_blob(&codec, &ctx, &bad_version),
        Err(SpartanWhirError::UnsupportedBlobVersion)
    ));

    let mut bad_flags = blob.clone();
    bad_flags[6] = 0;
    bad_flags[7] = 0;
    assert!(matches!(
        decode_spartan_blob_v1(&codec, &ctx, &bad_flags),
        Err(SpartanWhirError::InvalidBlobFlags)
    ));

    let mut bad_sections = blob.clone();
    bad_sections[9] = 7;
    assert!(matches!(
        decode_spartan_blob_v1(&codec, &ctx, &bad_sections),
        Err(SpartanWhirError::InvalidBlobHeader)
    ));

    let mut trailing = blob;
    trailing.push(0xaa);
    assert!(matches!(
        decode_spartan_blob_v1(&codec, &ctx, &trailing),
        Err(SpartanWhirError::InvalidBlobLayout)
    ));
}

#[test]
fn codec_v1_reject_compact_query_encoding_false() {
    let codec = ProofCodecConfig {
        compact_query_encoding: false,
        ..ProofCodecConfig::default()
    };

    let (vk, instance, proof, pcs_config) = regular_fixture();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();

    let encode_result = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof);
    assert_eq!(encode_result, Err(SpartanWhirError::InvalidBlobFlags));

    let good_codec = ProofCodecConfig::default();
    let blob = encode_spartan_blob_v1(&good_codec, &pcs_config, &instance, &proof).unwrap();
    let decode_result = decode_spartan_blob_v1(&codec, &ctx, &blob);
    assert!(matches!(
        decode_result,
        Err(SpartanWhirError::InvalidBlobFlags)
    ));
}

#[test]
fn codec_v1_reject_instance_proof_commitment_mismatch() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, mut proof, pcs_config) = regular_fixture();
    proof.pcs_proof.initial_commitment[0] ^= 1;

    let result = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof);
    assert_eq!(result, Err(SpartanWhirError::CommitmentMismatch));
}

#[test]
fn codec_v1_reject_noncanonical_field_word() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = regular_fixture();
    let ctx = SpartanBlobDecodeContext::from_vk(&vk).unwrap();
    let mut blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();

    // Header is 34 bytes, instance section starts with len u32, first public input follows.
    let start = 34 + 4;
    blob[start..start + 4].copy_from_slice(&F::ORDER_U32.to_be_bytes());

    assert!(matches!(
        decode_spartan_blob_v1(&codec, &ctx, &blob),
        Err(SpartanWhirError::NonCanonicalEncoding)
    ));
}

#[test]
fn codec_v1_reject_whir_context_mismatch() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = regular_fixture();
    let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();

    let mut altered_vk = vk;
    altered_vk.pcs_config.num_variables = 8;
    let bad_ctx = SpartanBlobDecodeContext::from_vk(&altered_vk).unwrap();

    let result = decode_spartan_blob_v1(&codec, &bad_ctx, &blob);
    assert!(matches!(result, Err(SpartanWhirError::InvalidBlobLayout)));
}

#[test]
fn codec_v1_reject_whir_query_count_mismatch() {
    let codec = ProofCodecConfig::default();
    let (vk, instance, proof, pcs_config) = regular_fixture();
    let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();

    let mut altered_vk = vk;
    altered_vk.pcs_config.whir.pow_bits = altered_vk.pcs_config.security.security_level_bits;
    let bad_ctx = SpartanBlobDecodeContext::from_vk(&altered_vk).unwrap();

    let result = decode_spartan_blob_v1(&codec, &bad_ctx, &blob);
    assert!(matches!(result, Err(SpartanWhirError::InvalidBlobLayout)));
}

#[test]
fn codec_v1_encoder_precheck_rejects_missing_final_query_batch() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, mut proof, pcs_config) = regular_fixture();
    proof.pcs_proof.final_query_batch = None;

    let result = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof);
    assert_eq!(result, Err(SpartanWhirError::ProofEncodeFailed));
}

#[test]
fn codec_v1_encoder_precheck_rejects_final_sumcheck_presence_mismatch() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, mut proof, pcs_config) = regular_fixture();
    proof.pcs_proof.final_sumcheck = Some(SumcheckData::default());

    let result = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof);
    assert_eq!(result, Err(SpartanWhirError::ProofEncodeFailed));
}

#[test]
fn codec_v1_encoder_precheck_rejects_missing_round_query_batch() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, mut proof, pcs_config) = multi_round_fixture();
    assert!(!proof.pcs_proof.rounds.is_empty());

    proof.pcs_proof.rounds[0].query_batch = None;
    let result = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof);
    assert_eq!(result, Err(SpartanWhirError::ProofEncodeFailed));
}

#[test]
fn codec_v1_profile_invariants_hold() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, proof, pcs_config) = regular_fixture();

    let (blob, report) =
        encode_spartan_blob_v1_with_report(&codec, &pcs_config, &instance, &proof).unwrap();

    assert_eq!(report.total_bytes, blob.len());
    assert_eq!(report.effective_digest_byte_width, 20);

    let section_sum: usize = report.sections.iter().map(|s| s.bytes).sum();
    assert_eq!(section_sum, report.total_bytes);

    let report_only = profile_spartan_blob_v1(&codec, &pcs_config, &instance, &proof).unwrap();
    assert_eq!(report_only, report);
}

#[test]
fn codec_v1_profile_is_deterministic_and_digest_override_changes_digest_bytes() {
    let codec = ProofCodecConfig::default();
    let (_vk, instance, proof, pcs_config) = regular_fixture();

    let (_, report_a) =
        encode_spartan_blob_v1_with_report(&codec, &pcs_config, &instance, &proof).unwrap();
    let (_, report_b) =
        encode_spartan_blob_v1_with_report(&codec, &pcs_config, &instance, &proof).unwrap();
    assert_eq!(report_a, report_b);

    let mut codec_override = codec;
    codec_override.digest_bytes_override = Some(32);
    let (_, report_override) =
        encode_spartan_blob_v1_with_report(&codec_override, &pcs_config, &instance, &proof)
            .unwrap();

    assert!(
        report_override.total_digest_data_bytes > report_a.total_digest_data_bytes,
        "digest payload bytes should increase with wider digest encoding"
    );
    assert!(
        report_override.effective_digest_byte_width > report_a.effective_digest_byte_width,
        "effective digest width should increase with override"
    );
}
