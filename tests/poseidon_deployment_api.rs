mod common;

use spartan_whir::{
    generate_satisfiable_fixture, setup_poseidon, MatrixClosingMode, PoseidonProof,
    PoseidonProvingKey, PoseidonSetupConfig, PoseidonVerifyingKey, QuarticBinExtension,
    SpartanSnarkConfig, SyntheticR1csConfig,
};

fn config(mode: MatrixClosingMode) -> PoseidonSetupConfig {
    SpartanSnarkConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        pcs_config: common::phase3_pcs_config(),
    }
}

fn fixture() -> spartan_whir::SyntheticR1csFixture {
    generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 2,
        num_constraints: 2,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0xD39E_0105_EE11,
    })
    .expect("fixture generation succeeds")
}

fn roundtrip_mode(mode: MatrixClosingMode) {
    let fixture = fixture();
    let (pk, vk) = PoseidonProvingKey::<QuarticBinExtension>::setup(fixture.shape, config(mode))
        .expect("setup succeeds");

    let proof = pk
        .prove(fixture.witness, fixture.public_inputs)
        .expect("prove succeeds");
    vk.verify(&proof).expect("verify succeeds");
    assert_eq!(proof.closing_mode(), mode);
}

#[test]
fn generic_poseidon_direct_api_roundtrips() {
    roundtrip_mode(MatrixClosingMode::DirectSparse);
}

#[test]
fn generic_poseidon_spark_api_roundtrips() {
    roundtrip_mode(MatrixClosingMode::Spark);
}

#[test]
fn poseidon_deployment_types_are_serializable() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        fixture.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");
    let proof = pk
        .prove(fixture.witness, fixture.public_inputs)
        .expect("prove succeeds");

    let pk_bytes = bincode::serialize(&pk).expect("proving key serializes");
    let vk_bytes = bincode::serialize(&vk).expect("verifying key serializes");
    let proof_bytes = serde_json::to_vec(&proof).expect("proof serializes");

    let pk_roundtrip: PoseidonProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("proving key deserializes");
    let vk_roundtrip: PoseidonVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("verifying key deserializes");
    let proof_roundtrip: PoseidonProof<QuarticBinExtension> =
        serde_json::from_slice(&proof_bytes).expect("proof deserializes");

    assert_eq!(pk_roundtrip.matrix_closing, MatrixClosingMode::DirectSparse);
    vk_roundtrip
        .verify(&proof_roundtrip)
        .expect("deserialized verifying key verifies deserialized proof");

    let mut tampered_proof_bytes = proof_bytes;
    let byte = tampered_proof_bytes
        .iter_mut()
        .find(|byte| byte.is_ascii_digit())
        .expect("serialized proof has a digit to tamper");
    *byte = if *byte == b'0' { b'1' } else { b'0' };
    match serde_json::from_slice::<PoseidonProof<QuarticBinExtension>>(&tampered_proof_bytes) {
        Ok(tampered_proof) => assert!(vk_roundtrip.verify(&tampered_proof).is_err()),
        Err(_) => {}
    }
}

#[test]
fn poseidon_spark_proving_key_is_serializable() {
    let fixture = fixture();
    let (direct_pk, _direct_vk) = setup_poseidon::<QuarticBinExtension>(
        fixture.shape.clone(),
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("direct setup succeeds");
    let (spark_pk, spark_vk) =
        setup_poseidon::<QuarticBinExtension>(fixture.shape, config(MatrixClosingMode::Spark))
            .expect("spark setup succeeds");
    let direct_pk_bytes = bincode::serialize(&direct_pk).expect("direct proving key serializes");
    let pk_bytes = bincode::serialize(&spark_pk).expect("spark proving key serializes");
    let vk_bytes = bincode::serialize(&spark_vk).expect("spark verifying key serializes");
    assert!(
        direct_pk_bytes.len() < 100_000,
        "tiny direct proving key should stay below 100 KB"
    );
    assert!(
        direct_pk_bytes.len() < pk_bytes.len(),
        "Spark proving key should carry fixed prover data"
    );
    let pk_roundtrip: PoseidonProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("spark proving key deserializes");
    let vk_roundtrip: PoseidonVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("spark verifying key deserializes");
    assert_eq!(pk_roundtrip.matrix_closing, MatrixClosingMode::Spark);
    assert_eq!(vk_roundtrip.matrix_closing, MatrixClosingMode::Spark);
}

#[cfg(all(feature = "circom", unix))]
#[test]
fn poseidon_can_prove_from_native_witness_generator() {
    use std::time::Duration;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::TempDir;

    use spartan_whir::{
        circom::import_r1cs_bytes, PoseidonWitnessGenerator, PoseidonWitnessGeneratorError,
    };

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");
    const TINY_WTNS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.wtns");

    let circom = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        circom.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    let dir = TempDir::new().expect("temp dir created");
    let wtns_path = dir.path().join("fixture.wtns");
    let script_path = dir.path().join("witness.sh");
    fs::write(&wtns_path, TINY_WTNS).expect("wtns fixture written");
    fs::write(
        &script_path,
        format!("#!/bin/sh\ncp '{}' \"$2\"\n", wtns_path.display()),
    )
    .expect("script written");
    let mut permissions = fs::metadata(&script_path)
        .expect("script metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions).expect("script executable");

    let too_small_generator = PoseidonWitnessGenerator::native_executable(&script_path)
        .with_timeout(Duration::from_secs(5))
        .with_max_witness_bytes(1);
    assert!(matches!(
        pk.prove_from_witness_generator(&too_small_generator, b"{}"),
        Err(PoseidonWitnessGeneratorError::WitnessTooLarge { .. })
    ));

    let generator = PoseidonWitnessGenerator::native_executable(&script_path)
        .with_timeout(Duration::from_secs(5));
    let proof = pk
        .prove_from_witness_generator(&generator, b"{}")
        .expect("prove from witness generator succeeds");
    vk.verify(&proof).expect("proof verifies");
}
