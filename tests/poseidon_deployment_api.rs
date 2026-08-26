mod common;

use rand::{rngs::StdRng, SeedableRng};
use spartan_whir::{
    generate_satisfiable_fixture, setup_poseidon, setup_poseidon_zk, InvalidConfigReason,
    MatrixClosingMode, PoseidonProof, PoseidonProvingKey, PoseidonSetupConfig,
    PoseidonVerifyingKey, PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkSetupConfig,
    PoseidonZkVerifyingKey, QuarticBinExtension, SpartanSnarkConfig, SpartanWhirError,
    SyntheticR1csConfig,
};

fn config(mode: MatrixClosingMode) -> PoseidonSetupConfig {
    SpartanSnarkConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        spark_whir_params: None,
    }
}

fn zk_config(mode: MatrixClosingMode) -> PoseidonZkSetupConfig {
    PoseidonZkSetupConfig {
        matrix_closing: mode,
        security: common::phase3_security(),
        whir_params: common::phase3_whir_params(),
        spark_whir_params: None,
        ell_zk: spartan_whir::DEFAULT_ZK_ELL,
        mask_log_inv_rate: spartan_whir::DEFAULT_ZK_MASK_LOG_INV_RATE,
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
fn poseidon_spark_verifying_key_authenticates_fixed_commitments() {
    let fixture = fixture();
    let (_, mut vk) =
        setup_poseidon::<QuarticBinExtension>(fixture.shape, config(MatrixClosingMode::Spark))
            .expect("setup succeeds");
    vk.authenticate_spark_fixed_commitments()
        .expect("honest key authenticates");

    // Preserve the shape dimensions and nonzero counts while changing the
    // relation represented by the serialized R1CS. Safe Rust callers only
    // receive immutable access to this commitment-bound state.
    let mut vk_json = serde_json::to_value(&vk).expect("verifying key serializes");
    let col = vk_json["shape_canonical"]["a"]["entries"][0]["col"]
        .as_u64()
        .expect("matrix column is an integer");
    vk_json["shape_canonical"]["a"]["entries"][0]["col"] = serde_json::json!(col ^ 1);
    let mut forged: PoseidonVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(vk_json).expect("forged key deserializes");
    assert_eq!(
        forged.authenticate_spark_fixed_commitments(),
        Err(SpartanWhirError::CommitmentMismatch)
    );
}

#[test]
fn poseidon_full_zk_spark_verifying_key_authenticates_fixed_commitments() {
    let fixture = fixture();
    let (_, mut vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::Spark),
    )
    .expect("setup succeeds");
    vk.authenticate_spark_fixed_commitments()
        .expect("honest key authenticates");

    let mut vk_json = serde_json::to_value(&vk).expect("verifying key serializes");
    let col = vk_json["shape_canonical"]["a"]["entries"][0]["col"]
        .as_u64()
        .expect("matrix column is an integer");
    vk_json["shape_canonical"]["a"]["entries"][0]["col"] = serde_json::json!(col ^ 1);
    let mut forged: PoseidonZkVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(vk_json).expect("forged key deserializes");
    assert_eq!(
        forged.authenticate_spark_fixed_commitments(),
        Err(SpartanWhirError::CommitmentMismatch)
    );
}

#[test]
fn poseidon_deployment_types_are_serializable() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        fixture.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");
    let witness = fixture.witness.clone();
    let public_inputs = fixture.public_inputs.clone();
    let proof = pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("prove succeeds");

    let pk_bytes = bincode::serialize(&pk).expect("proving key serializes");
    let vk_bytes = bincode::serialize(&vk).expect("verifying key serializes");
    let proof_bytes = serde_json::to_vec(&proof).expect("proof serializes");

    let mut pk_roundtrip: PoseidonProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("proving key deserializes");
    let vk_roundtrip: PoseidonVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("verifying key deserializes");
    let proof_roundtrip: PoseidonProof<QuarticBinExtension> =
        serde_json::from_slice(&proof_bytes).expect("proof deserializes");

    assert_eq!(pk_roundtrip.matrix_closing, MatrixClosingMode::DirectSparse);
    vk_roundtrip
        .verify(&proof_roundtrip)
        .expect("deserialized verifying key verifies deserialized proof");
    let missing_cache_error = match pk_roundtrip.prove(witness.clone(), public_inputs.clone()) {
        Ok(_) => panic!("deserialized proving key proves without derived cache rebuild"),
        Err(error) => error,
    };
    assert_eq!(
        missing_cache_error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::MissingDerivedProverData)
    );
    pk_roundtrip
        .prepare_for_proving()
        .expect("derived prover cache rebuild succeeds");
    let proof_from_roundtrip_pk = pk_roundtrip
        .prove(witness, public_inputs)
        .expect("deserialized proving key proves");
    vk_roundtrip
        .verify(&proof_from_roundtrip_pk)
        .expect("deserialized verifying key verifies proof from deserialized proving key");

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
fn poseidon_verifier_rejects_malformed_serialized_key_without_panicking() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        fixture.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");
    let proof = pk
        .prove(fixture.witness, fixture.public_inputs)
        .expect("prove succeeds");

    let mut encoded = serde_json::to_value(&vk).expect("verifying key serializes");
    encoded["shape_canonical"]["num_cons"] = serde_json::json!(0);
    let malformed: PoseidonVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");

    assert_eq!(
        malformed.verify(&proof),
        Err(SpartanWhirError::InvalidR1csShape)
    );

    let mut encoded = serde_json::to_value(&vk).expect("verifying key serializes");
    encoded["pcs_config"]["security"]["security_level_bits"] = serde_json::json!(80);
    let malformed: PoseidonVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");
    assert_eq!(
        malformed.verify(&proof),
        Err(SpartanWhirError::invalid_config())
    );
}

#[test]
fn poseidon_full_zk_deployment_api_is_serializable() {
    let fixture = fixture();
    let witness = fixture.witness.clone();
    let public_inputs = fixture.public_inputs.clone();
    let (pk, vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::DirectSparse),
    )
    .expect("full-ZK setup succeeds");
    let proof = pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("full-ZK proof succeeds");
    let pk_bytes = bincode::serialize(&pk).expect("full-ZK proving key serializes");
    let vk_bytes = bincode::serialize(&vk).expect("full-ZK verifying key serializes");
    let bytes = bincode::serialize(&proof).expect("full-ZK proof serializes");
    let decoded: PoseidonZkProof<QuarticBinExtension> =
        bincode::deserialize(&bytes).expect("full-ZK proof deserializes");
    let mut pk_roundtrip: PoseidonZkProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("full-ZK proving key deserializes");
    let vk_roundtrip: PoseidonZkVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("full-ZK verifying key deserializes");

    vk.verify(&decoded)
        .expect("deserialized full-ZK proof verifies");
    vk_roundtrip
        .verify(&decoded)
        .expect("deserialized full-ZK verifying key verifies");
    let error = match pk_roundtrip.prove(witness.clone(), public_inputs.clone()) {
        Ok(_) => panic!("deserialized full-ZK key must require layout preparation"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        SpartanWhirError::InvalidConfig(InvalidConfigReason::MissingDerivedProverData)
    );
    pk_roundtrip
        .prepare_for_proving()
        .expect("full-ZK derived layouts rebuild");
    let replay = pk_roundtrip
        .prove(witness, public_inputs)
        .expect("deserialized full-ZK proving key proves");
    vk_roundtrip
        .verify(&replay)
        .expect("deserialized full-ZK key pair remains reusable");
}

#[test]
fn poseidon_full_zk_verifier_rejects_malformed_serialized_key_without_panicking() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::DirectSparse),
    )
    .expect("full-ZK setup succeeds");
    let proof = pk
        .prove(fixture.witness, fixture.public_inputs)
        .expect("full-ZK proof succeeds");

    let mut encoded = serde_json::to_value(&vk).expect("full-ZK verifying key serializes");
    encoded["shape_canonical"]["num_cons"] = serde_json::json!(0);
    let malformed: PoseidonZkVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");

    assert_eq!(
        malformed.verify(&proof),
        Err(SpartanWhirError::InvalidR1csShape)
    );

    let mut encoded = serde_json::to_value(&vk).expect("full-ZK verifying key serializes");
    encoded["pcs_config"]["base"]["security"]["security_level_bits"] = serde_json::json!(80);
    let malformed: PoseidonZkVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");
    assert_eq!(
        malformed.verify(&proof),
        Err(SpartanWhirError::invalid_config())
    );
}

#[test]
fn poseidon_full_zk_spark_rejects_malformed_serialized_keys() {
    let fixture = fixture();
    let (pk, vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::Spark),
    )
    .expect("full-ZK SPARK setup succeeds");
    let proof = pk
        .prove(fixture.witness, fixture.public_inputs)
        .expect("full-ZK SPARK proof succeeds");

    let mut encoded = serde_json::to_value(&vk).expect("verifying key serializes");
    encoded["spark_pcs_configs"]["fixed_value"]["num_variables"] = serde_json::json!(0);
    let malformed: PoseidonZkVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");
    assert!(malformed.verify(&proof).is_err());

    let mut encoded = serde_json::to_value(&vk).expect("verifying key serializes");
    encoded["spark_table_metadata"]["value_domain_size"] = serde_json::json!(1);
    let malformed: PoseidonZkVerifyingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");
    assert_eq!(
        malformed.verify(&proof),
        Err(SpartanWhirError::InvalidR1csShape)
    );

    let mut encoded = serde_json::to_value(&pk).expect("proving key serializes");
    encoded["spark_tables"] = serde_json::Value::Null;
    let mut malformed: PoseidonZkProvingKey<QuarticBinExtension> =
        serde_json::from_value(encoded).expect("malformed key remains syntactically valid");
    assert_eq!(
        malformed.prepare_for_proving(),
        Err(SpartanWhirError::invalid_config())
    );
}

#[test]
fn poseidon_full_zk_deployment_api_accepts_seeded_rng() {
    let fixture = fixture();
    let witness = fixture.witness.clone();
    let public_inputs = fixture.public_inputs.clone();
    let (pk, vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");
    let mut first_rng = StdRng::seed_from_u64(0x5EED_0001);
    let mut replay_rng = StdRng::seed_from_u64(0x5EED_0001);
    let first = pk
        .prove_with_rng(witness.clone(), public_inputs.clone(), &mut first_rng)
        .expect("seeded full-ZK proof succeeds");
    let replay = pk
        .prove_with_rng(witness, public_inputs, &mut replay_rng)
        .expect("replayed full-ZK proof succeeds");

    assert_eq!(
        bincode::serialize(&first).expect("first proof serializes"),
        bincode::serialize(&replay).expect("replayed proof serializes")
    );
    vk.verify(&first).expect("seeded full-ZK proof verifies");
}

#[test]
fn poseidon_full_zk_spark_key_is_reusable_and_serializable() {
    let fixture = fixture();
    let witness = fixture.witness.clone();
    let public_inputs = fixture.public_inputs.clone();
    let (pk, vk) = setup_poseidon_zk::<QuarticBinExtension>(
        fixture.shape,
        zk_config(MatrixClosingMode::Spark),
    )
    .expect("full-ZK SPARK setup succeeds");
    let first = pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("first full-ZK SPARK proof succeeds");
    let second = pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("second full-ZK SPARK proof succeeds");
    vk.verify(&first).expect("first proof verifies");
    vk.verify(&second).expect("second proof verifies");

    let proof_bytes = bincode::serialize(&first).expect("full-ZK SPARK proof serializes");
    let proof_roundtrip: PoseidonZkProof<QuarticBinExtension> =
        bincode::deserialize(&proof_bytes).expect("full-ZK SPARK proof deserializes");
    vk.verify(&proof_roundtrip)
        .expect("deserialized full-ZK SPARK proof verifies");

    let pk_bytes = bincode::serialize(&pk).expect("full-ZK SPARK proving key serializes");
    let vk_bytes = bincode::serialize(&vk).expect("full-ZK SPARK verifying key serializes");
    let mut restored_pk: PoseidonZkProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("full-ZK SPARK proving key deserializes");
    let mut restored_vk: PoseidonZkVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("full-ZK SPARK verifying key deserializes");
    restored_pk
        .prepare_for_proving()
        .expect("derived prover layouts rebuild");
    let restored = restored_pk
        .prove(witness, public_inputs)
        .expect("restored full-ZK SPARK key proves");
    assert_eq!(
        restored_vk.verify(&restored),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::UnauthenticatedSparkVerifyingKey
        ))
    );
    restored_vk
        .authenticate_spark_fixed_commitments()
        .expect("restored full-ZK SPARK key authenticates");
    restored_vk
        .verify(&restored)
        .expect("restored full-ZK SPARK key verifies");
}

#[test]
fn poseidon_spark_proving_key_is_serializable() {
    let fixture = fixture();
    let witness = fixture.witness.clone();
    let public_inputs = fixture.public_inputs.clone();
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
        "Spark proving key should carry fixed prover data and cached Spark tables"
    );
    let first = spark_pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("first proof from reusable Spark key succeeds");
    let second = spark_pk
        .prove(witness.clone(), public_inputs.clone())
        .expect("second proof from reusable Spark key succeeds");
    spark_vk.verify(&first).expect("first Spark proof verifies");
    spark_vk
        .verify(&second)
        .expect("second Spark proof verifies");

    let proof_bytes = bincode::serialize(&first).expect("Spark proof serializes");
    let proof_roundtrip: PoseidonProof<QuarticBinExtension> =
        bincode::deserialize(&proof_bytes).expect("Spark proof deserializes");
    spark_vk
        .verify(&proof_roundtrip)
        .expect("deserialized Spark proof verifies");

    let mut pk_roundtrip: PoseidonProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("spark proving key deserializes");
    let mut vk_roundtrip: PoseidonVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("spark verifying key deserializes");
    assert_eq!(pk_roundtrip.matrix_closing, MatrixClosingMode::Spark);
    assert_eq!(vk_roundtrip.matrix_closing(), MatrixClosingMode::Spark);
    pk_roundtrip
        .prepare_for_proving()
        .expect("deserialized Spark key prepares for proving");
    let roundtrip_proof = pk_roundtrip
        .prove(witness, public_inputs)
        .expect("deserialized Spark key proves");
    assert_eq!(
        vk_roundtrip.verify(&roundtrip_proof),
        Err(SpartanWhirError::InvalidConfig(
            InvalidConfigReason::UnauthenticatedSparkVerifyingKey
        ))
    );
    vk_roundtrip
        .authenticate_spark_fixed_commitments()
        .expect("deserialized Spark verifying key authenticates");
    vk_roundtrip
        .verify(&roundtrip_proof)
        .expect("proof from deserialized Spark key verifies");
}

#[test]
fn poseidon_can_prove_from_linked_witness_generator() {
    use spartan_whir::{import_r1cs_bytes, PoseidonWitnessGenerator};

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let imported = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        imported.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    // SAFETY: these test callbacks implement the linked witness ABI and remain
    // available for the generator's full lifetime.
    let generator = unsafe {
        PoseidonWitnessGenerator::linked(
            "tiny_arithmetic",
            b"tiny.dat",
            tiny_load_circuit,
            tiny_arithmetic_witness,
            tiny_free_circuit,
        )
    }
    .expect("linked generator loads circuit");
    let proof = pk
        .prove_from_witness_generator(&generator, b"\x05")
        .expect("prove from witness generator succeeds");
    vk.verify(&proof).expect("proof verifies");
}

#[test]
fn poseidon_full_zk_spark_can_prove_compiled_circuit() {
    use spartan_whir::import_bytes;

    const R1CS: &[u8] = include_bytes!("fixtures/circom/non_power_of_two.r1cs");
    const WTNS: &[u8] = include_bytes!("fixtures/circom/non_power_of_two.wtns");

    let (shape, witness, public_inputs) = import_bytes(R1CS, WTNS).expect("circuit imports");
    let (pk, vk) =
        setup_poseidon_zk::<QuarticBinExtension>(shape, zk_config(MatrixClosingMode::Spark))
            .expect("full-ZK SPARK setup succeeds");
    let proof = pk
        .prove(witness, public_inputs)
        .expect("compiled-circuit full-ZK SPARK proof succeeds");
    vk.verify(&proof)
        .expect("compiled-circuit full-ZK SPARK proof verifies");
}

#[test]
fn linked_witness_generator_errors_are_reported() {
    use spartan_whir::{
        import_r1cs_bytes, PoseidonWitnessGenerator, PoseidonWitnessGeneratorError,
    };

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let imported = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, _vk) = setup_poseidon::<QuarticBinExtension>(
        imported.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    // SAFETY: these test callbacks implement the linked witness ABI and remain
    // available for the generator's full lifetime.
    let failing = unsafe {
        PoseidonWitnessGenerator::linked(
            "failing",
            b"tiny.dat",
            tiny_load_circuit,
            failing_witness,
            tiny_free_circuit,
        )
    }
    .expect("linked generator loads circuit");
    assert!(matches!(
        pk.prove_from_witness_generator(&failing, b""),
        Err(PoseidonWitnessGeneratorError::GeneratorFailed {
            name: "failing",
            code: 7,
            ..
        })
    ));

    // SAFETY: these test callbacks implement the linked witness ABI and remain
    // available for the generator's full lifetime.
    let noncanonical = unsafe {
        PoseidonWitnessGenerator::linked(
            "noncanonical",
            b"tiny.dat",
            tiny_load_circuit,
            noncanonical_tiny_arithmetic_witness,
            tiny_free_circuit,
        )
    }
    .expect("linked generator loads circuit");
    assert!(matches!(
        pk.prove_from_witness_generator(&noncanonical, b"\x05"),
        Err(PoseidonWitnessGeneratorError::InvalidFieldElement { .. })
    ));
}

#[test]
fn linked_witness_generator_rejects_unsatisfied_witness() {
    use spartan_whir::{
        import_r1cs_bytes, CircomAdapterError, PoseidonWitnessGenerator,
        PoseidonWitnessGeneratorError,
    };

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let imported = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        imported.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    // SAFETY: these test callbacks implement the linked witness ABI and remain
    // available for the generator's full lifetime.
    let bad = unsafe {
        PoseidonWitnessGenerator::linked(
            "bad_satisfaction",
            b"tiny.dat",
            tiny_load_circuit,
            bad_satisfaction_witness,
            tiny_free_circuit,
        )
    }
    .expect("linked generator loads circuit");

    let proof = pk
        .prove_from_witness_generator(&bad, b"\x05")
        .expect("fast path proves without explicit satisfaction validation");
    assert!(
        vk.verify(&proof).is_err(),
        "unsatisfied fast-path proof must not verify"
    );

    assert!(matches!(
        pk.prove_from_witness_generator_checked(&bad, b"\x05"),
        Err(PoseidonWitnessGeneratorError::Circom(
            CircomAdapterError::UnsatisfiedConstraint { .. }
        ))
    ));
}

unsafe extern "C" fn tiny_load_circuit(
    circuit_ptr: *const u8,
    circuit_len: usize,
    error_msg: *mut u8,
    error_msg_len: usize,
) -> *mut core::ffi::c_void {
    if circuit_len == 8 && core::slice::from_raw_parts(circuit_ptr, circuit_len) == b"tiny.dat" {
        1usize as *mut core::ffi::c_void
    } else {
        write_error(error_msg, error_msg_len, b"unexpected circuit data");
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn tiny_free_circuit(_circuit: *mut core::ffi::c_void) {}

unsafe extern "C" fn tiny_arithmetic_witness(
    circuit: *mut core::ffi::c_void,
    input_ptr: *const u8,
    input_len: usize,
    witness_ptr: *mut u32,
    witness_len: usize,
    public_inputs_ptr: *mut u32,
    public_inputs_len: usize,
    error_msg: *mut u8,
    error_msg_len: usize,
) -> i32 {
    if circuit.is_null()
        || input_len != 1
        || *input_ptr != 5
        || witness_len != 1
        || public_inputs_len != 2
    {
        write_error(
            error_msg,
            error_msg_len,
            b"unexpected linked witness ABI inputs",
        );
        return 1;
    }
    *witness_ptr = 7;
    *public_inputs_ptr.add(0) = 47;
    *public_inputs_ptr.add(1) = 5;
    spartan_whir::LINKED_WITNESS_GENERATOR_OK
}

unsafe extern "C" fn noncanonical_tiny_arithmetic_witness(
    circuit: *mut core::ffi::c_void,
    input_ptr: *const u8,
    input_len: usize,
    witness_ptr: *mut u32,
    witness_len: usize,
    public_inputs_ptr: *mut u32,
    public_inputs_len: usize,
    error_msg: *mut u8,
    error_msg_len: usize,
) -> i32 {
    let code = tiny_arithmetic_witness(
        circuit,
        input_ptr,
        input_len,
        witness_ptr,
        witness_len,
        public_inputs_ptr,
        public_inputs_len,
        error_msg,
        error_msg_len,
    );
    if code == spartan_whir::LINKED_WITNESS_GENERATOR_OK {
        *witness_ptr = spartan_whir::circom::KOALABEAR_MODULUS;
    }
    code
}

unsafe extern "C" fn bad_satisfaction_witness(
    circuit: *mut core::ffi::c_void,
    input_ptr: *const u8,
    input_len: usize,
    witness_ptr: *mut u32,
    witness_len: usize,
    public_inputs_ptr: *mut u32,
    public_inputs_len: usize,
    error_msg: *mut u8,
    error_msg_len: usize,
) -> i32 {
    let code = tiny_arithmetic_witness(
        circuit,
        input_ptr,
        input_len,
        witness_ptr,
        witness_len,
        public_inputs_ptr,
        public_inputs_len,
        error_msg,
        error_msg_len,
    );
    if code == spartan_whir::LINKED_WITNESS_GENERATOR_OK {
        *witness_ptr = 8;
    }
    code
}

unsafe extern "C" fn failing_witness(
    _circuit: *mut core::ffi::c_void,
    _input_ptr: *const u8,
    _input_len: usize,
    _witness_ptr: *mut u32,
    _witness_len: usize,
    _public_inputs_ptr: *mut u32,
    _public_inputs_len: usize,
    error_msg: *mut u8,
    error_msg_len: usize,
) -> i32 {
    write_error(error_msg, error_msg_len, b"fixture failure");
    7
}

unsafe fn write_error(error_msg: *mut u8, error_msg_len: usize, message: &[u8]) {
    if error_msg.is_null() || error_msg_len == 0 {
        return;
    }
    let copy_len = message.len().min(error_msg_len.saturating_sub(1));
    core::ptr::copy_nonoverlapping(message.as_ptr(), error_msg, copy_len);
    *error_msg.add(copy_len) = 0;
}
