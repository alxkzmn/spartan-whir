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
        spark_whir_params: None,
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
        "Spark proving key should carry fixed prover data and cached Spark tables"
    );
    let pk_roundtrip: PoseidonProvingKey<QuarticBinExtension> =
        bincode::deserialize(&pk_bytes).expect("spark proving key deserializes");
    let vk_roundtrip: PoseidonVerifyingKey<QuarticBinExtension> =
        bincode::deserialize(&vk_bytes).expect("spark verifying key deserializes");
    assert_eq!(pk_roundtrip.matrix_closing, MatrixClosingMode::Spark);
    assert_eq!(vk_roundtrip.matrix_closing, MatrixClosingMode::Spark);
}

#[cfg(feature = "circom")]
#[test]
fn poseidon_can_prove_from_linked_witness_generator() {
    use spartan_whir::{circom::import_r1cs_bytes, PoseidonWitnessGenerator};

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let circom = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, vk) = setup_poseidon::<QuarticBinExtension>(
        circom.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    let generator = PoseidonWitnessGenerator::linked(
        "tiny_arithmetic",
        b"tiny.dat",
        tiny_load_circuit,
        tiny_arithmetic_witness,
        tiny_free_circuit,
    )
    .expect("linked generator loads circuit");
    let proof = pk
        .prove_from_witness_generator(&generator, b"\x05")
        .expect("prove from witness generator succeeds");
    vk.verify(&proof).expect("proof verifies");
}

#[cfg(feature = "circom")]
#[test]
fn linked_witness_generator_errors_are_reported() {
    use spartan_whir::{
        circom::import_r1cs_bytes, PoseidonWitnessGenerator, PoseidonWitnessGeneratorError,
    };

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let circom = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, _vk) = setup_poseidon::<QuarticBinExtension>(
        circom.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    let failing = PoseidonWitnessGenerator::linked(
        "failing",
        b"tiny.dat",
        tiny_load_circuit,
        failing_witness,
        tiny_free_circuit,
    )
    .expect("linked generator loads circuit");
    assert!(matches!(
        pk.prove_from_witness_generator(&failing, b""),
        Err(PoseidonWitnessGeneratorError::GeneratorFailed {
            name: "failing",
            code: 7,
            ..
        })
    ));

    let noncanonical = PoseidonWitnessGenerator::linked(
        "noncanonical",
        b"tiny.dat",
        tiny_load_circuit,
        noncanonical_tiny_arithmetic_witness,
        tiny_free_circuit,
    )
    .expect("linked generator loads circuit");
    assert!(matches!(
        pk.prove_from_witness_generator(&noncanonical, b"\x05"),
        Err(PoseidonWitnessGeneratorError::InvalidFieldElement { .. })
    ));
}

#[cfg(feature = "circom")]
#[test]
fn linked_witness_generator_rejects_unsatisfied_witness() {
    use spartan_whir::{
        circom::{import_r1cs_bytes, CircomAdapterError},
        PoseidonWitnessGenerator, PoseidonWitnessGeneratorError,
    };

    const TINY_R1CS: &[u8] = include_bytes!("fixtures/circom/tiny_arithmetic.r1cs");

    let circom = import_r1cs_bytes(TINY_R1CS).expect("shape imports");
    let (pk, _vk) = setup_poseidon::<QuarticBinExtension>(
        circom.shape,
        config(MatrixClosingMode::DirectSparse),
    )
    .expect("setup succeeds");

    let bad = PoseidonWitnessGenerator::linked(
        "bad_satisfaction",
        b"tiny.dat",
        tiny_load_circuit,
        bad_satisfaction_witness,
        tiny_free_circuit,
    )
    .expect("linked generator loads circuit");
    assert!(matches!(
        pk.prove_from_witness_generator(&bad, b"\x05"),
        Err(PoseidonWitnessGeneratorError::Circom(
            CircomAdapterError::UnsatisfiedConstraint { .. }
        ))
    ));
}

#[cfg(feature = "circom")]
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

#[cfg(feature = "circom")]
unsafe extern "C" fn tiny_free_circuit(_circuit: *mut core::ffi::c_void) {}

#[cfg(feature = "circom")]
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

#[cfg(feature = "circom")]
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

#[cfg(feature = "circom")]
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

#[cfg(feature = "circom")]
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

#[cfg(feature = "circom")]
unsafe fn write_error(error_msg: *mut u8, error_msg_len: usize, message: &[u8]) {
    if error_msg.is_null() || error_msg_len == 0 {
        return;
    }
    let copy_len = message.len().min(error_msg_len.saturating_sub(1));
    core::ptr::copy_nonoverlapping(message.as_ptr(), error_msg, copy_len);
    *error_msg.add(copy_len) = 0;
}
