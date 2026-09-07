use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process,
};

use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_koala_bear::{
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    KOALABEAR_POSEIDON2_RC_16_INTERNAL, KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_24_INTERNAL,
};
use p3_merkle_tree::MerkleCap;
use p3_whir::pcs::proof::QueryOpenings;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use spartan_whir::protocol::{
    fixed_audit_column_count, fixed_value_column_count, read_table_group_column_counts,
};
use spartan_whir::{
    control_statement_digest, control_statement_digest_preimage, control_verifying_key_id,
    decode_control_guest_input, encode_control_guest_input, generate_satisfiable_fixture,
    recommended_quintic_spark_fixed_whir_params, recommended_quintic_spark_read_whir_params,
    recommended_quintic_spark_zk_whir_params, recommended_quintic_zk_whir_params,
    verify_control_with_trace, MatrixClosingMode, PoseidonProof, PoseidonSpartanProof,
    PoseidonSpartanProtocol, PoseidonTranscriptEvent, PoseidonZkSetupConfig, QuinticExtension,
    SecurityConfig, SoundnessAssumption, SparkWhirParams, SpartanProofKind, SpartanSnarkConfig,
    SyntheticR1csConfig, WhirParams, DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE,
    LEANVM_CONTROL_PROFILE_ID, LEANVM_CONTROL_PROFILE_NUMBER, LEANVM_CONTROL_STATEMENT_DIGEST_ID,
    LEANVM_CONTROL_STATEMENT_SCHEMA_ID, LEANVM_GUEST_INPUT_VERSION, MAX_CONTROL_GUEST_WORDS,
};

type ControlProof = PoseidonProof<QuinticExtension>;
type ControlDirectProof = PoseidonSpartanProof<QuinticExtension>;

const APPLICATION_R1CS_SHA256: &str =
    "1f1c6beae387e938d86b5ca433abc024945f14c2763db0c29638613ebb206627";
const APPLICATION_RAW_VARIABLES: usize = 593_120;
const APPLICATION_LOG2_WITNESS_VARIABLES: usize = 20;
const APPLICATION_PADDED_WITNESS_VARIABLES: usize = 1 << APPLICATION_LOG2_WITNESS_VARIABLES;
const APPLICATION_SPARK_RAW_ABC_ENTRIES: usize = 4_850_245;
const APPLICATION_SPARK_UNION_NNZ: usize = 3_251_928;
const MAX_PRODUCTION_GUEST_WORDS: usize = 1 << 20;
const M1_CONTROL_WHIR_LOG_INV_RATE: usize = 2;

#[derive(Debug, Serialize)]
struct SourceRevisions {
    spartan_whir: String,
    leanvm_upstream_base: String,
    leanvm_branch_head: String,
    sol_spartan_whir: String,
    plonky3: String,
    plonky3_source: &'static str,
}

#[derive(Debug, Serialize)]
struct ArtifactRecord {
    file: String,
    sha256: String,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct MutationRecord {
    target: &'static str,
    artifact: ArtifactRecord,
    expected_result: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let output_dir = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let revisions = SourceRevisions {
        spartan_whir: required_arg(&mut args, "spartan-whir commit")?,
        leanvm_upstream_base: required_arg(&mut args, "leanVM upstream base commit")?,
        leanvm_branch_head: required_arg(&mut args, "leanVM branch HEAD")?,
        sol_spartan_whir: required_arg(&mut args, "sol-spartan-whir commit")?,
        plonky3: locked_plonky3_revision()?,
        plonky3_source: "spartan-whir/Cargo.lock",
    };
    if args.next().is_some() {
        usage();
    }
    fs::create_dir_all(&output_dir)?;
    fs::create_dir_all(output_dir.join("mutations"))?;

    let fixture_config = SyntheticR1csConfig {
        target_log2_witness_poly: 2,
        num_constraints: 2,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0xC11E_1715_7A7E,
    };
    let fixture = generate_satisfiable_fixture(&fixture_config).map_err(protocol_error)?;
    let control_config = control_config();
    let (pk, vk) = PoseidonSpartanProtocol::<QuinticExtension>::setup_with_config(
        &fixture.shape,
        &control_config,
    )
    .map_err(protocol_error)?;
    let proof = pk
        .prove(fixture.witness, fixture.public_inputs.clone())
        .map_err(protocol_error)?;
    vk.verify(&fixture.public_inputs, &proof)
        .map_err(protocol_error)?;

    let guest_words = encode_control_guest_input(&proof).map_err(protocol_error)?;
    let decoded = decode_control_guest_input(&guest_words).map_err(protocol_error)?;
    vk.verify(&fixture.public_inputs, &decoded)
        .map_err(protocol_error)?;
    let reproduced = encode_control_guest_input(&decoded).map_err(protocol_error)?;
    if reproduced != guest_words {
        return Err(io::Error::other("control proof did not re-encode exactly").into());
    }

    let guest_input = write_words(&output_dir, "control_guest_input.words", &guest_words)?;
    let trace =
        verify_control_with_trace(&vk, &fixture.public_inputs, &proof).map_err(protocol_error)?;
    let trace_artifact = write_json(&output_dir, "control_transcript_trace.json", &trace)?;

    let guest_constants = control_guest_constants(&vk, &trace, &fixture.public_inputs)?;
    let guest_constants_artifact = write_json(
        &output_dir,
        "control_guest_constants.json",
        &guest_constants,
    )?;

    let digest_preimage = control_statement_digest_preimage(&fixture.public_inputs);
    let digest = control_statement_digest(&fixture.public_inputs);
    let statement = json!({
        "schema": LEANVM_CONTROL_STATEMENT_SCHEMA_ID,
        "inner_public_inputs": canonical(&fixture.public_inputs),
        "digest_algorithm": LEANVM_CONTROL_STATEMENT_DIGEST_ID,
        "digest_preimage": canonical(&digest_preimage),
        "digest": canonical(&digest),
    });
    let statement_artifact = write_json(&output_dir, "control_statement.json", &statement)?;

    let mut mutations = Vec::new();
    mutations.push(write_proof_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_public_input",
        "application public input",
        |proof| proof.instance.public_inputs[0] += spartan_whir::engine::F::ONE,
    )?);
    mutations.push(write_proof_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_witness_commitment",
        "witness commitment",
        |proof| {
            let mut roots = proof.instance.witness_commitment.roots().to_vec();
            roots[0][0] += spartan_whir::engine::F::ONE;
            proof.instance.witness_commitment = MerkleCap::new(roots);
        },
    )?);
    mutations.push(write_direct_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_outer_sumcheck",
        "outer sumcheck",
        |proof| proof.outer_sumcheck.rounds[0].0[0] += QuinticExtension::ONE,
    )?);
    mutations.push(write_direct_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_outer_claim",
        "outer claims",
        |proof| proof.outer_claims.0 += QuinticExtension::ONE,
    )?);
    mutations.push(write_direct_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_inner_sumcheck",
        "inner sumcheck",
        |proof| proof.inner_sumcheck.rounds[0].0[0] += QuinticExtension::ONE,
    )?);
    mutations.push(write_direct_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_witness_evaluation",
        "witness evaluation",
        |proof| proof.witness_eval += QuinticExtension::ONE,
    )?);
    mutations.push(write_direct_mutation(
        &output_dir,
        &guest_words,
        &fixture.public_inputs,
        &vk,
        "changed_whir_opening",
        "WHIR opening",
        |proof| match &mut proof.pcs_proof.final_openings {
            QueryOpenings::Base(opening) => {
                opening.rows[0][0] += spartan_whir::engine::F::ONE;
            }
            QueryOpenings::Extension(opening) => {
                opening.rows[0][0] += QuinticExtension::ONE;
            }
        },
    )?);

    let mut wrong_version = guest_words.clone();
    wrong_version[4] = LEANVM_GUEST_INPUT_VERSION + 1;
    mutations.push(write_decode_mutation(
        &output_dir,
        "wrong_version",
        "encoding version",
        &wrong_version,
    )?);
    let mut trailing = guest_words.clone();
    trailing.push(0);
    mutations.push(write_decode_mutation(
        &output_dir,
        "trailing_word",
        "exact proof consumption",
        &trailing,
    )?);

    let verifying_key_id = control_verifying_key_id(&vk);
    let fixture_manifest = json!({
        "manifest_version": 1,
        "profile_id": LEANVM_CONTROL_PROFILE_ID,
        "profile_number": LEANVM_CONTROL_PROFILE_NUMBER,
        "guest_input_version": LEANVM_GUEST_INPUT_VERSION,
        "source_revisions": revisions,
        "implementation_source_ids": implementation_source_ids(),
        "field": {
            "base": "KoalaBear",
            "modulus": spartan_whir::engine::F::ORDER_U32,
            "extension": "X^5 + X^2 - 1",
            "extension_coordinate_order": ["1", "X", "X^2", "X^3", "X^4"],
        },
        "privacy_mode": "no_zk",
        "matrix_closing": "direct_sparse",
        "security": control_config.security,
        "whir_params": control_config.whir_params,
        "synthetic_r1cs": {
            "target_log2_witness_poly": fixture_config.target_log2_witness_poly,
            "num_constraints": fixture_config.num_constraints,
            "num_io": fixture_config.num_io,
            "a_terms_per_constraint": fixture_config.a_terms_per_constraint,
            "b_terms_per_constraint": fixture_config.b_terms_per_constraint,
            "seed": fixture_config.seed,
        },
        "canonical_shape": {
            "constraints": vk.shape_canonical().num_cons,
            "variables": vk.shape_canonical().num_vars,
            "public_inputs": vk.shape_canonical().num_io,
        },
        "verifying_key_id": hex(&verifying_key_id),
        "guest_input": guest_input,
        "guest_input_words": guest_words.len(),
        "guest_input_word_limit": MAX_CONTROL_GUEST_WORDS,
        "statement": statement_artifact,
        "guest_constants": guest_constants_artifact,
        "transcript_trace": trace_artifact,
        "transcript_events": trace.len(),
        "mutations": mutations,
    });
    write_json(
        &output_dir,
        "control_fixture_manifest.json",
        &fixture_manifest,
    )?;

    let protocol_manifest = protocol_manifest(revisions_value(&fixture_manifest))?;
    write_json(&output_dir, "protocol_manifest.json", &protocol_manifest)?;
    println!("wrote LeanVM M0 fixtures to {}", output_dir.display());
    Ok(())
}

fn control_guest_constants(
    verifying_key: &spartan_whir::PoseidonVerifyingKey<QuinticExtension>,
    trace: &[PoseidonTranscriptEvent],
    public_inputs: &[spartan_whir::engine::F],
) -> Result<serde_json::Value, Box<dyn Error>> {
    let spartan_domain_separator = trace
        .get(..83)
        .ok_or_else(|| io::Error::other("control trace is missing the Spartan domain separator"))?
        .iter()
        .map(|event| match event {
            PoseidonTranscriptEvent::Observe { values } if values.len() == 1 => Ok(values[0]),
            _ => Err(io::Error::other(
                "control trace Spartan domain separator has an unexpected event",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    match trace.get(83) {
        Some(PoseidonTranscriptEvent::Observe { values })
            if values == &canonical(public_inputs) => {}
        _ => {
            return Err(io::Error::other(
                "control trace public input checkpoint has an unexpected value",
            )
            .into());
        }
    }
    let whir_domain_separator = match trace.get(84) {
        Some(PoseidonTranscriptEvent::Observe { values }) => values.clone(),
        _ => {
            return Err(io::Error::other(
                "control trace WHIR domain separator has an unexpected event",
            )
            .into());
        }
    };

    let inverse_power_of_two =
        |exponent: u64| spartan_whir::engine::F::TWO.exp_u64(exponent).inverse();
    let inv2 = inverse_power_of_two(1);
    let inv4 = inverse_power_of_two(2);
    let inv8 = inverse_power_of_two(3);
    let inv16 = inverse_power_of_two(4);
    let inv32 = inverse_power_of_two(5);
    let inv64 = inverse_power_of_two(6);
    let inv128 = inverse_power_of_two(7);
    let inv256 = inverse_power_of_two(8);
    let inv512 = inverse_power_of_two(9);
    let inv2_24 = inverse_power_of_two(24);
    let f = |value: i32| {
        if value >= 0 {
            spartan_whir::engine::F::from_u32(value as u32)
        } else {
            -spartan_whir::engine::F::from_u32((-value) as u32)
        }
    };
    let internal_diagonal_16 = [
        f(-2),
        f(1),
        f(2),
        inv2,
        f(3),
        f(4),
        -inv2,
        f(-3),
        f(-4),
        inv256,
        inv8,
        inv2_24,
        -inv256,
        -inv8,
        -inv16,
        -inv2_24,
    ];
    let internal_diagonal_24 = [
        f(-2),
        f(1),
        f(2),
        inv2,
        f(3),
        f(4),
        -inv2,
        f(-3),
        f(-4),
        inv256,
        inv4,
        inv8,
        inv16,
        inv32,
        inv64,
        inv2_24,
        -inv256,
        -inv8,
        -inv16,
        -inv32,
        -inv64,
        -inv128,
        -inv512,
        -inv2_24,
    ];
    let shape = verifying_key.shape_canonical();

    Ok(json!({
        "schema": "leanvm-control-guest-constants-v1",
        "spartan_domain_separator": spartan_domain_separator,
        "whir_domain_separator": whir_domain_separator,
        "canonical_shape": {
            "constraints": shape.num_cons,
            "variables": shape.num_vars,
            "public_inputs": shape.num_io,
            "a": canonical_matrix(&shape.a),
            "b": canonical_matrix(&shape.b),
            "c": canonical_matrix(&shape.c),
        },
        "poseidon2": {
            "width_16": {
                "external_initial": canonical_2d(&KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL),
                "internal": canonical(&KOALABEAR_POSEIDON2_RC_16_INTERNAL),
                "external_final": canonical_2d(&KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL),
                "internal_diagonal": canonical(&internal_diagonal_16),
            },
            "width_24": {
                "external_initial": canonical_2d(&KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL),
                "internal": canonical(&KOALABEAR_POSEIDON2_RC_24_INTERNAL),
                "external_final": canonical_2d(&KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL),
                "internal_diagonal": canonical(&internal_diagonal_24),
            },
        },
        "whir": {
            "num_variables": 2,
            "folding_factor": 1,
            "starting_domain_size": 256,
            "folded_domain_size": 128,
            "folded_domain_generator": spartan_whir::engine::F::two_adic_generator(7).as_canonical_u32(),
            "final_queries": 14,
            "uniform_query_bits": 7,
        },
    }))
}

fn canonical_matrix(
    matrix: &spartan_whir::SparseMatrix<spartan_whir::engine::F>,
) -> serde_json::Value {
    json!({
        "rows": matrix.num_rows,
        "columns": matrix.num_cols,
        "entries": matrix.entries.iter().map(|entry| json!({
            "row": entry.row,
            "column": entry.col,
            "value": entry.val.as_canonical_u32(),
        })).collect::<Vec<_>>(),
    })
}

fn canonical_2d<const ROWS: usize, const COLUMNS: usize>(
    values: &[[spartan_whir::engine::F; COLUMNS]; ROWS],
) -> Vec<Vec<u32>> {
    values.iter().map(|row| canonical(row)).collect()
}

fn protocol_manifest(
    source_revisions: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let value_domain_size = APPLICATION_SPARK_UNION_NNZ.next_power_of_two();
    let value_domain_log2 = exact_log2(value_domain_size, "SPARK value domain")?;
    let fixed_value_columns = fixed_value_column_count();
    let fixed_value_num_variables =
        value_domain_log2 + exact_log2(fixed_value_columns, "SPARK fixed-value column count")?;
    let row_memory_size = APPLICATION_PADDED_WITNESS_VARIABLES;
    let col_memory_size = APPLICATION_PADDED_WITNESS_VARIABLES * 2;
    let fixed_audit_columns = fixed_audit_column_count();
    let fixed_audit_domain_size = row_memory_size.max(col_memory_size) * fixed_audit_columns;
    let fixed_audit_num_variables = exact_log2(fixed_audit_domain_size, "SPARK audit domain")?;
    let read_group_columns =
        read_table_group_column_counts::<QuinticExtension>().map_err(protocol_error)?;
    let read_num_variables = read_group_columns
        .iter()
        .map(|&columns| {
            Ok(value_domain_log2 + exact_log2(columns, "SPARK read-group column count")?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let shared_read_num_variables = read_num_variables
        .iter()
        .copied()
        .max()
        .ok_or_else(|| io::Error::other("SPARK read groups are empty"))?;

    let security = SecurityConfig {
        security_level_bits: 116,
        merkle_security_bits: 116,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    let spark_whir_params = SparkWhirParams {
        fixed_value: recommended_quintic_spark_fixed_whir_params(fixed_value_num_variables),
        fixed_audit: recommended_quintic_spark_fixed_whir_params(fixed_audit_num_variables),
        read: recommended_quintic_spark_read_whir_params(shared_read_num_variables),
    };
    let direct = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security,
        whir_params: recommended_quintic_zk_whir_params(20),
        spark_whir_params: None,
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    };
    let spark = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::Spark,
        security,
        whir_params: recommended_quintic_spark_zk_whir_params(20),
        spark_whir_params: Some(spark_whir_params),
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    };

    Ok(json!({
        "manifest_version": 1,
        "m0_state": "complete",
        "source_revisions": source_revisions,
        "implementation_source_ids": implementation_source_ids(),
        "application": {
            "id": "sha256-2048-byte-optimized-v1",
            "circuit_source": "tests/circuits/optimized/sha256_2048b.circom",
            "r1cs_sha256": APPLICATION_R1CS_SHA256,
            "raw_constraints": 605424,
            "padded_rows": 1048576,
            "raw_variables": APPLICATION_RAW_VARIABLES,
            "log2_witness_variables": APPLICATION_LOG2_WITNESS_VARIABLES,
            "padded_witness_variables": APPLICATION_PADDED_WITNESS_VARIABLES,
            "public_statement": {
                "schema": "sha256-digest-bits-msb-first-v1",
                "fields": 256,
                "values": "boolean KoalaBear elements",
            },
        },
        "control_profile": {
            "id": LEANVM_CONTROL_PROFILE_ID,
            "encoding": "leanvm-control-field-words-v1",
            "fixture_manifest": "control_fixture_manifest.json",
        },
        "production_candidates": {
            "privacy": "full_zk",
            "base_field": "KoalaBear",
            "extension": "X^5 + X^2 - 1",
            "selected_hash_profile": "spartan-whir-poseidon1-v1",
            "selected_matrix_closing": "spark",
            "hash_candidates": [
                "spartan-whir-poseidon2-leanvm-instructions-v1",
                "spartan-whir-poseidon1-v1",
                "spartan-whir-poseidon2-leanvm-precompile-v1"
            ],
            "matrix_closing": {
                "direct_sparse": direct,
                "spark": spark,
            },
            "spark_sizing": {
                "raw_abc_entries": APPLICATION_SPARK_RAW_ABC_ENTRIES,
                "union_nnz": APPLICATION_SPARK_UNION_NNZ,
                "value_domain_size": value_domain_size,
                "value_domain_log2": value_domain_log2,
                "fixed_value_columns": fixed_value_columns,
                "fixed_value_num_variables": fixed_value_num_variables,
                "row_memory_size": row_memory_size,
                "column_memory_size": col_memory_size,
                "fixed_audit_columns": fixed_audit_columns,
                "fixed_audit_num_variables": fixed_audit_num_variables,
                "quintic_read_group_columns": read_group_columns,
                "quintic_read_num_variables": read_num_variables,
                "shared_read_schedule_num_variables": shared_read_num_variables,
                "derivation": "The application has 3251928 SPARK union entries, which round to a 2^22 value domain. Eight fixed-value columns give 22 + 3 = 25 variables. The 2^21 column memory dominates the 2^20 row memory, and two audit columns give a 2^22 audit domain. The ten quintic read coordinates split into eight- and two-column groups, giving 25 and 23 variables; the shared read schedule is selected at 25 and validated for both groups.",
                "measurement_source": "benchmark-results/2026-08-27-sha256-2048b-schedule-refresh.md"
            },
            "proof_encoding_ids": {
                "direct_sparse": {
                    "id": "leanvm-full-zk-direct-field-words-v1",
                    "status": "implemented; production guest rejected by LeanVM limits",
                    "rust_proof_type": "PoseidonZkProof with DirectSparse matrix closing",
                    "runtime_matrix_closing_tag": false
                },
                "spark": {
                    "id": "leanvm-full-zk-spark-field-words-v1",
                    "status": "implemented and selected",
                    "rust_proof_type": "PoseidonZkProof with SPARK matrix closing",
                    "runtime_matrix_closing_tag": false
                }
            },
        },
        "outer_profile": {
            "profile_id": "spartan-whir-poseidon1-quintic-full-zk-spark-leanvm-v1",
            "proof_system": "LeanVM execution proof",
            "transcript_and_merkle": "LeanVM Poseidon1",
            "security_bits": 121,
            "pow_bits": 16,
            "whir_initial_folding_factor": 9,
            "whir_subsequent_folding_factor": 5,
            "rs_domain_initial_reduction_factor": 5,
            "public_input_elements": 8,
            "statement_digest_delivery": "fixed application adapter supplies the canonical digest",
            "guest_bytecode_hash": [1029837421_u32, 1341148120, 691546331, 261592802, 1374499229, 1181121684, 850759154, 277945311],
            "m1_control_whir_log_inverse_rate": M1_CONTROL_WHIR_LOG_INV_RATE,
            "supported_whir_log_inverse_rates": [1, 2, 3, 4],
            "production_whir_log_inverse_rate": 1,
            "table_padding": {
                "log_rows_rule": "max(ceil(log2(non_padded_rows + 1)), profile_min_log_rows, 8)",
                "m1_control_profile_min_log_rows": {},
                "memory_rule": "next_power_of_two(max(memory_cells_after_padding_constants, execution_cycles, 256))",
                "maximum_log_rows": {
                    "execution": 26,
                    "extension_op": 22,
                    "poseidon16": 22
                }
            },
            "memory_log_size": 26,
            "table_log_rows": {
                "execution": 25,
                "extension_op": 21,
                "poseidon16": 17
            },
        },
        "limits": {
            "control_guest_input_words": MAX_CONTROL_GUEST_WORDS,
            "production_guest_input_words": MAX_PRODUCTION_GUEST_WORDS,
            "production_guest_input_bytes": MAX_PRODUCTION_GUEST_WORDS * 4,
            "production_guest_input_limit_basis": "The selected full-ZK SPARK proof uses 682698 canonical field words and pads to the fixed 1048576-word LeanVM witness.",
            "terminal_chain": "Ethereum mainnet",
            "terminal_chain_id": 1,
            "terminal_execution_environment": "standard EVM",
            "terminal_runtime_bytecode_bytes": 24576,
            "terminal_measurement_milestone": "M4",
            "terminal_acceptance_milestone": "M5",
            "terminal_acceptance_rule": "The complete verifier transaction must fit the current Ethereum mainnet block gas limit. M4 records calldata bytes, calldata gas, execution gas, total transaction gas, runtime bytecode, and required precompiles; M5 records the measured margin and accepts or rejects the deployment profile.",
        },
        "open_decisions": []
    }))
}

fn implementation_source_ids() -> serde_json::Value {
    json!({
        "Cargo.lock": source_sha256(include_bytes!("../../Cargo.lock")),
        "src/bin/leanvm-m0-fixture.rs": source_sha256(include_bytes!("leanvm-m0-fixture.rs")),
        "src/engine.rs": source_sha256(include_bytes!("../engine.rs")),
        "src/leanvm.rs": source_sha256(include_bytes!("../leanvm.rs")),
        "src/lib.rs": source_sha256(include_bytes!("../lib.rs")),
        "src/poseidon_trace.rs": source_sha256(include_bytes!("../poseidon_trace.rs")),
    })
}

fn exact_log2(value: usize, name: &str) -> Result<usize, Box<dyn Error>> {
    if value == 0 || !value.is_power_of_two() {
        return Err(io::Error::other(format!("{name} must be a non-zero power of two")).into());
    }
    Ok(value.ilog2() as usize)
}

fn locked_plonky3_revision() -> Result<String, Box<dyn Error>> {
    let mut revisions = BTreeSet::new();
    for line in include_str!("../../Cargo.lock").lines() {
        let Some(source) = line
            .strip_prefix("source = \"")
            .and_then(|line| line.strip_suffix('"'))
        else {
            continue;
        };
        if !source.contains("/Plonky3.git?rev=") {
            continue;
        }
        let revision = source
            .rsplit_once('#')
            .map(|(_, revision)| revision)
            .ok_or_else(|| {
                io::Error::other("Plonky3 Cargo.lock source has no resolved revision")
            })?;
        revisions.insert(revision.to_owned());
    }
    if revisions.len() != 1 {
        return Err(io::Error::other(format!(
            "expected one resolved Plonky3 revision in Cargo.lock, found {}",
            revisions.len()
        ))
        .into());
    }
    Ok(revisions.into_iter().next().unwrap())
}

fn source_sha256(source: &[u8]) -> String {
    hex(&Sha256::digest(source))
}

fn control_config() -> SpartanSnarkConfig {
    SpartanSnarkConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: 80,
            merkle_security_bits: 80,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        },
        whir_params: WhirParams {
            pow_bits: 0,
            folding_factor: 1,
            starting_log_inv_rate: 6,
            rs_domain_initial_reduction_factor: 1,
            ..WhirParams::default()
        },
        spark_whir_params: None,
    }
}

fn write_proof_mutation(
    output_dir: &Path,
    original: &[u32],
    public_inputs: &[spartan_whir::engine::F],
    verifying_key: &spartan_whir::PoseidonVerifyingKey<QuinticExtension>,
    file_stem: &str,
    target: &'static str,
    mutate: impl FnOnce(&mut ControlProof),
) -> Result<MutationRecord, Box<dyn Error>> {
    let mut proof = decode_control_guest_input(original).map_err(protocol_error)?;
    mutate(&mut proof);
    let words = encode_control_guest_input(&proof).map_err(protocol_error)?;
    let expected_result = verifying_key
        .verify(public_inputs, &proof)
        .err()
        .ok_or_else(|| io::Error::other(format!("{target} mutation was accepted")))?
        .to_string();
    let artifact = write_words(output_dir, &format!("mutations/{file_stem}.words"), &words)?;
    Ok(MutationRecord {
        target,
        artifact,
        expected_result,
    })
}

fn write_direct_mutation(
    output_dir: &Path,
    original: &[u32],
    public_inputs: &[spartan_whir::engine::F],
    verifying_key: &spartan_whir::PoseidonVerifyingKey<QuinticExtension>,
    file_stem: &str,
    target: &'static str,
    mutate: impl FnOnce(&mut ControlDirectProof),
) -> Result<MutationRecord, Box<dyn Error>> {
    write_proof_mutation(
        output_dir,
        original,
        public_inputs,
        verifying_key,
        file_stem,
        target,
        |proof| mutate(direct_mut(proof)),
    )
}

fn direct_mut(proof: &mut ControlProof) -> &mut ControlDirectProof {
    match &mut proof.proof {
        SpartanProofKind::Direct(proof) => proof,
        SpartanProofKind::Spark(_) => unreachable!("control decoder fixes DirectSparse"),
    }
}

fn write_decode_mutation(
    output_dir: &Path,
    file_stem: &str,
    target: &'static str,
    words: &[u32],
) -> Result<MutationRecord, Box<dyn Error>> {
    let expected_result = decode_control_guest_input(words)
        .err()
        .ok_or_else(|| io::Error::other(format!("{target} mutation decoded")))?
        .to_string();
    let artifact = write_words(output_dir, &format!("mutations/{file_stem}.words"), words)?;
    Ok(MutationRecord {
        target,
        artifact,
        expected_result,
    })
}

fn write_words(
    output_dir: &Path,
    relative: &str,
    words: &[u32],
) -> Result<ArtifactRecord, Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(words));
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    write_bytes(output_dir, relative, &bytes)
}

fn write_json(
    output_dir: &Path,
    relative: &str,
    value: &impl Serialize,
) -> Result<ArtifactRecord, Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes(output_dir, relative, &bytes)
}

fn write_bytes(
    output_dir: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<ArtifactRecord, Box<dyn Error>> {
    let path = output_dir.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    Ok(ArtifactRecord {
        file: relative.to_owned(),
        sha256: hex(&Sha256::digest(bytes)),
        bytes: bytes.len(),
    })
}

fn canonical(values: &[spartan_whir::engine::F]) -> Vec<u32> {
    values.iter().map(PrimeField32::as_canonical_u32).collect()
}

fn revisions_value(fixture_manifest: &serde_json::Value) -> serde_json::Value {
    fixture_manifest["source_revisions"].clone()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn protocol_error(error: spartan_whir::SpartanWhirError) -> io::Error {
    io::Error::other(error.to_string())
}

fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| io::Error::other(format!("missing {name}")))?
        .into_string()
        .map_err(|_| io::Error::other(format!("{name} must be UTF-8")).into())
}

fn usage() -> ! {
    eprintln!(
        "usage: leanvm-m0-fixture <output-dir> <spartan-whir-commit> <leanvm-upstream-base> <leanvm-branch-head> <sol-spartan-whir-commit>"
    );
    process::exit(2);
}
