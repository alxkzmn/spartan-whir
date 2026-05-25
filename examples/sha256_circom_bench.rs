use std::{
    env,
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use p3_field::{PrimeField32, TwoAdicField};
use sha2::{Digest, Sha256};
use spartan_whir::{
    circom::import_paths, compare_spark_layouts, engine::F, KeccakQuarticEngine as KeccakEngine,
    MatrixClosingMode, R1csShape, R1csWitness, SecurityConfig, SoundnessAssumption,
    SparkLayoutDecision, SpartanProtocol, SpartanSnarkConfig, SumcheckStrategy, WhirParams,
    WhirPcs, WhirPcsConfig,
};

const DEFAULT_SIZES: &[usize] = &[128, 256, 512, 1024, 2048];

#[derive(Debug)]
struct ArtifactPaths {
    r1cs: PathBuf,
    wtns: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workdir = env::var_os("SHA256_BENCH_WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("spartan-whir-sha256-bench"));
    let sizes = parse_sizes()?;

    println!("security: 80-bit (demo)");
    println!("sizes: {:?}", sizes);

    for size in sizes {
        run_size(&manifest_dir, &workdir, size)?;
    }

    Ok(())
}

fn run_size(manifest_dir: &Path, workdir: &Path, size: usize) -> Result<(), Box<dyn Error>> {
    let circuit = manifest_dir.join(format!("tests/circuits/sha256_{size}b.circom"));
    let size_workdir = workdir.join(format!("sha256_{size}b"));
    let message = reference_message(size);
    let expected_digest = Sha256::digest(&message);

    println!("size_bytes: {size}");

    let compile_start = Instant::now();
    let artifacts = generate_circom_artifacts(manifest_dir, &circuit, &size_workdir, size)?;
    println!("compile_and_build_ms: {}", compile_start.elapsed().as_millis());

    let input_path = size_workdir.join(format!("sha256_{size}b_input.json"));
    write_input_json(&input_path, &message)?;

    let witness_start = Instant::now();
    run(Command::new(
        size_workdir
            .join(format!("sha256_{size}b_cpp"))
            .join(format!("sha256_{size}b")),
    )
    .arg(&input_path)
    .arg(&artifacts.wtns))?;
    println!("witness_ms: {}", witness_start.elapsed().as_millis());

    let import_start = Instant::now();
    let (shape, witness, public_inputs) = import_paths(&artifacts.r1cs, &artifacts.wtns)?;
    println!("import_ms: {}", import_start.elapsed().as_millis());

    let actual_digest_bits = public_digest_bits(&public_inputs)?;
    let expected_digest_bits = expected_digest_bits(&expected_digest);
    if actual_digest_bits != expected_digest_bits {
        return Err(format!("digest mismatch for {size}B circuit").into());
    }

    let blocks = (size + 8) / 64 + 1;
    println!(
        "shape: blocks={} constraints={} constraints_per_block={} vars={} public={}",
        blocks,
        shape.num_cons,
        shape.num_cons / blocks,
        shape.num_vars,
        public_inputs.len()
    );

    let padded_shape = shape
        .pad_regular()
        .map_err(|err| format!("padding failed for {size}B: {err}"))?;
    let spark_layout = compare_spark_layouts(&padded_shape)
        .map_err(|err| format!("Spark layout failed for {size}B: {err}"))?;
    let selected_layout = match spark_layout.decision {
        SparkLayoutDecision::SharedUnion => &spark_layout.joint,
        SparkLayoutDecision::PerMatrix => &spark_layout.per_matrix,
    };
    println!(
        "spark_layout: decision={:?} value_domain={} union_nnz={} max_matrix_nnz_padded={}",
        spark_layout.decision,
        selected_layout.value_domain_size,
        selected_layout.union_nnz,
        selected_layout.max_matrix_nnz_padded
    );

    prove_and_verify(
        "direct_sparse_no_spark",
        MatrixClosingMode::DirectSparse,
        1,
        &shape,
        &witness,
        &public_inputs,
    )?;
    let spark_folding_factor = spark_folding_factor(selected_layout.value_domain_size)?;
    prove_and_verify(
        "spark",
        MatrixClosingMode::Spark,
        spark_folding_factor,
        &shape,
        &witness,
        &public_inputs,
    )?;

    Ok(())
}

fn generate_circom_artifacts(
    manifest_dir: &Path,
    circuit: &Path,
    workdir: &Path,
    size: usize,
) -> Result<ArtifactPaths, Box<dyn Error>> {
    let circom_bin = env::var_os("CIRCOM_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../circom/target/debug/circom"));
    fs::create_dir_all(workdir)?;
    clear_previous_outputs(workdir, size)?;

    run(Command::new(&circom_bin)
        .arg(circuit)
        .arg("--prime")
        .arg("koalabear")
        .arg("--r1cs")
        .arg("--c")
        .arg("-o")
        .arg(workdir))?;

    let cpp_dir = workdir.join(format!("sha256_{size}b_cpp"));
    let mut make = Command::new("make");
    make.arg("-C").arg(&cpp_dir);
    pass_make_override(&mut make, "CC");
    pass_make_override(&mut make, "CFLAGS");
    pass_make_override(&mut make, "CXXFLAGS");
    run(&mut make)?;

    Ok(ArtifactPaths {
        r1cs: workdir.join(format!("sha256_{size}b.r1cs")),
        wtns: workdir.join(format!("sha256_{size}b.wtns")),
    })
}

fn clear_previous_outputs(workdir: &Path, size: usize) -> Result<(), Box<dyn Error>> {
    remove_file_if_exists(&workdir.join(format!("sha256_{size}b.r1cs")))?;
    remove_file_if_exists(&workdir.join(format!("sha256_{size}b.wtns")))?;
    remove_file_if_exists(&workdir.join(format!("sha256_{size}b_input.json")))?;

    let cpp_dir = workdir.join(format!("sha256_{size}b_cpp"));
    match fs::remove_dir_all(&cpp_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", cpp_dir.display()).into()),
    }
}

fn prove_and_verify(
    label: &str,
    matrix_closing: MatrixClosingMode,
    folding_factor: usize,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    let config = protocol_config(matrix_closing, folding_factor);
    let setup_start = Instant::now();
    let (pk, vk) = SpartanProtocol::<KeccakEngine, WhirPcs>::setup_with_config(shape, &config)
        .map_err(|err| format!("{label} setup failed: {err}"))?;
    let setup_ms = setup_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove_with_mode(
        &pk,
        public_inputs,
        witness,
        matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    let prove_ms = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    SpartanProtocol::<KeccakEngine, WhirPcs>::verify_with_mode(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .map_err(|err| format!("{label} verify failed: {err}"))?;
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "mode: {label} folding_factor={folding_factor} setup_ms={setup_ms} prove_ms={prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
}

fn pass_make_override(make: &mut Command, name: &str) {
    if let Some(value) = env::var_os(name) {
        let mut arg = OsString::from(name);
        arg.push("=");
        arg.push(value);
        make.arg(arg);
    }
}

fn run(command: &mut Command) -> Result<(), Box<dyn Error>> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}: {command:?}").into())
    }
}

fn parse_sizes() -> Result<Vec<usize>, Box<dyn Error>> {
    let Some(raw) = env::var_os("SHA256_BENCH_SIZES") else {
        return Ok(DEFAULT_SIZES.to_vec());
    };
    let raw = raw
        .into_string()
        .map_err(|_| "SHA256_BENCH_SIZES must be valid UTF-8")?;
    let mut sizes = Vec::new();
    for part in raw.split(',') {
        let size = part.trim().parse::<usize>()?;
        if !DEFAULT_SIZES.contains(&size) {
            return Err(format!("unsupported SHA benchmark size: {size}").into());
        }
        sizes.push(size);
    }
    if sizes.is_empty() {
        return Err("SHA256_BENCH_SIZES must not be empty".into());
    }
    Ok(sizes)
}

fn reference_message(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect()
}

fn write_input_json(path: &Path, message: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut out = String::from("{\"in\":[");
    for (i, bit) in message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
        .enumerate()
    {
        if i != 0 {
            out.push(',');
        }
        out.push(char::from(b'0' + bit));
    }
    out.push_str("]}\n");
    fs::write(path, out)?;
    Ok(())
}

fn expected_digest_bits(digest: &[u8]) -> Vec<u8> {
    digest
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
        .collect()
}

fn public_digest_bits(public_inputs: &[F]) -> Result<Vec<u8>, Box<dyn Error>> {
    public_inputs
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let bit = x.as_canonical_u32();
            if bit < 2 {
                Ok(bit as u8)
            } else {
                Err(format!("public digest bit {i} is not boolean: {bit}").into())
            }
        })
        .collect()
}

fn remove_file_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", path.display()).into()),
    }
}

fn spark_folding_factor(value_domain_size: usize) -> Result<usize, Box<dyn Error>> {
    let max_spark_num_variables = value_domain_size.ilog2() as usize + 3;
    Ok(max_spark_num_variables
        .checked_add(1)
        .and_then(|v| v.checked_sub(F::TWO_ADICITY))
        .unwrap_or(1)
        .max(1))
}

fn protocol_config(matrix_closing: MatrixClosingMode, folding_factor: usize) -> SpartanSnarkConfig {
    let security = SecurityConfig {
        security_level_bits: 80,
        merkle_security_bits: 80,
        soundness_assumption: SoundnessAssumption::CapacityBound,
    };
    let whir_params = WhirParams {
        pow_bits: 0,
        folding_factor,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 1,
    };
    SpartanSnarkConfig {
        matrix_closing,
        security,
        whir_params,
        pcs_config: WhirPcsConfig {
            num_variables: 0,
            security,
            whir: whir_params,
            sumcheck_strategy: SumcheckStrategy::Svo,
        },
    }
}
