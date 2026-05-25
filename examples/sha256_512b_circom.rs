use std::{
    env,
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use p3_field::PrimeField32;
use sha2::{Digest, Sha256};
use spartan_whir::{
    circom::import_paths, compare_spark_layouts, engine::F, KeccakQuarticEngine as KeccakEngine,
    MatrixClosingMode, R1csShape, R1csWitness, SecurityConfig, SoundnessAssumption,
    SparkLayoutDecision, SpartanProtocol, SpartanSnarkConfig, SumcheckStrategy, WhirParams,
    WhirPcs, WhirPcsConfig,
};

const INPUT_BYTES: usize = 512;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let circuit = manifest_dir.join("tests/circuits/sha256_512b.circom");
    let workdir = env::var_os("SHA256_512B_WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("spartan-whir-sha256-512b-example"));

    let (r1cs_path, wtns_path) = match (
        env::var_os("SHA256_512B_R1CS"),
        env::var_os("SHA256_512B_WTNS"),
    ) {
        (Some(r1cs), Some(wtns)) => (PathBuf::from(r1cs), PathBuf::from(wtns)),
        _ => generate_circom_artifacts(&manifest_dir, &circuit, &workdir)?,
    };

    let message = reference_message();
    let expected_digest = Sha256::digest(message);

    let import_start = Instant::now();
    let (shape, witness, public_inputs) = import_paths(&r1cs_path, &wtns_path)?;
    println!(
        "imported: constraints={} vars={} public={} witness={} elapsed_ms={}",
        shape.num_cons,
        shape.num_vars,
        public_inputs.len(),
        witness.w.len(),
        import_start.elapsed().as_millis()
    );

    let actual_digest_bits = public_digest_bits(&public_inputs)?;
    let expected_digest_bits = expected_digest_bits(&expected_digest);
    if actual_digest_bits != expected_digest_bits {
        return Err("public SHA-256 digest bits do not match the reference digest".into());
    }
    println!("digest: {}", hex(&expected_digest));

    let padded_shape = shape
        .pad_regular()
        .map_err(|err| format!("padding failed: {err}"))?;
    let spark_layout = compare_spark_layouts(&padded_shape)
        .map_err(|err| format!("Spark layout failed: {err}"))?;
    let selected_layout = match spark_layout.decision {
        SparkLayoutDecision::SharedUnion => &spark_layout.joint,
        SparkLayoutDecision::PerMatrix => &spark_layout.per_matrix,
    };
    println!(
        "spark layout: decision={:?} value_domain={} union_nnz={} max_matrix_nnz_padded={}",
        spark_layout.decision,
        selected_layout.value_domain_size,
        selected_layout.union_nnz,
        selected_layout.max_matrix_nnz_padded
    );

    prove_and_verify(
        "direct_sparse_no_spark",
        MatrixClosingMode::DirectSparse,
        &shape,
        &witness,
        &public_inputs,
    )?;
    prove_and_verify(
        "spark",
        MatrixClosingMode::Spark,
        &shape,
        &witness,
        &public_inputs,
    )?;

    Ok(())
}

fn prove_and_verify(
    label: &str,
    matrix_closing: MatrixClosingMode,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    println!("mode: {label}");
    let config = protocol_config(matrix_closing);
    println!(
        "security: {}-bit (demo)",
        config.security.security_level_bits
    );
    let setup_start = Instant::now();
    let (pk, vk) = SpartanProtocol::<KeccakEngine, WhirPcs>::setup_with_config(&shape, &config)
        .map_err(|err| format!("{label} setup failed: {err}"))?;
    println!(
        "setup: canonical_constraints={} canonical_vars={} elapsed_ms={}",
        pk.shape_canonical.num_cons,
        pk.shape_canonical.num_vars,
        setup_start.elapsed().as_millis()
    );

    let prove_start = Instant::now();
    let mut prover_challenger = spartan_whir::keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine, WhirPcs>::prove_with_mode(
        &pk,
        &public_inputs,
        &witness,
        matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    println!("prove: elapsed_ms={}", prove_start.elapsed().as_millis());

    let verify_start = Instant::now();
    let mut verifier_challenger = spartan_whir::keccak_challenger();
    SpartanProtocol::<KeccakEngine, WhirPcs>::verify_with_mode(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .map_err(|err| format!("{label} verify failed: {err}"))?;
    println!("verify: elapsed_ms={}", verify_start.elapsed().as_millis());
    Ok(())
}

fn generate_circom_artifacts(
    manifest_dir: &Path,
    circuit: &Path,
    workdir: &Path,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let circom_bin = env::var_os("CIRCOM_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../circom/target/debug/circom"));
    fs::create_dir_all(workdir)?;
    clear_previous_sha256_outputs(workdir)?;

    run(Command::new(&circom_bin)
        .arg(circuit)
        .arg("--prime")
        .arg("koalabear")
        .arg("--r1cs")
        .arg("--c")
        .arg("-o")
        .arg(workdir))?;

    let cpp_dir = workdir.join("sha256_512b_cpp");
    let mut make = Command::new("make");
    make.arg("-C").arg(&cpp_dir);
    pass_make_override(&mut make, "CC");
    pass_make_override(&mut make, "CFLAGS");
    pass_make_override(&mut make, "CXXFLAGS");
    apply_default_gmp_search_paths(&mut make);
    run(&mut make)?;

    let input_path = workdir.join("sha256_512b_input.json");
    write_input_json(&input_path, reference_message())?;

    let wtns_path = workdir.join("sha256_512b.wtns");
    run(Command::new(cpp_dir.join("sha256_512b"))
        .arg(&input_path)
        .arg(&wtns_path))?;

    Ok((workdir.join("sha256_512b.r1cs"), wtns_path))
}

fn clear_previous_sha256_outputs(workdir: &Path) -> Result<(), Box<dyn Error>> {
    remove_file_if_exists(&workdir.join("sha256_512b.r1cs"))?;
    remove_file_if_exists(&workdir.join("sha256_512b.wtns"))?;
    remove_file_if_exists(&workdir.join("sha256_512b_input.json"))?;

    let cpp_dir = workdir.join("sha256_512b_cpp");
    match fs::remove_dir_all(&cpp_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", cpp_dir.display()).into()),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", path.display()).into()),
    }
}

fn pass_make_override(make: &mut Command, name: &str) {
    if let Some(value) = env::var_os(name) {
        let mut arg = OsString::from(name);
        arg.push("=");
        arg.push(value);
        make.arg(arg);
    }
}

fn apply_default_gmp_search_paths(command: &mut Command) {
    add_env_path_if_exists(
        command,
        "CPATH",
        Path::new("/opt/homebrew/include"),
        "gmp.h",
    );
    add_env_path_if_exists(command, "CPATH", Path::new("/usr/local/include"), "gmp.h");
    add_env_path_if_exists(
        command,
        "LIBRARY_PATH",
        Path::new("/opt/homebrew/lib"),
        "libgmp.dylib",
    );
    add_env_path_if_exists(
        command,
        "LIBRARY_PATH",
        Path::new("/usr/local/lib"),
        "libgmp.dylib",
    );
}

fn add_env_path_if_exists(command: &mut Command, var: &str, dir: &Path, marker: &str) {
    if !dir.join(marker).exists() {
        return;
    }

    let mut paths: Vec<PathBuf> = env::var_os(var)
        .map(|value| env::split_paths(&value).collect())
        .unwrap_or_default();
    if paths.iter().any(|path| path == dir) {
        return;
    }
    paths.push(dir.to_path_buf());
    if let Ok(joined) = env::join_paths(paths) {
        command.env(var, joined);
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

fn reference_message() -> Vec<u8> {
    (0..INPUT_BYTES)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect()
}

fn write_input_json(path: &Path, message: Vec<u8>) -> Result<(), Box<dyn Error>> {
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn protocol_config(matrix_closing: MatrixClosingMode) -> SpartanSnarkConfig {
    let security = SecurityConfig {
        security_level_bits: 80,
        merkle_security_bits: 80,
        soundness_assumption: SoundnessAssumption::CapacityBound,
    };
    // Spark fixed/read tables are wider than the witness commitment for this
    // circuit, so the Spark run needs a larger WHIR folding factor.
    let folding_factor = if matrix_closing == MatrixClosingMode::Spark {
        2
    } else {
        1
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
