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
    circom::import_paths, compare_spark_layouts, engine::F, KeccakQuarticEngine, MatrixClosingMode,
    PoseidonQuarticEngine, PoseidonSpartanProtocol, QuarticBinExtension, R1csShape, R1csWitness,
    SecurityConfig, SoundnessAssumption, SparkLayoutDecision, SpartanProtocol, SpartanSnarkConfig,
    SumcheckStrategy, WhirParams, WhirPcs, WhirPcsConfig,
};

const DEFAULT_SIZES: &[usize] = &[128, 256, 512, 1024, 2048];

#[derive(Debug)]
struct ArtifactPaths {
    r1cs: PathBuf,
    wtns: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    init_profile_tracing();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workdir = env::var_os("SHA256_BENCH_WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("spartan-whir-sha256-bench"));
    let sizes = parse_sizes()?;
    let engines = parse_engines()?;
    let modes = parse_modes()?;
    let repeats = parse_repeats()?;

    println!("security: 80-bit (demo)");
    println!("sizes: {:?}", sizes);
    println!("engines: {:?}", engines);
    println!("modes: {:?}", modes);
    println!("repeats: {repeats}");
    if spartan_whir::profiling::profile_enabled() {
        println!("profile: enabled");
    }

    for size in sizes {
        run_size(&manifest_dir, &workdir, size, &engines, &modes, repeats)?;
    }

    Ok(())
}

fn init_profile_tracing() {
    if !spartan_whir::profiling::profile_enabled() {
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .with_level(false)
        .try_init();
}

fn run_size(
    manifest_dir: &Path,
    workdir: &Path,
    size: usize,
    engines: &[BenchEngine],
    modes: &[BenchMode],
    repeats: usize,
) -> Result<(), Box<dyn Error>> {
    let profile_mode = format!("sha256_{size}b");
    let _profile_context = spartan_whir::profiling::set_profile_context("bench", &profile_mode);
    let circuit = manifest_dir.join(format!("tests/circuits/sha256_{size}b.circom"));
    let size_workdir = workdir.join(format!("sha256_{size}b"));
    let message = reference_message(size);
    let expected_digest = Sha256::digest(&message);

    println!("size_bytes: {size}");

    let compile_start = Instant::now();
    let artifacts = generate_circom_artifacts(manifest_dir, &circuit, &size_workdir, size)?;
    let compile_elapsed = compile_start.elapsed();
    println!("compile_and_build_ms: {}", compile_elapsed.as_millis());
    spartan_whir::profiling::record_profile_phase("circom_compile_build", compile_elapsed);

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
    let witness_elapsed = witness_start.elapsed();
    println!("witness_ms: {}", witness_elapsed.as_millis());
    spartan_whir::profiling::record_profile_phase("witness_generation", witness_elapsed);

    let import_start = Instant::now();
    let (shape, witness, public_inputs) = import_paths(&artifacts.r1cs, &artifacts.wtns)?;
    let import_elapsed = import_start.elapsed();
    println!("import_ms: {}", import_elapsed.as_millis());
    spartan_whir::profiling::record_profile_phase("circom_import", import_elapsed);

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

    for sample in 0..repeats {
        if repeats > 1 {
            println!("sample: {}", sample + 1);
        }
        for &engine in engines {
            for &mode in modes {
                match mode {
                    BenchMode::Direct => prove_and_verify(
                        engine,
                        "direct_sparse_no_spark",
                        MatrixClosingMode::DirectSparse,
                        1,
                        &shape,
                        &witness,
                        &public_inputs,
                    )?,
                    BenchMode::Spark => {
                        let spark_folding_factor =
                            spark_folding_factor(selected_layout.value_domain_size)?;
                        prove_and_verify(
                            engine,
                            "spark",
                            MatrixClosingMode::Spark,
                            spark_folding_factor,
                            &shape,
                            &witness,
                            &public_inputs,
                        )?;
                    }
                }
            }
        }
    }

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
    apply_default_gmp_search_paths(&mut make);
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
    engine: BenchEngine,
    label: &str,
    matrix_closing: MatrixClosingMode,
    folding_factor: usize,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    match engine {
        BenchEngine::Poseidon => prove_and_verify_poseidon(
            label,
            matrix_closing,
            folding_factor,
            shape,
            witness,
            public_inputs,
        ),
        BenchEngine::PoseidonPlonky3 => prove_and_verify_poseidon_plonky3(
            label,
            matrix_closing,
            folding_factor,
            shape,
            witness,
            public_inputs,
        ),
        BenchEngine::Keccak => prove_and_verify_keccak(
            label,
            matrix_closing,
            folding_factor,
            shape,
            witness,
            public_inputs,
        ),
    }
}

fn prove_and_verify_poseidon_plonky3(
    label: &str,
    matrix_closing: MatrixClosingMode,
    folding_factor: usize,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    type Protocol = PoseidonSpartanProtocol<QuarticBinExtension>;

    let _profile_context =
        spartan_whir::profiling::set_profile_context("poseidon-plonky3-whir", label);
    let config = protocol_config(matrix_closing, folding_factor);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) = Protocol::setup_with_config(shape, &config)
        .map_err(|err| format!("{label} Poseidon Plonky3 setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("prove");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = Protocol::prove_with_mode(
        &pk,
        public_inputs,
        witness,
        matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} Poseidon Plonky3 prove failed: {err}"))?;
    drop(_prove_profile);
    let prove_ms = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let _verify_profile = spartan_whir::profiling::profile_scope("verify");
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    Protocol::verify_with_mode(&vk, &instance, &proof, &mut verifier_challenger)
        .map_err(|err| format!("{label} Poseidon Plonky3 verify failed: {err}"))?;
    drop(_verify_profile);
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "engine: poseidon-plonky3-whir mode: {label} folding_factor={folding_factor} setup_ms={setup_ms} prove_ms={prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
}

fn prove_and_verify_poseidon(
    label: &str,
    matrix_closing: MatrixClosingMode,
    folding_factor: usize,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    let _profile_context = spartan_whir::profiling::set_profile_context("poseidon", label);
    let config = protocol_config(matrix_closing, folding_factor);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) =
        SpartanProtocol::<PoseidonQuarticEngine, WhirPcs>::setup_with_config(shape, &config)
            .map_err(|err| format!("{label} setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("prove");
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = SpartanProtocol::<PoseidonQuarticEngine, WhirPcs>::prove_with_mode(
        &pk,
        public_inputs,
        witness,
        matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    drop(_prove_profile);
    let prove_ms = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let _verify_profile = spartan_whir::profiling::profile_scope("verify");
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    SpartanProtocol::<PoseidonQuarticEngine, WhirPcs>::verify_with_mode(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .map_err(|err| format!("{label} verify failed: {err}"))?;
    drop(_verify_profile);
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "engine: poseidon mode: {label} folding_factor={folding_factor} setup_ms={setup_ms} prove_ms={prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
}

fn prove_and_verify_keccak(
    label: &str,
    matrix_closing: MatrixClosingMode,
    folding_factor: usize,
    shape: &R1csShape<F>,
    witness: &R1csWitness<F>,
    public_inputs: &[F],
) -> Result<(), Box<dyn Error>> {
    let _profile_context = spartan_whir::profiling::set_profile_context("keccak", label);
    let config = protocol_config(matrix_closing, folding_factor);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) =
        SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::setup_with_config(shape, &config)
            .map_err(|err| format!("{label} setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("prove");
    let mut prover_challenger = spartan_whir::keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::prove_with_mode(
        &pk,
        public_inputs,
        witness,
        matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    drop(_prove_profile);
    let prove_ms = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let _verify_profile = spartan_whir::profiling::profile_scope("verify");
    let mut verifier_challenger = spartan_whir::keccak_challenger();
    SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::verify_with_mode(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .map_err(|err| format!("{label} verify failed: {err}"))?;
    drop(_verify_profile);
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "engine: keccak mode: {label} folding_factor={folding_factor} setup_ms={setup_ms} prove_ms={prove_ms} verify_ms={verify_ms}"
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

#[derive(Debug, Clone, Copy)]
enum BenchEngine {
    PoseidonPlonky3,
    Poseidon,
    Keccak,
}

fn parse_engines() -> Result<Vec<BenchEngine>, Box<dyn Error>> {
    let Some(raw) = env::var_os("SHA256_BENCH_ENGINES") else {
        return Ok(vec![BenchEngine::PoseidonPlonky3]);
    };
    let raw = raw
        .into_string()
        .map_err(|_| "SHA256_BENCH_ENGINES must be valid UTF-8")?;
    let mut engines = Vec::new();
    for part in raw.split(',') {
        match part.trim() {
            "poseidon-plonky3" | "plonky3" | "plonky3-whir" => {
                engines.push(BenchEngine::PoseidonPlonky3)
            }
            "poseidon" => engines.push(BenchEngine::Poseidon),
            "keccak" => engines.push(BenchEngine::Keccak),
            "both" => {
                engines.push(BenchEngine::Keccak);
                engines.push(BenchEngine::Poseidon);
            }
            "poseidon-plonky3-vs-old-poseidon" => {
                engines.push(BenchEngine::PoseidonPlonky3);
                engines.push(BenchEngine::Poseidon);
            }
            "all" => {
                engines.push(BenchEngine::Keccak);
                engines.push(BenchEngine::Poseidon);
                engines.push(BenchEngine::PoseidonPlonky3);
            }
            other => return Err(format!("unsupported SHA benchmark engine: {other}").into()),
        }
    }
    if engines.is_empty() {
        return Err("SHA256_BENCH_ENGINES must not be empty".into());
    }
    Ok(engines)
}

#[derive(Debug, Clone, Copy)]
enum BenchMode {
    Direct,
    Spark,
}

fn parse_modes() -> Result<Vec<BenchMode>, Box<dyn Error>> {
    let Some(raw) = env::var_os("SHA256_BENCH_MODES") else {
        return Ok(vec![BenchMode::Direct, BenchMode::Spark]);
    };
    let raw = raw
        .into_string()
        .map_err(|_| "SHA256_BENCH_MODES must be valid UTF-8")?;
    let mut modes = Vec::new();
    for part in raw.split(',') {
        match part.trim() {
            "direct" | "direct-sparse" | "direct_sparse_no_spark" => modes.push(BenchMode::Direct),
            "spark" => modes.push(BenchMode::Spark),
            "both" | "all" => {
                modes.push(BenchMode::Direct);
                modes.push(BenchMode::Spark);
            }
            other => return Err(format!("unsupported SHA benchmark mode: {other}").into()),
        }
    }
    if modes.is_empty() {
        return Err("SHA256_BENCH_MODES must not be empty".into());
    }
    Ok(modes)
}

fn parse_repeats() -> Result<usize, Box<dyn Error>> {
    let Some(raw) = env::var_os("SHA256_BENCH_REPEATS") else {
        return Ok(1);
    };
    let repeats = raw
        .into_string()
        .map_err(|_| "SHA256_BENCH_REPEATS must be valid UTF-8")?
        .parse::<usize>()?;
    if repeats == 0 {
        return Err("SHA256_BENCH_REPEATS must be greater than zero".into());
    }
    Ok(repeats)
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
