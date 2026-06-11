use std::{
    env,
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use libloading::Library;
use p3_field::{PrimeField32, TwoAdicField};
use sha2::{Digest, Sha256};
use spartan_whir::{
    circom::import_r1cs_path, compare_spark_layouts, engine::F, recommended_octic_whir_params,
    KeccakQuarticEngine, MatrixClosingMode, OcticBinExtension, PoseidonOcticEngine,
    PoseidonSpartanProtocol, PoseidonWitnessGenerator, R1csShape, SecurityConfig,
    SoundnessAssumption, SparkLayoutDecision, SparkWhirParams, SpartanProtocol, SpartanSnarkConfig,
    SumcheckStrategy, WhirFoldingSchedule, WhirParams, WhirPcs, WhirPcsConfig,
};
use spartan_whir::{
    protocol::{fixed_audit_column_count, fixed_value_column_bits, read_column_bits},
    spark::spark_col_memory_size,
};

const DEFAULT_SIZES: &[usize] = &[128, 256, 512, 1024, 2048];
const POSEIDON_DIRECT_SCHEDULE: &str = "octic_constant_pow0_ff8_lir1_rsv8";
const POSEIDON_DIRECT_FOLDING_FACTOR: usize = 8;
const POSEIDON_DIRECT_STARTING_LOG_INV_RATE: usize = 1;
const POSEIDON_DIRECT_RS_REDUCTION_FACTOR: usize = 8;
const POSEIDON_SECURITY_BITS: u32 = 128;

#[derive(Debug)]
struct ArtifactPaths {
    r1cs: PathBuf,
    linked_library: PathBuf,
    circuit_data: Vec<u8>,
    run_name: String,
}

struct LoadedWitnessGenerator {
    generator: PoseidonWitnessGenerator,
    _library: Library,
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

    println!("security: {POSEIDON_SECURITY_BITS}-bit JohnsonBound");
    println!("poseidon_direct_schedule: {POSEIDON_DIRECT_SCHEDULE}");
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

    let import_start = Instant::now();
    let circom = import_r1cs_path(&artifacts.r1cs)?;
    let shape = circom.shape;
    let input_binary = input_binary(&message);
    let loaded_generator = load_linked_witness_generator(&artifacts)?;
    let import_elapsed = import_start.elapsed();
    println!("shape_import_ms: {}", import_elapsed.as_millis());
    spartan_whir::profiling::record_profile_phase("circom_shape_import", import_elapsed);

    let (_validation_witness, validation_public_inputs) = loaded_generator
        .generator
        .generate_witness(&input_binary, shape.num_vars, shape.num_io)?;
    let actual_digest_bits = public_digest_bits(&validation_public_inputs)?;
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
        validation_public_inputs.len()
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
    let direct_config = protocol_config(
        MatrixClosingMode::DirectSparse,
        poseidon_direct_whir_params(),
        None,
    );
    let spark_config = {
        let spark_folding_factor = spark_folding_factor(selected_layout.value_domain_size)?;
        protocol_config(
            MatrixClosingMode::Spark,
            legacy_spark_whir_params(spark_folding_factor),
            None,
        )
    };
    let spark_independent_config =
        independent_spark_protocol_config(&padded_shape, selected_layout.value_domain_size)?;

    for sample in 0..repeats {
        if repeats > 1 {
            println!("sample: {}", sample + 1);
        }
        for &engine in engines {
            for &mode in modes {
                match mode {
                    BenchMode::Direct => prove_and_verify(
                        engine,
                        "direct_sparse_octic_constant_pow0_ff8_lir1_rsv8",
                        &direct_config,
                        &shape,
                        &loaded_generator.generator,
                        &input_binary,
                    )?,
                    BenchMode::Spark => prove_and_verify(
                        engine,
                        "spark",
                        &spark_config,
                        &shape,
                        &loaded_generator.generator,
                        &input_binary,
                    )?,
                    BenchMode::SparkIndependent => prove_and_verify(
                        engine,
                        "spark_independent_whir_schedules",
                        &spark_independent_config,
                        &shape,
                        &loaded_generator.generator,
                        &input_binary,
                    )?,
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
    let linked_library = workdir.join(dynamic_library_name(size));
    build_linked_witness_library(&cpp_dir, size, &linked_library)?;
    let circuit_data = fs::read(cpp_dir.join(format!("sha256_{size}b.dat")))?;

    Ok(ArtifactPaths {
        r1cs: workdir.join(format!("sha256_{size}b.r1cs")),
        linked_library,
        circuit_data,
        run_name: format!("sha256_{size}b"),
    })
}

fn clear_previous_outputs(workdir: &Path, size: usize) -> Result<(), Box<dyn Error>> {
    remove_file_if_exists(&workdir.join(format!("sha256_{size}b.r1cs")))?;
    remove_file_if_exists(&workdir.join(dynamic_library_name(size)))?;

    let cpp_dir = workdir.join(format!("sha256_{size}b_cpp"));
    match fs::remove_dir_all(&cpp_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", cpp_dir.display()).into()),
    }
}

fn build_linked_witness_library(
    cpp_dir: &Path,
    size: usize,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    let cxx = env::var_os("CXX").unwrap_or_else(|| OsString::from("c++"));
    let mut command = Command::new(cxx);
    command
        .arg("-std=c++11")
        .arg("-O3")
        .arg("-fPIC")
        .arg("-fvisibility=hidden")
        .arg("-UNDEBUG")
        .arg("-DCIRCOM_LINKED_WITNESS_ONLY")
        .arg("-I")
        .arg(cpp_dir)
        .arg(cpp_dir.join("calcwit.cpp"))
        .arg(cpp_dir.join("fr.cpp"))
        .arg(cpp_dir.join("main.cpp"))
        .arg(cpp_dir.join(format!("sha256_{size}b.cpp")));
    add_include_path_if_exists(&mut command, Path::new("/opt/homebrew/include"), "gmp.h");
    add_include_path_if_exists(&mut command, Path::new("/usr/local/include"), "gmp.h");
    match env::consts::OS {
        "macos" | "ios" => {
            command.arg("-dynamiclib").arg(format!(
                "-Wl,-install_name,@rpath/{}",
                output.file_name().unwrap().to_str().unwrap()
            ));
        }
        _ => {
            command.arg("-shared");
        }
    }
    run(command.arg("-o").arg(output))
}

fn add_include_path_if_exists(command: &mut Command, dir: &Path, marker: &str) {
    if dir.join(marker).exists() {
        command.arg("-I").arg(dir);
    }
}

fn load_linked_witness_generator(
    artifacts: &ArtifactPaths,
) -> Result<LoadedWitnessGenerator, Box<dyn Error>> {
    let library = unsafe { Library::new(&artifacts.linked_library)? };
    let mut load_symbol = format!("{}_load_circuit", artifacts.run_name).into_bytes();
    load_symbol.push(0);
    let mut generate_symbol = format!("{}_linked_witness", artifacts.run_name).into_bytes();
    generate_symbol.push(0);
    let mut free_symbol = format!("{}_free_circuit", artifacts.run_name).into_bytes();
    free_symbol.push(0);
    let load = unsafe { *library.get::<spartan_whir::LinkedWitnessLoadCircuitFn>(&load_symbol)? };
    let generate =
        unsafe { *library.get::<spartan_whir::LinkedWitnessGeneratorFn>(&generate_symbol)? };
    let free = unsafe { *library.get::<spartan_whir::LinkedWitnessFreeCircuitFn>(&free_symbol)? };
    let generator = PoseidonWitnessGenerator::linked(
        "sha256_circom_bench",
        &artifacts.circuit_data,
        load,
        generate,
        free,
    )?;
    Ok(LoadedWitnessGenerator {
        generator,
        _library: library,
    })
}

fn dynamic_library_name(size: usize) -> String {
    format!(
        "{}sha256_{size}b_witness.{}",
        env::consts::DLL_PREFIX,
        env::consts::DLL_EXTENSION
    )
}

fn prove_and_verify(
    engine: BenchEngine,
    label: &str,
    config: &SpartanSnarkConfig,
    shape: &R1csShape<F>,
    generator: &PoseidonWitnessGenerator,
    input_binary: &[u8],
) -> Result<(), Box<dyn Error>> {
    match engine {
        BenchEngine::Poseidon => {
            prove_and_verify_poseidon(label, config, shape, generator, input_binary)
        }
        BenchEngine::PoseidonPlonky3 => {
            prove_and_verify_poseidon_plonky3(label, config, shape, generator, input_binary)
        }
        BenchEngine::Keccak => {
            prove_and_verify_keccak(label, config, shape, generator, input_binary)
        }
    }
}

fn prove_and_verify_poseidon_plonky3(
    label: &str,
    config: &SpartanSnarkConfig,
    shape: &R1csShape<F>,
    generator: &PoseidonWitnessGenerator,
    input_binary: &[u8],
) -> Result<(), Box<dyn Error>> {
    type Protocol = PoseidonSpartanProtocol<OcticBinExtension>;

    let _profile_context =
        spartan_whir::profiling::set_profile_context("poseidon-plonky3-whir", label);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) = Protocol::setup_with_config(shape, config)
        .map_err(|err| format!("{label} Poseidon Plonky3 setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let witness_and_prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("witness_and_prove");
    let (witness, public_inputs) =
        generator.generate_witness(input_binary, shape.num_vars, shape.num_io)?;
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = Protocol::prove_with_mode(
        &pk,
        &public_inputs,
        &witness,
        config.matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} Poseidon Plonky3 prove failed: {err}"))?;
    drop(_prove_profile);
    let witness_and_prove_ms = witness_and_prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let _verify_profile = spartan_whir::profiling::profile_scope("verify");
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    Protocol::verify_with_mode(&vk, &instance, &proof, &mut verifier_challenger)
        .map_err(|err| format!("{label} Poseidon Plonky3 verify failed: {err}"))?;
    drop(_verify_profile);
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "engine: poseidon-plonky3-whir mode: {label} setup_ms={setup_ms} witness_and_prove_ms={witness_and_prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
}

fn prove_and_verify_poseidon(
    label: &str,
    config: &SpartanSnarkConfig,
    shape: &R1csShape<F>,
    generator: &PoseidonWitnessGenerator,
    input_binary: &[u8],
) -> Result<(), Box<dyn Error>> {
    let _profile_context = spartan_whir::profiling::set_profile_context("poseidon", label);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) =
        SpartanProtocol::<PoseidonOcticEngine, WhirPcs>::setup_with_config(shape, config)
            .map_err(|err| format!("{label} setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let witness_and_prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("witness_and_prove");
    let (witness, public_inputs) =
        generator.generate_witness(input_binary, shape.num_vars, shape.num_io)?;
    let mut prover_challenger = spartan_whir::poseidon_challenger();
    let (instance, proof) = SpartanProtocol::<PoseidonOcticEngine, WhirPcs>::prove_with_mode(
        &pk,
        &public_inputs,
        &witness,
        config.matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    drop(_prove_profile);
    let witness_and_prove_ms = witness_and_prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    let _verify_profile = spartan_whir::profiling::profile_scope("verify");
    let mut verifier_challenger = spartan_whir::poseidon_challenger();
    SpartanProtocol::<PoseidonOcticEngine, WhirPcs>::verify_with_mode(
        &vk,
        &instance,
        &proof,
        &mut verifier_challenger,
    )
    .map_err(|err| format!("{label} verify failed: {err}"))?;
    drop(_verify_profile);
    let verify_ms = verify_start.elapsed().as_millis();

    println!(
        "engine: poseidon mode: {label} setup_ms={setup_ms} witness_and_prove_ms={witness_and_prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
}

fn prove_and_verify_keccak(
    label: &str,
    config: &SpartanSnarkConfig,
    shape: &R1csShape<F>,
    generator: &PoseidonWitnessGenerator,
    input_binary: &[u8],
) -> Result<(), Box<dyn Error>> {
    let _profile_context = spartan_whir::profiling::set_profile_context("keccak", label);
    let setup_start = Instant::now();
    let _setup_profile = spartan_whir::profiling::profile_scope("setup");
    let (pk, vk) =
        SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::setup_with_config(shape, config)
            .map_err(|err| format!("{label} setup failed: {err}"))?;
    drop(_setup_profile);
    let setup_ms = setup_start.elapsed().as_millis();

    let witness_and_prove_start = Instant::now();
    let _prove_profile = spartan_whir::profiling::profile_scope("witness_and_prove");
    let (witness, public_inputs) =
        generator.generate_witness(input_binary, shape.num_vars, shape.num_io)?;
    let mut prover_challenger = spartan_whir::keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakQuarticEngine, WhirPcs>::prove_with_mode(
        &pk,
        &public_inputs,
        &witness,
        config.matrix_closing,
        &mut prover_challenger,
    )
    .map_err(|err| format!("{label} prove failed: {err}"))?;
    drop(_prove_profile);
    let witness_and_prove_ms = witness_and_prove_start.elapsed().as_millis();

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
        "engine: keccak mode: {label} setup_ms={setup_ms} witness_and_prove_ms={witness_and_prove_ms} verify_ms={verify_ms}"
    );
    Ok(())
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
    SparkIndependent,
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
            "spark-independent" | "spark_independent" | "spark-opt" => {
                modes.push(BenchMode::SparkIndependent)
            }
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

fn input_binary(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() * 8 * core::mem::size_of::<u32>());
    for bit in message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| u32::from((byte >> bit) & 1)))
    {
        out.extend_from_slice(&bit.to_le_bytes());
    }
    out
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

fn protocol_config(
    matrix_closing: MatrixClosingMode,
    whir_params: WhirParams,
    spark_whir_params: Option<SparkWhirParams>,
) -> SpartanSnarkConfig {
    let security = SecurityConfig {
        security_level_bits: POSEIDON_SECURITY_BITS,
        merkle_security_bits: POSEIDON_SECURITY_BITS,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    SpartanSnarkConfig {
        matrix_closing,
        security,
        whir_params: whir_params.clone(),
        pcs_config: WhirPcsConfig {
            num_variables: 0,
            security,
            whir: whir_params,
            sumcheck_strategy: SumcheckStrategy::Svo,
        },
        spark_whir_params,
    }
}

fn poseidon_direct_whir_params() -> WhirParams {
    WhirParams {
        pow_bits: 0,
        folding_factor: POSEIDON_DIRECT_FOLDING_FACTOR,
        starting_log_inv_rate: POSEIDON_DIRECT_STARTING_LOG_INV_RATE,
        rs_domain_initial_reduction_factor: POSEIDON_DIRECT_RS_REDUCTION_FACTOR,
        ..WhirParams::default()
    }
}

fn legacy_spark_whir_params(folding_factor: usize) -> WhirParams {
    WhirParams {
        pow_bits: 0,
        folding_factor,
        starting_log_inv_rate: POSEIDON_DIRECT_STARTING_LOG_INV_RATE,
        rs_domain_initial_reduction_factor: 1,
        ..WhirParams::default()
    }
}

fn independent_spark_protocol_config(
    padded_shape: &R1csShape<F>,
    value_domain_size: usize,
) -> Result<SpartanSnarkConfig, Box<dyn Error>> {
    let witness_vars = log2_power_of_two(padded_shape.num_vars)?;
    let value_vars = log2_power_of_two(value_domain_size)?;
    let col_memory_size =
        spark_col_memory_size(padded_shape).map_err(|err| format!("Spark layout failed: {err}"))?;
    let audit_memory_size = padded_shape
        .num_cons
        .max(col_memory_size)
        .checked_next_power_of_two()
        .ok_or("audit memory size overflow")?;
    let fixed_audit_domain_size = audit_memory_size
        .checked_mul(fixed_audit_column_count())
        .ok_or("fixed audit domain size overflow")?;
    let fixed_value_vars = value_vars + fixed_value_column_bits();
    let fixed_audit_vars = log2_power_of_two(fixed_audit_domain_size)?;
    let read_vars = value_vars + read_column_bits::<OcticBinExtension>();

    println!(
        "spark_independent_vars: witness={witness_vars} fixed_value={fixed_value_vars} fixed_audit={fixed_audit_vars} read={read_vars}"
    );

    let witness = recommended_octic_whir_params(witness_vars);
    let fixed_value = recommended_octic_whir_params(fixed_value_vars);
    let fixed_audit = recommended_octic_whir_params(fixed_audit_vars);
    let read = recommended_octic_whir_params(read_vars);

    println!(
        "spark_independent_schedules: witness={} fixed_value={} fixed_audit={} read={}",
        whir_schedule_label(&witness),
        whir_schedule_label(&fixed_value),
        whir_schedule_label(&fixed_audit),
        whir_schedule_label(&read)
    );

    Ok(protocol_config(
        MatrixClosingMode::Spark,
        witness,
        Some(SparkWhirParams {
            fixed_value,
            fixed_audit,
            read,
        }),
    ))
}

fn whir_schedule_label(params: &WhirParams) -> String {
    match params.effective_folding_schedule() {
        WhirFoldingSchedule::Constant(factor) => format!(
            "octic_constant_pow{}_ff{factor}_lir{}_rsv{}",
            params.pow_bits,
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
        WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => format!(
            "octic_cfsr_pow{}_ff{first}_rest{rest}_lir{}_rsv{}",
            params.pow_bits,
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
        WhirFoldingSchedule::PerRound(factors) => format!(
            "octic_per_round_pow{}_factors{:?}_lir{}_rsv{}",
            params.pow_bits,
            factors,
            params.starting_log_inv_rate,
            params.rs_domain_initial_reduction_factor
        ),
    }
}

fn log2_power_of_two(value: usize) -> Result<usize, Box<dyn Error>> {
    if value == 0 || !value.is_power_of_two() {
        return Err(format!("expected power-of-two value, got {value}").into());
    }
    Ok(value.ilog2() as usize)
}
