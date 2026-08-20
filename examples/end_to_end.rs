use std::{
    env,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    process,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use spartan_whir::{
    import_r1cs_path, import_witness_path, recommended_quintic_zk_whir_params, CircomR1cs,
    MatrixClosingMode, PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkSetupConfig,
    PoseidonZkVerifyingKey, QuinticExtension, SecurityConfig, SoundnessAssumption, DEFAULT_ZK_ELL,
    DEFAULT_ZK_MASK_LOG_INV_RATE,
};

type ProvingKey = PoseidonZkProvingKey<QuinticExtension>;
type VerifyingKey = PoseidonZkVerifyingKey<QuinticExtension>;
type Proof = PoseidonZkProof<QuinticExtension>;

#[derive(Debug)]
struct ProtocolError(String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProtocolError {}

#[derive(Serialize, Deserialize)]
struct ProvingArtifact {
    circuit: CircomR1cs,
    key: ProvingKey,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| usage());
    let paths = args.map(PathBuf::from).collect::<Vec<_>>();

    match command.to_str() {
        Some("setup") if paths.len() == 3 => setup(&paths[0], &paths[1], &paths[2]),
        Some("prove") if paths.len() == 3 => prove(&paths[0], &paths[1], &paths[2]),
        Some("verify") if paths.len() == 2 => verify(&paths[0], &paths[1]),
        _ => usage(),
    }
}

fn setup(
    r1cs_path: &Path,
    proving_key_path: &Path,
    verifying_key_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let circuit = import_r1cs_path(r1cs_path)?;
    let num_variables = circuit.shape.num_vars.next_power_of_two().ilog2() as usize;
    let config = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: 116,
            merkle_security_bits: 116,
            soundness_assumption: SoundnessAssumption::JohnsonBound,
        },
        whir_params: recommended_quintic_zk_whir_params(num_variables),
        spark_whir_params: None,
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    };
    let (key, verifying_key) =
        ProvingKey::setup(circuit.shape.clone(), config).map_err(protocol_error)?;

    write_artifact(proving_key_path, &ProvingArtifact { circuit, key })?;
    write_artifact(verifying_key_path, &verifying_key)?;
    println!("wrote proving key: {}", proving_key_path.display());
    println!("wrote verifying key: {}", verifying_key_path.display());
    Ok(())
}

fn prove(
    proving_key_path: &Path,
    witness_path: &Path,
    proof_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut artifact: ProvingArtifact = read_artifact(proving_key_path)?;
    artifact.key.prepare_for_proving().map_err(protocol_error)?;
    let (witness, public_inputs) = import_witness_path(&artifact.circuit.shape, witness_path)?;
    let proof = artifact
        .key
        .prove(witness, public_inputs)
        .map_err(protocol_error)?;

    write_artifact(proof_path, &proof)?;
    println!("wrote proof: {}", proof_path.display());
    Ok(())
}

fn verify(verifying_key_path: &Path, proof_path: &Path) -> Result<(), Box<dyn Error>> {
    let verifying_key: VerifyingKey = read_artifact(verifying_key_path)?;
    let proof: Proof = read_artifact(proof_path)?;
    verifying_key.verify(&proof).map_err(protocol_error)?;
    println!("proof verified");
    Ok(())
}

fn write_artifact(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, bincode::serialize(value)?)?;
    Ok(())
}

fn read_artifact<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    Ok(bincode::deserialize(&fs::read(path)?)?)
}

fn protocol_error(error: spartan_whir::SpartanWhirError) -> ProtocolError {
    ProtocolError(error.to_string())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  end_to_end setup <circuit.r1cs> <proving-key.bin> <verifying-key.bin>\n  end_to_end prove <proving-key.bin> <witness.wtns> <proof.bin>\n  end_to_end verify <verifying-key.bin> <proof.bin>"
    );
    process::exit(2);
}
