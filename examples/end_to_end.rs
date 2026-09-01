use std::{
    env,
    error::Error,
    fmt, fs,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process,
};

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use spartan_whir::{
    engine::F, import_r1cs_path, import_witness_path, recommended_quintic_zk_whir_params,
    CircomR1cs, MatrixClosingMode, PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkSetupConfig,
    PoseidonZkVerifyingKey, QuinticExtension, SecurityConfig, SoundnessAssumption, DEFAULT_ZK_ELL,
    DEFAULT_ZK_MASK_LOG_INV_RATE,
};

type ProvingKey = PoseidonZkProvingKey<QuinticExtension>;
type VerifyingKey = PoseidonZkVerifyingKey<QuinticExtension>;
type Proof = PoseidonZkProof<QuinticExtension>;
type PublicInputs = Vec<F>;

const MAX_PROVING_KEY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_VERIFYING_KEY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PUBLIC_INPUT_BYTES: u64 = 16 * 1024 * 1024;

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
        Some("prove") if paths.len() == 4 => prove(&paths[0], &paths[1], &paths[2], &paths[3]),
        Some("verify") if paths.len() == 3 => verify(&paths[0], &paths[1], &paths[2]),
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
    public_inputs_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut artifact: ProvingArtifact = read_artifact(proving_key_path, MAX_PROVING_KEY_BYTES)?;
    artifact.key.prepare_for_proving().map_err(protocol_error)?;
    let (witness, public_inputs) = import_witness_path(&artifact.circuit.shape, witness_path)?;
    let proof = artifact
        .key
        .prove(witness, public_inputs)
        .map_err(protocol_error)?;

    write_artifact(proof_path, &proof)?;
    write_artifact(public_inputs_path, &proof.instance.public_inputs)?;
    println!("wrote proof: {}", proof_path.display());
    println!("wrote public inputs: {}", public_inputs_path.display());
    Ok(())
}

fn verify(
    verifying_key_path: &Path,
    public_inputs_path: &Path,
    proof_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let verifying_key: VerifyingKey = read_artifact(verifying_key_path, MAX_VERIFYING_KEY_BYTES)?;
    let expected_public_inputs: PublicInputs =
        read_artifact(public_inputs_path, MAX_PUBLIC_INPUT_BYTES)?;
    let proof: Proof = read_artifact(proof_path, MAX_PROOF_BYTES)?;
    verifying_key
        .verify(&expected_public_inputs, &proof)
        .map_err(protocol_error)?;
    println!("proof verified");
    Ok(())
}

fn write_artifact(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, bincode::serialize(value)?)?;
    Ok(())
}

fn read_artifact<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T, Box<dyn Error>> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len > max_bytes {
        return Err(Box::new(ProtocolError(format!(
            "artifact {} is {file_len} bytes; limit is {max_bytes} bytes",
            path.display()
        ))));
    }

    let mut reader = BufReader::new(file);
    decode_artifact(&mut reader, max_bytes, path)
}

fn decode_artifact<T: DeserializeOwned>(
    mut reader: impl Read,
    max_bytes: u64,
    path: &Path,
) -> Result<T, Box<dyn Error>> {
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(max_bytes)
        .deserialize_from(&mut reader)?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(Box::new(ProtocolError(format!(
            "artifact {} contains trailing bytes",
            path.display()
        ))));
    }
    Ok(value)
}

fn protocol_error(error: spartan_whir::SpartanWhirError) -> ProtocolError {
    ProtocolError(error.to_string())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  end_to_end setup <circuit.r1cs> <proving-key.bin> <verifying-key.bin>\n  end_to_end prove <proving-key.bin> <witness.wtns> <proof.bin> <public-inputs.bin>\n  end_to_end verify <verifying-key.bin> <expected-public-inputs.bin> <proof.bin>"
    );
    process::exit(2);
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn artifact_decoder_accepts_fixed_integer_encoding() {
        let expected = vec![1u64, 2, 3];
        let bytes = bincode::serialize(&expected).expect("artifact serializes");
        let decoded: Vec<u64> = decode_artifact(
            Cursor::new(bytes.clone()),
            bytes.len() as u64,
            Path::new("test.bin"),
        )
        .expect("artifact decodes");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn artifact_decoder_rejects_trailing_bytes() {
        let mut bytes = bincode::serialize(&7u64).expect("artifact serializes");
        bytes.push(0);
        assert!(decode_artifact::<u64>(Cursor::new(bytes), 64, Path::new("test.bin")).is_err());
    }

    #[test]
    fn artifact_decoder_rejects_oversized_vector_before_allocation() {
        let encoded_vec_len = u64::MAX.to_le_bytes();
        assert!(decode_artifact::<Vec<u8>>(
            Cursor::new(encoded_vec_len),
            64,
            Path::new("test.bin")
        )
        .is_err());
    }
}
