use alloc::vec::Vec;
use p3_challenger::CanObserve;
use serde::{Deserialize, Serialize};

use crate::{
    engine::{poseidon_challenger, ExtField, PoseidonChallenger, PoseidonEngine, F},
    MatrixClosingMode, MlePcs, Plonky3WhirPcs, R1csInstance, R1csShape, R1csWitness,
    SpartanProofKind, SpartanProtocol, SpartanSnarkConfig, SpartanWhirError,
};

pub type PoseidonSetupConfig = SpartanSnarkConfig;
pub type PoseidonProofKind<Ext> = SpartanProofKind<PoseidonEngine<Ext>, Plonky3WhirPcs>;

/// Poseidon Spartan proof plus its public instance.
///
/// Serialize this value with any serde-compatible encoding chosen by the
/// deployment or benchmark layer.
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "Ext: ExtField, R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>: Serialize, PoseidonProofKind<Ext>: Serialize",
    deserialize = "Ext: ExtField, R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>: Deserialize<'de>, PoseidonProofKind<Ext>: Deserialize<'de>"
))]
pub struct PoseidonProof<Ext: ExtField> {
    pub instance: R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
    pub proof: PoseidonProofKind<Ext>,
}

impl<Ext: ExtField> PoseidonProof<Ext> {
    pub fn new(
        instance: R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
        proof: PoseidonProofKind<Ext>,
    ) -> Self {
        Self { instance, proof }
    }

    pub fn closing_mode(&self) -> MatrixClosingMode {
        self.proof.kind()
    }

    #[deprecated(since = "0.1.0", note = "use closing_mode")]
    pub fn kind(&self) -> MatrixClosingMode {
        self.closing_mode()
    }
}

pub fn setup_poseidon<Ext>(
    shape: R1csShape<F>,
    config: PoseidonSetupConfig,
) -> Result<
    (
        crate::PoseidonProvingKey<Ext>,
        crate::PoseidonVerifyingKey<Ext>,
    ),
    SpartanWhirError,
>
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
{
    SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::setup_with_config(&shape, &config)
}

impl<Ext> crate::PoseidonProvingKey<Ext>
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
{
    /// Set up a Poseidon Spartan proving/verifying key pair.
    ///
    /// Spark proving keys include fixed-table prover data, so their serialized
    /// form is expected to be materially larger than direct-mode keys.
    pub fn setup(
        shape: R1csShape<F>,
        config: PoseidonSetupConfig,
    ) -> Result<
        (
            crate::PoseidonProvingKey<Ext>,
            crate::PoseidonVerifyingKey<Ext>,
        ),
        SpartanWhirError,
    > {
        setup_poseidon::<Ext>(shape, config)
    }

    pub fn prove(
        &self,
        witness: R1csWitness<F>,
        public_inputs: Vec<F>,
    ) -> Result<PoseidonProof<Ext>, SpartanWhirError> {
        let mut challenger = poseidon_challenger();
        let (instance, proof) =
            SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::prove_with_mode(
                self,
                &public_inputs,
                &witness,
                self.matrix_closing,
                &mut challenger,
            )?;
        Ok(PoseidonProof::new(instance, proof))
    }
}

impl<Ext> crate::PoseidonVerifyingKey<Ext>
where
    Ext: ExtField,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
{
    pub fn verify(&self, proof: &PoseidonProof<Ext>) -> Result<(), SpartanWhirError> {
        let mut challenger = poseidon_challenger();
        SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::verify_with_mode(
            self,
            &proof.instance,
            &proof.proof,
            &mut challenger,
        )
    }
}

#[cfg(feature = "circom")]
mod witness_generator {
    use alloc::string::{String, ToString};
    use core::fmt;
    use std::{
        fs,
        io::{ErrorKind, Read},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use tempfile::TempDir;

    use super::*;
    use crate::circom::{import_witness_bytes_with_layout, CircomAdapterError};

    const DEFAULT_TIMEOUT_MILLIS: u64 = 30_000;
    const DEFAULT_MAX_WITNESS_BYTES: u64 = 1 << 30;

    /// Native Circom witness generator handle.
    ///
    /// The executable is invoked as:
    ///
    /// ```text
    /// executable input.json output.wtns
    /// ```
    ///
    /// `input.json` is written into a private temporary directory and
    /// `output.wtns` is read back after the process exits successfully.
    /// Proving from this generator blocks the calling thread until the
    /// generator exits or the configured timeout elapses.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PoseidonWitnessGenerator {
        executable: String,
        timeout_millis: u64,
        max_witness_bytes: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PoseidonWitnessGeneratorError {
        Io { kind: ErrorKind, message: String },
        Timeout { timeout_millis: u64 },
        WitnessTooLarge { max_bytes: u64, actual_bytes: u64 },
        ProcessFailed { status: Option<i32> },
        Circom(CircomAdapterError),
        Protocol(SpartanWhirError),
    }

    impl fmt::Display for PoseidonWitnessGeneratorError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Io { kind, message } => write!(f, "I/O error ({kind:?}): {message}"),
                Self::Timeout { timeout_millis } => {
                    write!(f, "witness generator timed out after {timeout_millis} ms")
                }
                Self::WitnessTooLarge {
                    max_bytes,
                    actual_bytes,
                } => write!(
                    f,
                    "witness output is too large: max {max_bytes} bytes, got {actual_bytes}"
                ),
                Self::ProcessFailed { status } => {
                    write!(f, "witness generator failed with status {status:?}")
                }
                Self::Circom(error) => write!(f, "Circom witness import failed: {error}"),
                Self::Protocol(error) => write!(f, "Poseidon proof failed: {error:?}"),
            }
        }
    }

    impl std::error::Error for PoseidonWitnessGeneratorError {}

    impl From<std::io::Error> for PoseidonWitnessGeneratorError {
        fn from(value: std::io::Error) -> Self {
            Self::Io {
                kind: value.kind(),
                message: value.to_string(),
            }
        }
    }

    impl From<CircomAdapterError> for PoseidonWitnessGeneratorError {
        fn from(value: CircomAdapterError) -> Self {
            Self::Circom(value)
        }
    }

    impl From<SpartanWhirError> for PoseidonWitnessGeneratorError {
        fn from(value: SpartanWhirError) -> Self {
            Self::Protocol(value)
        }
    }

    impl PoseidonWitnessGenerator {
        pub fn native_executable(path: impl Into<PathBuf>) -> Self {
            let path = path.into();
            Self {
                executable: path.to_string_lossy().into_owned(),
                timeout_millis: DEFAULT_TIMEOUT_MILLIS,
                max_witness_bytes: DEFAULT_MAX_WITNESS_BYTES,
            }
        }

        pub fn executable(&self) -> &Path {
            Path::new(&self.executable)
        }

        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout_millis = timeout.as_millis().try_into().unwrap_or(u64::MAX);
            self
        }

        pub fn with_max_witness_bytes(mut self, max_witness_bytes: u64) -> Self {
            self.max_witness_bytes = max_witness_bytes;
            self
        }

        fn generate_witness(
            &self,
            input: impl AsRef<[u8]>,
        ) -> Result<Vec<u8>, PoseidonWitnessGeneratorError> {
            let tempdir = TempDir::new()?;
            let input_path = tempdir.path().join("input.json");
            let witness_path = tempdir.path().join("witness.wtns");

            fs::write(&input_path, input)?;
            let mut child = Command::new(&self.executable)
                .arg(&input_path)
                .arg(&witness_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let timeout = Duration::from_millis(self.timeout_millis);
            let started = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => {}
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error.into());
                    }
                }
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(PoseidonWitnessGeneratorError::Timeout {
                        timeout_millis: self.timeout_millis,
                    });
                }
                thread::sleep(Duration::from_millis(1));
            };
            if !status.success() {
                return Err(PoseidonWitnessGeneratorError::ProcessFailed {
                    status: status.code(),
                });
            }

            let actual_bytes = fs::metadata(&witness_path)?.len();
            if actual_bytes > self.max_witness_bytes {
                return Err(PoseidonWitnessGeneratorError::WitnessTooLarge {
                    max_bytes: self.max_witness_bytes,
                    actual_bytes,
                });
            }
            let capacity: usize = actual_bytes.try_into().map_err(|_| {
                PoseidonWitnessGeneratorError::WitnessTooLarge {
                    max_bytes: self.max_witness_bytes,
                    actual_bytes,
                }
            })?;
            let mut witness = Vec::with_capacity(capacity);
            fs::File::open(&witness_path)?.read_to_end(&mut witness)?;
            Ok(witness)
        }
    }

    impl<Ext> crate::PoseidonProvingKey<Ext>
    where
        Ext: ExtField,
        PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
    {
        pub fn prove_from_witness_generator(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<PoseidonProof<Ext>, PoseidonWitnessGeneratorError> {
            let witness_bytes = generator.generate_witness(input)?;
            let (witness, public_inputs) = import_witness_bytes_with_layout(
                &self.shape_canonical,
                self.num_vars_unpadded,
                self.num_io,
                &witness_bytes,
            )?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }
    }
}

#[cfg(feature = "circom")]
pub use witness_generator::{PoseidonWitnessGenerator, PoseidonWitnessGeneratorError};
