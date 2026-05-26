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
    use alloc::{string::String, vec};
    use core::{
        ffi::{c_int, c_void},
        fmt,
        ptr::NonNull,
    };
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::circom::{validate_satisfaction, CircomAdapterError, KOALABEAR_MODULUS};

    pub const LINKED_WITNESS_GENERATOR_OK: c_int = 0;

    /// Linked witness-generator circuit loader ABI.
    ///
    /// `circuit_ptr/circuit_len` is the linked Circom `.dat` payload. Return
    /// an opaque non-null circuit handle on success, or null on failure after
    /// optionally writing a UTF-8, nul-terminated error message to `error_msg`.
    pub type LinkedWitnessLoadCircuitFn = unsafe extern "C" fn(
        circuit_ptr: *const u8,
        circuit_len: usize,
        error_msg: *mut u8,
        error_msg_len: usize,
    ) -> *mut c_void;

    /// Linked witness-generator circuit release ABI.
    pub type LinkedWitnessFreeCircuitFn = unsafe extern "C" fn(circuit: *mut c_void);

    /// Linked witness-generator ABI.
    ///
    /// `circuit` is the opaque handle returned by `LinkedWitnessLoadCircuitFn`.
    /// `input_ptr/input_len` is an application-defined binary input buffer. The
    /// generator writes exactly `witness_len` private/internal witness values
    /// and `public_inputs_len` public values, all as canonical KoalaBear `u32`
    /// limbs. Public values must be ordered as Circom exposes them:
    /// `public_outputs || public_inputs`.
    ///
    /// Return `LINKED_WITNESS_GENERATOR_OK` on success. On failure, return a
    /// non-zero code and optionally write a UTF-8, nul-terminated error message
    /// into `error_msg`.
    pub type LinkedWitnessGeneratorFn = unsafe extern "C" fn(
        circuit: *mut c_void,
        input_ptr: *const u8,
        input_len: usize,
        witness_ptr: *mut u32,
        witness_len: usize,
        public_inputs_ptr: *mut u32,
        public_inputs_len: usize,
        error_msg: *mut u8,
        error_msg_len: usize,
    ) -> c_int;

    /// Linked native witness generator handle.
    pub struct PoseidonWitnessGenerator {
        name: &'static str,
        circuit: NonNull<c_void>,
        generate: LinkedWitnessGeneratorFn,
        free: LinkedWitnessFreeCircuitFn,
    }

    // The generated witness function allocates a fresh Circom_CalcWit per call.
    // The shared circuit handle is read-only after loading.
    unsafe impl Send for PoseidonWitnessGenerator {}
    unsafe impl Sync for PoseidonWitnessGenerator {}

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PoseidonWitnessGeneratorError {
        CircuitLoadFailed {
            name: &'static str,
            message: String,
        },
        GeneratorFailed {
            name: &'static str,
            code: c_int,
            message: String,
        },
        InvalidFieldElement {
            value: u32,
        },
        Circom(CircomAdapterError),
        Protocol(SpartanWhirError),
    }

    impl fmt::Debug for PoseidonWitnessGenerator {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PoseidonWitnessGenerator")
                .field("name", &self.name)
                .finish_non_exhaustive()
        }
    }

    impl fmt::Display for PoseidonWitnessGeneratorError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::CircuitLoadFailed { name, message } => {
                    write!(
                        f,
                        "linked witness generator {name} failed to load circuit: {message}"
                    )
                }
                Self::GeneratorFailed {
                    name,
                    code,
                    message,
                } => write!(
                    f,
                    "linked witness generator {name} failed with code {code}: {message}"
                ),
                Self::InvalidFieldElement { value } => {
                    write!(
                        f,
                        "linked witness generator returned non-canonical field element {value}"
                    )
                }
                Self::Circom(error) => write!(f, "Circom witness import failed: {error}"),
                Self::Protocol(error) => write!(f, "Poseidon proof failed: {error:?}"),
            }
        }
    }

    impl std::error::Error for PoseidonWitnessGeneratorError {}

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
        pub fn linked(
            name: &'static str,
            circuit_data: &[u8],
            load: LinkedWitnessLoadCircuitFn,
            generate: LinkedWitnessGeneratorFn,
            free: LinkedWitnessFreeCircuitFn,
        ) -> Result<Self, PoseidonWitnessGeneratorError> {
            let mut error_msg = vec![0u8; 512];
            let circuit = unsafe {
                load(
                    circuit_data.as_ptr(),
                    circuit_data.len(),
                    error_msg.as_mut_ptr(),
                    error_msg.len(),
                )
            };
            let circuit = NonNull::new(circuit).ok_or_else(|| {
                PoseidonWitnessGeneratorError::CircuitLoadFailed {
                    name,
                    message: error_message(&error_msg),
                }
            })?;
            Ok(Self {
                name,
                circuit,
                generate,
                free,
            })
        }

        pub const fn name(&self) -> &'static str {
            self.name
        }

        pub fn generate_witness(
            &self,
            input: impl AsRef<[u8]>,
            num_vars: usize,
            num_io: usize,
        ) -> Result<(R1csWitness<F>, Vec<F>), PoseidonWitnessGeneratorError> {
            let input = input.as_ref();
            let mut raw_witness = vec![0u32; num_vars];
            let mut raw_public_inputs = vec![0u32; num_io];
            let mut error_msg = vec![0u8; 512];
            let code = unsafe {
                (self.generate)(
                    self.circuit.as_ptr(),
                    input.as_ptr(),
                    input.len(),
                    raw_witness.as_mut_ptr(),
                    raw_witness.len(),
                    raw_public_inputs.as_mut_ptr(),
                    raw_public_inputs.len(),
                    error_msg.as_mut_ptr(),
                    error_msg.len(),
                )
            };
            if code != LINKED_WITNESS_GENERATOR_OK {
                return Err(PoseidonWitnessGeneratorError::GeneratorFailed {
                    name: self.name,
                    code,
                    message: error_message(&error_msg),
                });
            }

            let public_inputs = raw_public_inputs
                .into_iter()
                .map(canonical_field)
                .collect::<Result<Vec<_>, _>>()?;
            let witness = R1csWitness {
                w: raw_witness
                    .into_iter()
                    .map(canonical_field)
                    .collect::<Result<Vec<_>, _>>()?,
            };
            Ok((witness, public_inputs))
        }
    }

    impl Drop for PoseidonWitnessGenerator {
        fn drop(&mut self) {
            unsafe {
                (self.free)(self.circuit.as_ptr());
            }
        }
    }

    fn canonical_field(value: u32) -> Result<F, PoseidonWitnessGeneratorError> {
        if value >= KOALABEAR_MODULUS {
            return Err(PoseidonWitnessGeneratorError::InvalidFieldElement { value });
        }
        Ok(F::from_u32(value))
    }

    fn error_message(buffer: &[u8]) -> String {
        let len = buffer
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(buffer.len());
        String::from_utf8_lossy(&buffer[..len]).into_owned()
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
            let (witness, public_inputs) =
                generator.generate_witness(input, self.num_vars_unpadded, self.num_io)?;
            validate_satisfaction(&self.shape_canonical, &witness, &public_inputs)?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }
    }
}

#[cfg(feature = "circom")]
pub use witness_generator::{
    LinkedWitnessFreeCircuitFn, LinkedWitnessGeneratorFn, LinkedWitnessLoadCircuitFn,
    PoseidonWitnessGenerator, PoseidonWitnessGeneratorError, LINKED_WITNESS_GENERATOR_OK,
};
