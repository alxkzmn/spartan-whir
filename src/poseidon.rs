use alloc::vec::Vec;
use core::marker::PhantomData;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use rand::{
    distr::{Distribution, StandardUniform},
    CryptoRng, Rng,
};
use serde::{Deserialize, Serialize};

use crate::{
    engine::{poseidon_challenger, ExtField, PoseidonChallenger, PoseidonEngine, F},
    plonky3_whir_pcs::{build_poseidon_full_zk_pcs, PoseidonCommitment},
    protocol::{
        combined_application_mask_shape, validate_canonical_verifying_shape,
        PoseidonZkSpartanProtocol,
    },
    r1cs::{DirectBindLayout, DirectMultiplyLayout},
    DomainSeparator, MatrixClosingMode, MlePcs, Plonky3WhirPcs, R1csInstance, R1csShape,
    R1csWitness, SecurityConfig, SpartanProofKind, SpartanProtocol, SpartanSnarkConfig,
    SpartanWhirError, WhirParams, ZkSpartanProof, ZkWhirPcsConfig,
};

pub type PoseidonSetupConfig = SpartanSnarkConfig;
pub type PoseidonProofKind<Ext> = SpartanProofKind<PoseidonEngine<Ext>, Plonky3WhirPcs>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonZkSetupConfig {
    pub matrix_closing: MatrixClosingMode,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub ell_zk: usize,
    pub mask_log_inv_rate: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct PoseidonZkProvingKey<Ext: ExtField> {
    pub(crate) shape_canonical: R1csShape<F>,
    pub(crate) num_cons_unpadded: usize,
    pub(crate) num_vars_unpadded: usize,
    pub(crate) num_io: usize,
    pub(crate) pcs_config: ZkWhirPcsConfig,
    pub(crate) domain_separator: DomainSeparator,
    #[serde(skip)]
    pub(crate) direct_bind_layout: Option<DirectBindLayout<F>>,
    #[serde(skip)]
    pub(crate) direct_multiply_layout: Option<DirectMultiplyLayout>,
    marker: PhantomData<Ext>,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct PoseidonZkVerifyingKey<Ext: ExtField> {
    pub(crate) shape_canonical: R1csShape<F>,
    pub(crate) num_cons_unpadded: usize,
    pub(crate) num_vars_unpadded: usize,
    pub(crate) num_io: usize,
    pub(crate) pcs_config: ZkWhirPcsConfig,
    pub(crate) domain_separator: DomainSeparator,
    marker: PhantomData<Ext>,
}

impl<Ext: ExtField> PoseidonZkProvingKey<Ext> {
    pub fn prepare_for_proving(&mut self) -> Result<(), SpartanWhirError> {
        self.direct_bind_layout = Some(self.shape_canonical.direct_bind_layout()?);
        self.direct_multiply_layout = Some(self.shape_canonical.direct_multiply_layout()?);
        Ok(())
    }
}

impl<Ext: ExtField> PoseidonZkVerifyingKey<Ext> {
    pub(crate) fn validate(&self) -> Result<(), SpartanWhirError> {
        validate_canonical_verifying_shape(
            &self.shape_canonical,
            self.num_cons_unpadded,
            self.num_vars_unpadded,
            self.num_io,
        )?;
        self.pcs_config.validate()?;

        let num_outer_rounds = self.shape_canonical.num_cons.ilog2() as usize;
        if num_outer_rounds == 0
            || self.pcs_config.base.num_variables != self.shape_canonical.num_vars.ilog2() as usize
        {
            return Err(SpartanWhirError::invalid_config());
        }
        let expected_domain = DomainSeparator::new_full_zk(
            &self.shape_canonical,
            &self.pcs_config.base.security,
            &self.pcs_config.base.whir,
        );
        if self.domain_separator != expected_domain {
            return Err(SpartanWhirError::invalid_config());
        }

        Ok(())
    }
}

/// Poseidon Spartan proof plus its public instance.
///
/// Serialize this value with any serde-compatible encoding chosen by the
/// deployment or benchmark layer. This is the no-ZK Spartan IOP with plain
/// WHIR. Use [`PoseidonZkProof`] when the application requires zero knowledge.
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "Ext: ExtField, R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>: Serialize, PoseidonProofKind<Ext>: Serialize",
    deserialize = "Ext: ExtField, R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>: Deserialize<'de>, PoseidonProofKind<Ext>: Deserialize<'de>"
))]
pub struct PoseidonProof<Ext: ExtField>
where
    StandardUniform: Distribution<Ext>,
{
    pub instance: R1csInstance<F, <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>,
    pub proof: PoseidonProofKind<Ext>,
}

/// Full witness-hiding DirectSparse Spartan-WHIR proof plus its public instance.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "Ext: ExtField, ZkSpartanProof<Ext>: Serialize",
    deserialize = "Ext: ExtField, ZkSpartanProof<Ext>: Deserialize<'de>"
))]
pub struct PoseidonZkProof<Ext: ExtField>
where
    StandardUniform: Distribution<Ext>,
{
    pub instance: R1csInstance<F, PoseidonCommitment>,
    pub proof: ZkSpartanProof<Ext>,
}

impl<Ext: ExtField> PoseidonProof<Ext>
where
    StandardUniform: Distribution<Ext>,
{
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
    StandardUniform: Distribution<Ext>,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::setup_with_config(&shape, &config)
}

pub fn setup_poseidon_zk<Ext>(
    shape: R1csShape<F>,
    config: PoseidonZkSetupConfig,
) -> Result<(PoseidonZkProvingKey<Ext>, PoseidonZkVerifyingKey<Ext>), SpartanWhirError>
where
    Ext: ExtField,
    StandardUniform: Distribution<Ext>,
{
    if config.matrix_closing != MatrixClosingMode::DirectSparse {
        return Err(SpartanWhirError::UnsupportedFullZkMatrixClosing(
            config.matrix_closing,
        ));
    }
    config.security.validate()?;
    shape.validate()?;

    let shape_canonical = shape.pad_regular()?;
    let num_variables = shape_canonical.num_vars.ilog2() as usize;
    let num_outer_rounds = shape_canonical.num_cons.ilog2() as usize;
    if num_outer_rounds == 0 {
        return Err(SpartanWhirError::invalid_config());
    }
    let pcs_config = ZkWhirPcsConfig {
        base: crate::WhirPcsConfig {
            num_variables,
            security: config.security,
            whir: config.whir_params,
        },
        ell_zk: config.ell_zk,
        mask_log_inv_rate: config.mask_log_inv_rate,
    };
    let (_, [inner_shape, outer_shape, _]) =
        build_poseidon_full_zk_pcs::<Ext>(&pcs_config, num_outer_rounds, num_variables + 1)?;
    combined_application_mask_shape(inner_shape, outer_shape)?;
    let domain_separator = DomainSeparator::new_full_zk(
        &shape_canonical,
        &pcs_config.base.security,
        &pcs_config.base.whir,
    );
    let mut pk = PoseidonZkProvingKey {
        shape_canonical: shape_canonical.clone(),
        num_cons_unpadded: shape.num_cons,
        num_vars_unpadded: shape.num_vars,
        num_io: shape.num_io,
        pcs_config: pcs_config.clone(),
        domain_separator: domain_separator.clone(),
        direct_bind_layout: None,
        direct_multiply_layout: None,
        marker: PhantomData,
    };
    pk.prepare_for_proving()?;
    let vk = PoseidonZkVerifyingKey {
        shape_canonical,
        num_cons_unpadded: shape.num_cons,
        num_vars_unpadded: shape.num_vars,
        num_io: shape.num_io,
        pcs_config,
        domain_separator,
        marker: PhantomData,
    };
    Ok((pk, vk))
}

impl<Ext> crate::PoseidonProvingKey<Ext>
where
    Ext: ExtField,
    StandardUniform: Distribution<Ext>,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
{
    /// Set up a Poseidon Spartan proving/verifying key pair.
    ///
    /// Spark proving keys include fixed-table prover data and cached Spark
    /// preprocessing tables, so their serialized form is expected to be
    /// materially larger than direct-mode keys.
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
    StandardUniform: Distribution<Ext>,
    PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>
        + CanSampleUniformBits<F>
        + FieldChallenger<F>
        + GrindingChallenger<Witness = F>,
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

impl<Ext> PoseidonZkProvingKey<Ext>
where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<PoseidonCommitment>,
{
    pub fn setup(
        shape: R1csShape<F>,
        config: PoseidonZkSetupConfig,
    ) -> Result<(Self, PoseidonZkVerifyingKey<Ext>), SpartanWhirError> {
        setup_poseidon_zk(shape, config)
    }

    pub fn prove(
        &self,
        witness: R1csWitness<F>,
        public_inputs: Vec<F>,
    ) -> Result<PoseidonZkProof<Ext>, SpartanWhirError> {
        let mut challenger = poseidon_challenger();
        let (instance, proof) = PoseidonZkSpartanProtocol::<Ext>::prove(
            self,
            &public_inputs,
            &witness,
            &mut challenger,
        )?;
        Ok(PoseidonZkProof { instance, proof })
    }

    pub fn prove_with_rng<R>(
        &self,
        witness: R1csWitness<F>,
        public_inputs: Vec<F>,
        rng: &mut R,
    ) -> Result<PoseidonZkProof<Ext>, SpartanWhirError>
    where
        R: Rng + CryptoRng,
    {
        let mut challenger = poseidon_challenger();
        let (instance, proof) = PoseidonZkSpartanProtocol::<Ext>::prove_with_rng(
            self,
            &public_inputs,
            &witness,
            &mut challenger,
            rng,
        )?;
        Ok(PoseidonZkProof { instance, proof })
    }
}

impl<Ext> PoseidonZkVerifyingKey<Ext>
where
    Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
    StandardUniform: Distribution<Ext> + Distribution<F>,
    PoseidonChallenger: CanObserve<PoseidonCommitment>,
{
    pub fn verify(&self, proof: &PoseidonZkProof<Ext>) -> Result<(), SpartanWhirError> {
        let mut challenger = poseidon_challenger();
        PoseidonZkSpartanProtocol::<Ext>::verify(
            self,
            &proof.instance,
            &proof.proof,
            &mut challenger,
        )
    }
}

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
        /// Construct a witness generator from linked native callbacks.
        ///
        /// # Safety
        ///
        /// The callbacks must implement the documented ABI, must remain loaded
        /// until this value is dropped, and must use the returned circuit handle
        /// only through the supplied `generate` and `free` functions. `load` must
        /// not retain `circuit_data`, `generate` must respect every pointer/length
        /// pair, and `free` must accept the handle exactly once.
        pub unsafe fn linked(
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
        StandardUniform: Distribution<Ext>,
        PoseidonChallenger: CanObserve<<Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::Commitment>
            + CanSampleUniformBits<F>
            + FieldChallenger<F>
            + GrindingChallenger<Witness = F>,
    {
        fn witness_from_generator(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<(R1csWitness<F>, Vec<F>), PoseidonWitnessGeneratorError> {
            generator.generate_witness(input, self.num_vars_unpadded, self.num_io)
        }

        /// Generate a witness and prove it without a full R1CS satisfaction check.
        ///
        /// The prover evaluates the R1CS matrices as part of the Spartan
        /// protocol. Use `prove_from_witness_generator_checked` when the caller
        /// wants an explicit R1CS satisfaction check.
        pub fn prove_from_witness_generator(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<PoseidonProof<Ext>, PoseidonWitnessGeneratorError> {
            let (witness, public_inputs) = self.witness_from_generator(generator, input)?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }

        /// Generate a witness, validate R1CS satisfaction, then prove it.
        ///
        /// This is intended for import tests and debugging native witness
        /// generators. It performs a full matrix-vector pass before proving and
        /// should not be used as the default benchmark or production prove path.
        pub fn prove_from_witness_generator_checked(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<PoseidonProof<Ext>, PoseidonWitnessGeneratorError> {
            let (witness, public_inputs) = self.witness_from_generator(generator, input)?;
            validate_satisfaction(&self.shape_canonical, &witness, &public_inputs)?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }
    }

    impl<Ext> PoseidonZkProvingKey<Ext>
    where
        Ext: ExtField + Serialize + for<'de> Deserialize<'de>,
        StandardUniform: Distribution<Ext> + Distribution<F>,
        PoseidonChallenger: CanObserve<PoseidonCommitment>,
    {
        fn witness_from_generator(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<(R1csWitness<F>, Vec<F>), PoseidonWitnessGeneratorError> {
            generator.generate_witness(input, self.num_vars_unpadded, self.num_io)
        }

        pub fn prove_from_witness_generator(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<PoseidonZkProof<Ext>, PoseidonWitnessGeneratorError> {
            let (witness, public_inputs) = self.witness_from_generator(generator, input)?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }

        pub fn prove_from_witness_generator_checked(
            &self,
            generator: &PoseidonWitnessGenerator,
            input: impl AsRef<[u8]>,
        ) -> Result<PoseidonZkProof<Ext>, PoseidonWitnessGeneratorError> {
            let (witness, public_inputs) = self.witness_from_generator(generator, input)?;
            validate_satisfaction(&self.shape_canonical, &witness, &public_inputs)?;
            self.prove(witness, public_inputs).map_err(Into::into)
        }
    }
}

pub use witness_generator::{
    LinkedWitnessFreeCircuitFn, LinkedWitnessGeneratorFn, LinkedWitnessLoadCircuitFn,
    PoseidonWitnessGenerator, PoseidonWitnessGeneratorError, LINKED_WITNESS_GENERATOR_OK,
};
