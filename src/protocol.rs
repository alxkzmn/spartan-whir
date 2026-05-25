use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, Hash};

use crate::engine::{ExtField, KeccakEngine, PoseidonEngine, F};
use crate::profiling::profile_scope;
use crate::{
    compute_spark_read_tables, evaluate_mle_table, preprocess_spark_tables, prove_inner,
    prove_outer, prove_spark_batched_memory_products_with_leaf_claims, verify_inner, verify_outer,
    verify_spark_batched_memory_leaf_claims_with_openings,
    verify_spark_batched_memory_product_claims, CommittedPolynomialView, DomainSeparator,
    EqPolynomial, InnerSumcheckProof, MatrixClosingMode, MlePcs, MultilinearPoint, NoopObserver,
    OuterSumcheckProof, PcsStatementBuilder, PointEvalClaim, ProtocolObserver, ProtocolPcs,
    ProtocolStage, R1csInstance, R1csShape, R1csWitness, SecurityConfig,
    SparkBatchedMemoryProductsLeafClaims, SparkBatchedMemoryProductsProof,
    SparkFixedTableOpeningEvals, SparkReadTableOpeningEvals, SparkReadTables, SpartanWhirEngine,
    SpartanWhirError, WhirParams, WhirPcsConfig,
};

pub struct ProvingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub matrix_closing: MatrixClosingMode,
    pub shape_canonical: R1csShape<E::F>,
    pub num_cons_unpadded: usize,
    pub num_vars_unpadded: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub pcs_config: Pcs::Config,
    pub spark_fixed_commitments: Option<SparkFixedCommitments<Pcs::Commitment>>,
    spark_fixed_prover_data: Option<SparkFixedProverData<E, Pcs>>,
    pub domain_separator: DomainSeparator,
    pub observer: Option<NoopObserver>,
    marker: PhantomData<(E, Pcs)>,
}

pub struct VerifyingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub matrix_closing: MatrixClosingMode,
    pub shape_canonical: R1csShape<E::F>,
    pub num_cons_unpadded: usize,
    pub num_vars_unpadded: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub pcs_config: Pcs::Config,
    pub spark_fixed_commitments: Option<SparkFixedCommitments<Pcs::Commitment>>,
    pub domain_separator: DomainSeparator,
    pub observer: Option<NoopObserver>,
    marker: PhantomData<(E, Pcs)>,
}

pub struct SpartanProof<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub outer_sumcheck: OuterSumcheckProof<E::EF>,
    pub outer_claims: (E::EF, E::EF, E::EF),
    pub inner_sumcheck: InnerSumcheckProof<E::EF>,
    pub witness_eval: E::EF,
    pub pcs_proof: Pcs::Proof,
}

pub struct SparkSpartanProof<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub outer_sumcheck: OuterSumcheckProof<E::EF>,
    pub outer_claims: (E::EF, E::EF, E::EF),
    pub inner_sumcheck: InnerSumcheckProof<E::EF>,
    pub witness_eval: E::EF,
    pub spark_products: SparkBatchedMemoryProductsProof<E::EF>,
    pub spark_fixed_openings: SparkFixedOpeningProof<E, Pcs>,
    pub spark_read_openings: SparkReadOpeningProof<E, Pcs>,
    pub pcs_proof: Pcs::Proof,
}

pub struct SparkFixedOpeningProof<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub value_num_variables: usize,
    pub value_column_bits: usize,
    pub audit_num_variables: usize,
    pub audit_column_bits: usize,
    pub value_commitment: Pcs::Commitment,
    pub audit_commitment: Pcs::Commitment,
    pub evals: SparkFixedTableOpeningEvals<E::EF>,
    pub value_proof: Pcs::Proof,
    pub audit_proof: Pcs::Proof,
    marker: PhantomData<E>,
}

pub struct SparkReadOpeningProof<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub num_variables: usize,
    pub column_bits: usize,
    pub commitment: Pcs::Commitment,
    pub erow_low_evals: Vec<E::EF>,
    pub erow_high_evals: Vec<E::EF>,
    pub ecol_low_evals: Vec<E::EF>,
    pub ecol_high_evals: Vec<E::EF>,
    pub erow_ops_evals: Vec<E::EF>,
    pub ecol_ops_evals: Vec<E::EF>,
    pub proof: Pcs::Proof,
    marker: PhantomData<E>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpartanSnarkConfig {
    pub matrix_closing: MatrixClosingMode,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub pcs_config: WhirPcsConfig,
}

pub enum SpartanProofKind<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    Direct(SpartanProof<E, Pcs>),
    Spark(SparkSpartanProof<E, Pcs>),
}

impl<E: SpartanWhirEngine, Pcs: MlePcs<E>> SpartanProofKind<E, Pcs> {
    pub fn kind(&self) -> MatrixClosingMode {
        match self {
            Self::Direct(_) => MatrixClosingMode::DirectSparse,
            Self::Spark(_) => MatrixClosingMode::Spark,
        }
    }
}

struct SparkReadProverData<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    data: Pcs::ProverData,
    marker: PhantomData<E>,
}

struct SparkReadCommitments<C> {
    commitment: C,
}

struct SparkFixedProverData<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    value: Pcs::ProverData,
    audit: Pcs::ProverData,
    marker: PhantomData<E>,
}

impl<E, Pcs> Clone for SparkFixedProverData<E, Pcs>
where
    E: SpartanWhirEngine,
    Pcs: MlePcs<E>,
    Pcs::ProverData: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            audit: self.audit.clone(),
            marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkFixedCommitments<C = [u64; 4]> {
    pub value: C,
    pub audit: C,
}

struct ParsedSparkReadOpenings<E, Pcs>
where
    E: SpartanWhirEngine,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
{
    commitment: Pcs::ParsedCommitment,
}

struct ParsedSparkFixedOpenings<E, Pcs>
where
    E: SpartanWhirEngine,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
{
    value: Pcs::ParsedCommitment,
    audit: Pcs::ParsedCommitment,
}

pub trait SpartanContextEngine: SpartanWhirEngine<F = F>
where
    Self::EF: ExtField,
{
    fn challenger() -> Self::Challenger;

    fn observe_spartan_context(
        challenger: &mut Self::Challenger,
        domain_separator: &DomainSeparator,
        public_inputs: &[F],
    ) -> Result<(), SpartanWhirError>;
}

impl<Ext> SpartanContextEngine for KeccakEngine<Ext>
where
    Ext: ExtField,
{
    fn challenger() -> Self::Challenger {
        crate::engine::keccak_challenger()
    }

    fn observe_spartan_context(
        challenger: &mut Self::Challenger,
        domain_separator: &DomainSeparator,
        public_inputs: &[F],
    ) -> Result<(), SpartanWhirError> {
        let digest_bytes = Keccak256Hash {}.hash_iter(domain_separator.to_bytes());
        let digest_hash: Hash<F, u8, 32> = digest_bytes.into();
        challenger.observe(digest_hash);
        for &input in public_inputs {
            challenger.observe(input);
        }
        Ok(())
    }
}

impl<Ext> SpartanContextEngine for PoseidonEngine<Ext>
where
    Ext: ExtField,
{
    fn challenger() -> Self::Challenger {
        crate::engine::poseidon_challenger()
    }

    fn observe_spartan_context(
        challenger: &mut Self::Challenger,
        domain_separator: &DomainSeparator,
        public_inputs: &[F],
    ) -> Result<(), SpartanWhirError> {
        // TODO: decide whether the Poseidon transcript should first compress
        // the domain separator into field elements instead of absorbing bytes.
        for byte in domain_separator.to_bytes() {
            challenger.observe(F::from_u8(byte));
        }
        for &input in public_inputs {
            challenger.observe(input);
        }
        Ok(())
    }
}

pub struct SpartanProtocol<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    marker: PhantomData<(E, Pcs)>,
}

impl<E, Pcs> SpartanProtocol<E, Pcs>
where
    E: SpartanContextEngine,
    E::EF: ExtField,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    Pcs::ProverData: Clone + CommittedPolynomialView<E::EF>,
    Pcs::Commitment: Clone + PartialEq,
    E::Challenger: FieldChallenger<F>,
{
    pub fn setup(
        shape: &R1csShape<F>,
        security: &SecurityConfig,
        whir_params: &WhirParams,
        pcs_config: &WhirPcsConfig,
    ) -> Result<(ProvingKey<E, Pcs>, VerifyingKey<E, Pcs>), SpartanWhirError> {
        // Defaults to SPARK setup; call `setup_with_config` with
        // `DirectSparse` to skip SPARK preprocessing.
        Self::setup_for_mode(
            shape,
            security,
            whir_params,
            pcs_config,
            MatrixClosingMode::Spark,
        )
    }

    pub fn setup_with_config(
        shape: &R1csShape<F>,
        config: &SpartanSnarkConfig,
    ) -> Result<(ProvingKey<E, Pcs>, VerifyingKey<E, Pcs>), SpartanWhirError> {
        Self::setup_for_mode(
            shape,
            &config.security,
            &config.whir_params,
            &config.pcs_config,
            config.matrix_closing,
        )
    }

    fn setup_for_mode(
        shape: &R1csShape<F>,
        security: &SecurityConfig,
        whir_params: &WhirParams,
        pcs_config: &WhirPcsConfig,
        matrix_closing: MatrixClosingMode,
    ) -> Result<(ProvingKey<E, Pcs>, VerifyingKey<E, Pcs>), SpartanWhirError> {
        let mut observer = NoopObserver;
        observer.on_stage(ProtocolStage::SetupStart);

        security.validate()?;
        shape.validate()?;

        let shape_canonical = shape.pad_regular()?;
        let num_variables = shape_canonical.num_vars.ilog2() as usize;

        let mut canonical_pcs_config = *pcs_config;
        canonical_pcs_config.num_variables = num_variables;
        canonical_pcs_config.security = *security;
        canonical_pcs_config.whir = *whir_params;
        canonical_pcs_config.validate()?;

        let domain_separator = DomainSeparator::new_with_matrix_closing(
            &shape_canonical,
            security,
            whir_params,
            matrix_closing,
        );
        let spark_fixed_setup = match matrix_closing {
            MatrixClosingMode::DirectSparse => None,
            MatrixClosingMode::Spark => {
                let _profile = profile_scope("spark_fixed_setup");
                setup_spark_fixed_commitments::<E, E::EF, Pcs>(
                    &canonical_pcs_config,
                    &shape_canonical,
                )?
            }
        };
        let (spark_fixed_prover_data, spark_fixed_commitments) = match spark_fixed_setup {
            Some((prover_data, commitments)) => (Some(prover_data), Some(commitments)),
            None => (None, None),
        };

        let pk = ProvingKey {
            matrix_closing,
            shape_canonical: shape_canonical.clone(),
            num_cons_unpadded: shape.num_cons,
            num_vars_unpadded: shape.num_vars,
            num_io: shape.num_io,
            security: *security,
            whir_params: *whir_params,
            pcs_config: canonical_pcs_config,
            spark_fixed_commitments: spark_fixed_commitments.clone(),
            spark_fixed_prover_data,
            domain_separator: domain_separator.clone(),
            observer: Some(NoopObserver),
            marker: PhantomData,
        };

        let vk = VerifyingKey {
            matrix_closing,
            shape_canonical,
            num_cons_unpadded: shape.num_cons,
            num_vars_unpadded: shape.num_vars,
            num_io: shape.num_io,
            security: *security,
            whir_params: *whir_params,
            pcs_config: canonical_pcs_config,
            spark_fixed_commitments,
            domain_separator,
            observer: Some(NoopObserver),
            marker: PhantomData,
        };

        observer.on_stage(ProtocolStage::SetupEnd);
        Ok((pk, vk))
    }

    pub fn prove_with_mode(
        pk: &ProvingKey<E, Pcs>,
        public_inputs: &[F],
        witness: &R1csWitness<F>,
        mode: MatrixClosingMode,
        challenger: &mut E::Challenger,
    ) -> Result<
        (
            R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
            SpartanProofKind<E, Pcs>,
        ),
        SpartanWhirError,
    > {
        match mode {
            MatrixClosingMode::DirectSparse => {
                let (instance, proof) = Self::prove(pk, public_inputs, witness, challenger)?;
                Ok((instance, SpartanProofKind::Direct(proof)))
            }
            MatrixClosingMode::Spark => {
                let (instance, proof) = Self::prove_spark(pk, public_inputs, witness, challenger)?;
                Ok((instance, SpartanProofKind::Spark(proof)))
            }
        }
    }

    pub fn verify_with_mode(
        vk: &VerifyingKey<E, Pcs>,
        instance: &R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
        proof: &SpartanProofKind<E, Pcs>,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError> {
        match proof {
            SpartanProofKind::Direct(proof) => Self::verify(vk, instance, proof, challenger),
            SpartanProofKind::Spark(proof) => Self::verify_spark(vk, instance, proof, challenger),
        }
    }

    fn ensure_key_mode(
        actual: MatrixClosingMode,
        expected: MatrixClosingMode,
    ) -> Result<(), SpartanWhirError> {
        if actual != expected {
            return Err(SpartanWhirError::ProofKindMismatch);
        }
        Ok(())
    }

    pub fn prove(
        pk: &ProvingKey<E, Pcs>,
        public_inputs: &[F],
        witness: &R1csWitness<F>,
        challenger: &mut E::Challenger,
    ) -> Result<
        (
            R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
            SpartanProof<E, Pcs>,
        ),
        SpartanWhirError,
    > {
        let mut observer = pk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::ProveStart);
        Self::ensure_key_mode(pk.matrix_closing, MatrixClosingMode::DirectSparse)?;

        if public_inputs.len() != pk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }
        if witness.w.len() != pk.num_vars_unpadded {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        observe_spartan_context::<E, E::EF>(challenger, &pk.domain_separator, public_inputs)?;

        let mut witness_padded = witness.w.clone();
        witness_padded.resize(pk.shape_canonical.num_vars, F::ZERO);
        let witness_mle = {
            let _profile = profile_scope("witness_to_mle");
            pk.shape_canonical.witness_to_mle(&witness_padded)?
        };

        observer.on_stage(ProtocolStage::PcsCommit);
        let (witness_commitment, prover_data) = {
            let _profile = profile_scope("witness_pcs_commit");
            <Pcs as MlePcs<E>>::commit(&pk.pcs_config, &witness_mle, challenger)?
        };
        let instance = R1csInstance {
            public_inputs: public_inputs.to_vec(),
            witness_commitment,
        };

        let z_witness_half = witness_padded;
        let z_public_half = build_public_half(pk.shape_canonical.num_vars, public_inputs);
        let z_full = [z_witness_half.clone(), z_public_half.clone()].concat();
        let z_short = build_matrix_z(&z_witness_half, public_inputs);

        let (az_f, bz_f, cz_f) = {
            let _profile = profile_scope("r1cs_multiply_vec");
            pk.shape_canonical.multiply_vec(&z_short)?
        };
        let az: Vec<E::EF> = az_f.iter().map(|&v| E::EF::from(v)).collect();
        let bz: Vec<E::EF> = bz_f.iter().map(|&v| E::EF::from(v)).collect();
        let cz: Vec<E::EF> = cz_f.iter().map(|&v| E::EF::from(v)).collect();

        let num_rounds_x = pk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec::<E, E::EF>(challenger, num_rounds_x);
        let tau_point = MultilinearPoint(tau.clone());

        let (outer_sumcheck, r_x, outer_claims) = {
            let _profile = profile_scope("outer_sumcheck");
            prove_outer::<F, E::EF, _>(&pk.shape_canonical, &az, &bz, &cz, &tau_point, challenger)?
        };

        challenger.observe_algebra_slice(&[outer_claims.0, outer_claims.1, outer_claims.2]);
        let r = challenger.sample_algebra_element::<E::EF>();
        let claim_inner_joint = outer_claims.0 + r * outer_claims.1 + r * r * outer_claims.2;

        let t_x = EqPolynomial::evals_from_point(&r_x.0);
        let (evals_a, evals_b, evals_c) = pk.shape_canonical.bind_row_vars::<E::EF>(&t_x)?;
        let poly_abc: Vec<E::EF> = evals_a
            .iter()
            .zip(evals_b.iter())
            .zip(evals_c.iter())
            .map(|((&a, &b), &c)| a + r * b + r * r * c)
            .collect();
        let z_lifted: Vec<E::EF> = z_full.iter().map(|&v| E::EF::from(v)).collect();

        let (inner_sumcheck, r_y, eval_z) = {
            let _profile = profile_scope("inner_sumcheck");
            prove_inner::<F, E::EF, _>(
                &pk.shape_canonical,
                claim_inner_joint,
                &poly_abc,
                &z_lifted,
                challenger,
            )?
        };

        let eval_x_table = public_half_as_extension(pk.shape_canonical.num_vars, public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let witness_eval = recover_witness_eval(r_y.0[0], eval_z, eval_x)?;

        let pcs_statement = PcsStatementBuilder::<E>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: witness_eval,
            })
            .finalize()?;

        observer.on_stage(ProtocolStage::PcsOpen);
        let pcs_proof = {
            let _profile = profile_scope("witness_pcs_open");
            <Pcs as MlePcs<E>>::open(&pk.pcs_config, prover_data, &pcs_statement, challenger)?
        };
        observer.on_stage(ProtocolStage::ProveEnd);

        Ok((
            instance,
            SpartanProof {
                outer_sumcheck,
                outer_claims,
                inner_sumcheck,
                witness_eval,
                pcs_proof,
            },
        ))
    }

    pub fn verify(
        vk: &VerifyingKey<E, Pcs>,
        instance: &R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
        proof: &SpartanProof<E, Pcs>,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError> {
        let mut observer = vk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::VerifyStart);
        Self::ensure_key_mode(vk.matrix_closing, MatrixClosingMode::DirectSparse)?;

        if instance.public_inputs.len() != vk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }

        observe_spartan_context::<E, E::EF>(
            challenger,
            &vk.domain_separator,
            &instance.public_inputs,
        )?;

        observer.on_stage(ProtocolStage::PcsVerify);
        let parsed_commitment = <Pcs as ProtocolPcs<E>>::verify_parse_commitment(
            &vk.pcs_config,
            &instance.witness_commitment,
            &proof.pcs_proof,
            challenger,
        )?;

        let num_rounds_x = vk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec::<E, E::EF>(challenger, num_rounds_x);
        let (r_x, final_outer_claim) = verify_outer::<F, E::EF, _>(
            &proof.outer_sumcheck,
            E::EF::ZERO,
            num_rounds_x,
            challenger,
        )?;

        let expected_outer = eq_point_eval(&tau, &r_x.0)
            * (proof.outer_claims.0 * proof.outer_claims.1 - proof.outer_claims.2);
        if final_outer_claim != expected_outer {
            return Err(SpartanWhirError::SumcheckFailed);
        }

        challenger.observe_algebra_slice(&[
            proof.outer_claims.0,
            proof.outer_claims.1,
            proof.outer_claims.2,
        ]);
        let r = challenger.sample_algebra_element::<E::EF>();
        let claim_inner_joint =
            proof.outer_claims.0 + r * proof.outer_claims.1 + r * r * proof.outer_claims.2;

        let num_rounds_y = vk.shape_canonical.num_vars.ilog2() as usize + 1;
        let (r_y, inner_final_claim) = verify_inner::<F, E::EF, _>(
            &proof.inner_sumcheck,
            claim_inner_joint,
            num_rounds_y,
            challenger,
        )?;

        let t_x = EqPolynomial::evals_from_point(&r_x.0);
        let t_y = EqPolynomial::evals_from_point(&r_y.0);
        let (eval_a, eval_b, eval_c) = vk
            .shape_canonical
            .evaluate_with_tables::<E::EF>(&t_x, &t_y)?;

        let eval_x_table =
            public_half_as_extension(vk.shape_canonical.num_vars, &instance.public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let eval_z = (E::EF::ONE - r_y.0[0]) * proof.witness_eval + r_y.0[0] * eval_x;
        let expected_inner = (eval_a + r * eval_b + r * r * eval_c) * eval_z;
        if inner_final_claim != expected_inner {
            return Err(SpartanWhirError::SumcheckFailed);
        }

        let pcs_statement = PcsStatementBuilder::<E>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: proof.witness_eval,
            })
            .finalize()?;

        <Pcs as ProtocolPcs<E>>::verify_finalize(
            &vk.pcs_config,
            &parsed_commitment,
            &pcs_statement,
            &proof.pcs_proof,
            challenger,
        )?;

        observer.on_stage(ProtocolStage::VerifyEnd);
        Ok(())
    }

    pub fn prove_spark(
        pk: &ProvingKey<E, Pcs>,
        public_inputs: &[F],
        witness: &R1csWitness<F>,
        challenger: &mut E::Challenger,
    ) -> Result<
        (
            R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
            SparkSpartanProof<E, Pcs>,
        ),
        SpartanWhirError,
    > {
        let mut observer = pk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::ProveStart);
        Self::ensure_key_mode(pk.matrix_closing, MatrixClosingMode::Spark)?;

        if public_inputs.len() != pk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }
        if witness.w.len() != pk.num_vars_unpadded {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        observe_spartan_context::<E, E::EF>(challenger, &pk.domain_separator, public_inputs)?;

        let mut witness_padded = witness.w.clone();
        witness_padded.resize(pk.shape_canonical.num_vars, F::ZERO);
        let witness_mle = {
            let _profile = profile_scope("witness_to_mle");
            pk.shape_canonical.witness_to_mle(&witness_padded)?
        };

        observer.on_stage(ProtocolStage::PcsCommit);
        let (witness_commitment, prover_data) = {
            let _profile = profile_scope("witness_pcs_commit");
            <Pcs as MlePcs<E>>::commit(&pk.pcs_config, &witness_mle, challenger)?
        };
        let instance = R1csInstance {
            public_inputs: public_inputs.to_vec(),
            witness_commitment,
        };

        let z_witness_half = witness_padded;
        let z_public_half = build_public_half(pk.shape_canonical.num_vars, public_inputs);
        let z_full = [z_witness_half.clone(), z_public_half.clone()].concat();
        let z_short = build_matrix_z(&z_witness_half, public_inputs);

        let (az_f, bz_f, cz_f) = {
            let _profile = profile_scope("r1cs_multiply_vec");
            pk.shape_canonical.multiply_vec(&z_short)?
        };
        let az: Vec<E::EF> = az_f.iter().map(|&v| E::EF::from(v)).collect();
        let bz: Vec<E::EF> = bz_f.iter().map(|&v| E::EF::from(v)).collect();
        let cz: Vec<E::EF> = cz_f.iter().map(|&v| E::EF::from(v)).collect();

        let num_rounds_x = pk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec::<E, E::EF>(challenger, num_rounds_x);
        let tau_point = MultilinearPoint(tau.clone());

        let (outer_sumcheck, r_x, outer_claims) = {
            let _profile = profile_scope("outer_sumcheck");
            prove_outer::<F, E::EF, _>(&pk.shape_canonical, &az, &bz, &cz, &tau_point, challenger)?
        };

        challenger.observe_algebra_slice(&[outer_claims.0, outer_claims.1, outer_claims.2]);
        let r = challenger.sample_algebra_element::<E::EF>();
        let claim_inner_joint = outer_claims.0 + r * outer_claims.1 + r * r * outer_claims.2;

        let t_x = EqPolynomial::evals_from_point(&r_x.0);
        let (evals_a, evals_b, evals_c) = pk.shape_canonical.bind_row_vars::<E::EF>(&t_x)?;
        let poly_abc: Vec<E::EF> = evals_a
            .iter()
            .zip(evals_b.iter())
            .zip(evals_c.iter())
            .map(|((&a, &b), &c)| a + r * b + r * r * c)
            .collect();
        let z_lifted: Vec<E::EF> = z_full.iter().map(|&v| E::EF::from(v)).collect();

        let (inner_sumcheck, r_y, eval_z) = {
            let _profile = profile_scope("inner_sumcheck");
            prove_inner::<F, E::EF, _>(
                &pk.shape_canonical,
                claim_inner_joint,
                &poly_abc,
                &z_lifted,
                challenger,
            )?
        };

        let spark_tables = {
            let _profile = profile_scope("spark_preprocess_tables");
            preprocess_spark_tables(&pk.shape_canonical)?
        };
        let spark_value_pcs_config =
            spark_table_pcs_config(&pk.pcs_config, spark_tables.value_domain_size)?;
        let spark_fixed_value_pcs_config = spark_fixed_value_pcs_config(&spark_value_pcs_config)?;
        let spark_fixed_audit_pcs_config = spark_fixed_audit_pcs_config(
            &pk.pcs_config,
            spark_tables.row_memory_size,
            spark_tables.col_memory_size,
        )?;
        let spark_read_pcs_config = spark_read_pcs_config::<E::EF>(&spark_value_pcs_config)?;
        let fixed_prover_data = pk
            .spark_fixed_prover_data
            .clone()
            .ok_or(SpartanWhirError::InvalidConfig)?;
        let expected_fixed_commitments = pk
            .spark_fixed_commitments
            .clone()
            .ok_or(SpartanWhirError::InvalidConfig)?;
        let fixed_prover_data = {
            let _profile = profile_scope("spark_prepare_fixed_openings");
            prepare_spark_fixed_openings::<E, E::EF, Pcs>(
                &spark_fixed_value_pcs_config,
                &spark_fixed_audit_pcs_config,
                fixed_prover_data,
                challenger,
            )?
        };
        let read_tables = {
            let _profile = profile_scope("spark_compute_read_tables");
            compute_spark_read_tables(&spark_tables, &r_x, &r_y)?
        };
        let (read_prover_data, read_commitments) = {
            let _profile = profile_scope("spark_commit_read_tables");
            commit_spark_read_tables::<E, E::EF, Pcs>(
                &spark_read_pcs_config,
                &read_tables,
                challenger,
            )?
        };
        let (spark_products, product_claims) = {
            let _profile = profile_scope("spark_memory_products");
            prove_spark_batched_memory_products_with_leaf_claims(
                &spark_tables,
                &r_x,
                &r_y,
                challenger,
            )?
        };
        let spark_fixed_openings = {
            let _profile = profile_scope("spark_open_fixed_tables");
            open_spark_fixed_tables::<E, E::EF, Pcs>(
                &spark_fixed_value_pcs_config,
                &spark_fixed_audit_pcs_config,
                fixed_prover_data,
                expected_fixed_commitments,
                &spark_tables,
                &product_claims,
                challenger,
            )?
        };
        let spark_read_openings = {
            let _profile = profile_scope("spark_open_read_tables");
            open_spark_read_tables::<E, E::EF, Pcs>(
                &spark_read_pcs_config,
                read_prover_data,
                read_commitments,
                &product_claims,
                challenger,
            )?
        };

        let eval_x_table = public_half_as_extension(pk.shape_canonical.num_vars, public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let witness_eval = recover_witness_eval(r_y.0[0], eval_z, eval_x)?;

        let pcs_statement = PcsStatementBuilder::<E>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: witness_eval,
            })
            .finalize()?;

        observer.on_stage(ProtocolStage::PcsOpen);
        let pcs_proof = {
            let _profile = profile_scope("witness_pcs_open");
            <Pcs as MlePcs<E>>::open(&pk.pcs_config, prover_data, &pcs_statement, challenger)?
        };
        observer.on_stage(ProtocolStage::ProveEnd);

        Ok((
            instance,
            SparkSpartanProof {
                outer_sumcheck,
                outer_claims,
                inner_sumcheck,
                witness_eval,
                spark_products,
                spark_fixed_openings,
                spark_read_openings,
                pcs_proof,
            },
        ))
    }

    pub fn verify_spark(
        vk: &VerifyingKey<E, Pcs>,
        instance: &R1csInstance<F, <Pcs as MlePcs<E>>::Commitment>,
        proof: &SparkSpartanProof<E, Pcs>,
        challenger: &mut E::Challenger,
    ) -> Result<(), SpartanWhirError> {
        let mut observer = vk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::VerifyStart);
        Self::ensure_key_mode(vk.matrix_closing, MatrixClosingMode::Spark)?;

        if instance.public_inputs.len() != vk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }

        observe_spartan_context::<E, E::EF>(
            challenger,
            &vk.domain_separator,
            &instance.public_inputs,
        )?;

        observer.on_stage(ProtocolStage::PcsVerify);
        let parsed_commitment = <Pcs as ProtocolPcs<E>>::verify_parse_commitment(
            &vk.pcs_config,
            &instance.witness_commitment,
            &proof.pcs_proof,
            challenger,
        )?;

        let num_rounds_x = vk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec::<E, E::EF>(challenger, num_rounds_x);
        let (r_x, final_outer_claim) = verify_outer::<F, E::EF, _>(
            &proof.outer_sumcheck,
            E::EF::ZERO,
            num_rounds_x,
            challenger,
        )?;

        let expected_outer = eq_point_eval(&tau, &r_x.0)
            * (proof.outer_claims.0 * proof.outer_claims.1 - proof.outer_claims.2);
        if final_outer_claim != expected_outer {
            return Err(SpartanWhirError::SumcheckFailed);
        }

        challenger.observe_algebra_slice(&[
            proof.outer_claims.0,
            proof.outer_claims.1,
            proof.outer_claims.2,
        ]);
        let r = challenger.sample_algebra_element::<E::EF>();
        let claim_inner_joint =
            proof.outer_claims.0 + r * proof.outer_claims.1 + r * r * proof.outer_claims.2;

        let num_rounds_y = vk.shape_canonical.num_vars.ilog2() as usize + 1;
        let (r_y, inner_final_claim) = verify_inner::<F, E::EF, _>(
            &proof.inner_sumcheck,
            claim_inner_joint,
            num_rounds_y,
            challenger,
        )?;

        let spark_tables = preprocess_spark_tables(&vk.shape_canonical)?;
        let spark_value_pcs_config =
            spark_table_pcs_config(&vk.pcs_config, spark_tables.value_domain_size)?;
        let spark_fixed_value_pcs_config = spark_fixed_value_pcs_config(&spark_value_pcs_config)?;
        let spark_fixed_audit_pcs_config = spark_fixed_audit_pcs_config(
            &vk.pcs_config,
            spark_tables.row_memory_size,
            spark_tables.col_memory_size,
        )?;
        let spark_read_pcs_config = spark_read_pcs_config::<E::EF>(&spark_value_pcs_config)?;
        let expected_fixed_commitments = vk
            .spark_fixed_commitments
            .clone()
            .ok_or(SpartanWhirError::InvalidConfig)?;
        validate_spark_fixed_commitments::<E, E::EF, Pcs>(
            &proof.spark_fixed_openings,
            &expected_fixed_commitments,
        )?;
        let parsed_fixed_openings = parse_spark_fixed_openings::<E, E::EF, Pcs>(
            &spark_fixed_value_pcs_config,
            &spark_fixed_audit_pcs_config,
            &proof.spark_fixed_openings,
            challenger,
        )?;
        let parsed_read_openings = parse_spark_read_openings::<E, E::EF, Pcs>(
            &spark_read_pcs_config,
            &proof.spark_read_openings,
            challenger,
        )?;
        let product_claims = verify_spark_batched_memory_product_claims(
            &spark_tables,
            &proof.spark_products,
            challenger,
        )?;
        finalize_spark_fixed_openings::<E, E::EF, Pcs>(
            &spark_fixed_value_pcs_config,
            &spark_fixed_audit_pcs_config,
            spark_tables.row_memory_size,
            spark_tables.col_memory_size,
            &proof.spark_fixed_openings,
            parsed_fixed_openings,
            &product_claims,
            challenger,
        )?;
        let read_opening_evals = finalize_spark_read_openings::<E, E::EF, Pcs>(
            &spark_read_pcs_config,
            &proof.spark_read_openings,
            parsed_read_openings,
            &product_claims,
            challenger,
        )?;
        verify_spark_batched_memory_leaf_claims_with_openings(
            spark_tables.row_memory_size,
            spark_tables.col_memory_size,
            &product_claims,
            &proof.spark_fixed_openings.evals,
            &read_opening_evals,
            &r_x,
            &r_y,
        )?;

        let eval_x_table =
            public_half_as_extension(vk.shape_canonical.num_vars, &instance.public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let eval_z = (E::EF::ONE - r_y.0[0]) * proof.witness_eval + r_y.0[0] * eval_x;
        let spark_matrix_eval = matrix_eval_rlc(product_claims.matrix_evals, r);
        if inner_final_claim != spark_matrix_eval * eval_z {
            return Err(SpartanWhirError::SumcheckFailed);
        }

        let pcs_statement = PcsStatementBuilder::<E>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: proof.witness_eval,
            })
            .finalize()?;

        <Pcs as ProtocolPcs<E>>::verify_finalize(
            &vk.pcs_config,
            &parsed_commitment,
            &pcs_statement,
            &proof.pcs_proof,
            challenger,
        )?;

        observer.on_stage(ProtocolStage::VerifyEnd);
        Ok(())
    }
}

fn observe_spartan_context<E, Ext>(
    challenger: &mut E::Challenger,
    domain_separator: &DomainSeparator,
    public_inputs: &[F],
) -> Result<(), SpartanWhirError>
where
    Ext: ExtField,
    E: SpartanContextEngine<EF = Ext>,
{
    E::observe_spartan_context(challenger, domain_separator, public_inputs)
}

fn sample_algebra_vec<E, Ext>(challenger: &mut E::Challenger, len: usize) -> Vec<Ext>
where
    Ext: ExtField,
    E: SpartanWhirEngine<F = F, EF = Ext>,
    E::Challenger: FieldChallenger<F>,
{
    (0..len)
        .map(|_| challenger.sample_algebra_element::<Ext>())
        .collect()
}

fn matrix_eval_rlc<EF>(matrix_evals: [EF; 3], r: EF) -> EF
where
    EF: Field,
{
    matrix_evals[0] + r * matrix_evals[1] + r * r * matrix_evals[2]
}

fn setup_spark_fixed_commitments<E, EF, Pcs>(
    pcs_config: &WhirPcsConfig,
    shape: &R1csShape<F>,
) -> Result<
    Option<(
        SparkFixedProverData<E, Pcs>,
        SparkFixedCommitments<<Pcs as MlePcs<E>>::Commitment>,
    )>,
    SpartanWhirError,
>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let spark_tables = preprocess_spark_tables(shape)?;
    let spark_value_pcs_config = spark_table_pcs_config(pcs_config, spark_tables.value_domain_size);
    let spark_fixed_audit_pcs_config = spark_fixed_audit_pcs_config(
        pcs_config,
        spark_tables.row_memory_size,
        spark_tables.col_memory_size,
    );

    let (Ok(value_config), Ok(audit_config)) =
        (spark_value_pcs_config, spark_fixed_audit_pcs_config)
    else {
        return Ok(None);
    };
    let Ok(fixed_value_config) = spark_fixed_value_pcs_config(&value_config) else {
        return Ok(None);
    };

    let mut spark_setup_challenger = E::challenger();
    let (prover_data, commitments) = commit_spark_fixed_tables::<E, EF, Pcs>(
        &fixed_value_config,
        &audit_config,
        &spark_tables,
        &mut spark_setup_challenger,
    )?;
    Ok(Some((prover_data, commitments)))
}

fn spark_table_pcs_config(
    base: &WhirPcsConfig,
    domain_size: usize,
) -> Result<WhirPcsConfig, SpartanWhirError> {
    if domain_size == 0 || !domain_size.is_power_of_two() {
        return Err(SpartanWhirError::InvalidPolynomialLength);
    }
    let mut config = *base;
    config.num_variables = domain_size.ilog2() as usize;
    config.validate()?;
    Ok(config)
}

fn spark_read_pcs_config<EF>(
    value_config: &WhirPcsConfig,
) -> Result<WhirPcsConfig, SpartanWhirError>
where
    EF: ExtField,
{
    let mut config = *value_config;
    config.num_variables = config
        .num_variables
        .checked_add(read_column_bits::<EF>())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    config.validate()?;
    Ok(config)
}

fn spark_fixed_value_pcs_config(
    value_config: &WhirPcsConfig,
) -> Result<WhirPcsConfig, SpartanWhirError> {
    let mut config = *value_config;
    config.num_variables = config
        .num_variables
        .checked_add(fixed_value_column_bits())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    config.validate()?;
    Ok(config)
}

fn spark_fixed_audit_pcs_config(
    base: &WhirPcsConfig,
    row_memory_size: usize,
    col_memory_size: usize,
) -> Result<WhirPcsConfig, SpartanWhirError> {
    let audit_memory_size = row_memory_size
        .max(col_memory_size)
        .checked_next_power_of_two()
        .ok_or(SpartanWhirError::InvalidConfig)?;
    let audit_domain_size = audit_memory_size
        .checked_mul(fixed_audit_column_count())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    spark_table_pcs_config(base, audit_domain_size)
}

fn commit_spark_fixed_tables<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    tables: &crate::SparkTables,
    challenger: &mut E::Challenger,
) -> Result<
    (
        SparkFixedProverData<E, Pcs>,
        SparkFixedCommitments<<Pcs as MlePcs<E>>::Commitment>,
    ),
    SpartanWhirError,
>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let value_bundle = fixed_value_bundle(tables, fixed_value_config)?;
    let audit_bundle = fixed_audit_bundle(tables, audit_config)?;
    let (value_commitment, value) =
        <Pcs as MlePcs<E>>::commit(fixed_value_config, &value_bundle, challenger)?;
    let (audit_commitment, audit) =
        <Pcs as MlePcs<E>>::commit(audit_config, &audit_bundle, challenger)?;

    Ok((
        SparkFixedProverData {
            value,
            audit,
            marker: PhantomData,
        },
        SparkFixedCommitments {
            value: value_commitment,
            audit: audit_commitment,
        },
    ))
}

fn fixed_value_bundle(
    tables: &crate::SparkTables,
    config: &WhirPcsConfig,
) -> Result<Vec<F>, SpartanWhirError> {
    let domain_size = tables.value_domain_size;
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || config.num_variables != domain_size.ilog2() as usize + fixed_value_column_bits()
    {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let mut packed = vec![F::ZERO; domain_size * fixed_value_column_count()];
    copy_rectangular_base_column(&mut packed, domain_size, 0, &tables.rows)?;
    copy_rectangular_base_column(&mut packed, domain_size, 1, &tables.cols)?;
    copy_rectangular_base_column(&mut packed, domain_size, 2, &tables.val_a)?;
    copy_rectangular_base_column(&mut packed, domain_size, 3, &tables.val_b)?;
    copy_rectangular_base_column(&mut packed, domain_size, 4, &tables.val_c)?;
    copy_rectangular_base_column(&mut packed, domain_size, 5, &tables.read_ts_row)?;
    copy_rectangular_base_column(&mut packed, domain_size, 6, &tables.read_ts_col)?;
    Ok(packed)
}

fn fixed_audit_bundle(
    tables: &crate::SparkTables,
    config: &WhirPcsConfig,
) -> Result<Vec<F>, SpartanWhirError> {
    if config.num_variables < fixed_audit_column_bits() {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let audit_memory_bits = config.num_variables - fixed_audit_column_bits();
    let audit_memory_size = 1usize
        .checked_shl(audit_memory_bits as u32)
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if tables.row_memory_size > audit_memory_size || tables.col_memory_size > audit_memory_size {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let mut packed = vec![F::ZERO; audit_memory_size * fixed_audit_column_count()];
    copy_rectangular_base_column(&mut packed, audit_memory_size, 0, &tables.audit_ts_row)?;
    copy_rectangular_base_column(&mut packed, audit_memory_size, 1, &tables.audit_ts_col)?;
    Ok(packed)
}

fn copy_rectangular_base_column(
    packed: &mut [F],
    domain_size: usize,
    column: usize,
    values: &[F],
) -> Result<(), SpartanWhirError> {
    let start = column
        .checked_mul(domain_size)
        .ok_or(SpartanWhirError::InvalidConfig)?;
    let end = start
        .checked_add(values.len())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if domain_size == 0 || values.len() > domain_size || end > packed.len() {
        return Err(SpartanWhirError::InvalidConfig);
    }
    packed[start..end].copy_from_slice(values);
    Ok(())
}

fn commit_spark_read_tables<E, EF, Pcs>(
    config: &WhirPcsConfig,
    read_tables: &SparkReadTables<EF>,
    challenger: &mut E::Challenger,
) -> Result<
    (
        SparkReadProverData<E, Pcs>,
        SparkReadCommitments<<Pcs as MlePcs<E>>::Commitment>,
    ),
    SpartanWhirError,
>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let erow_columns = extension_table_to_base_columns(&read_tables.erow)?;
    let ecol_columns = extension_table_to_base_columns(&read_tables.ecol)?;
    let domain_size = read_tables.erow.len();
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || read_tables.ecol.len() != domain_size
        || config.num_variables != domain_size.ilog2() as usize + read_column_bits::<EF>()
    {
        return Err(SpartanWhirError::InvalidConfig);
    }
    // Column-major layout: high selector bits choose the coordinate column, and
    // the remaining coordinates are the original sparse-entry point.
    let mut packed = vec![F::ZERO; domain_size * read_column_count::<EF>()];
    for (column_index, column) in erow_columns.iter().enumerate() {
        packed[column_index * domain_size..(column_index + 1) * domain_size]
            .copy_from_slice(column);
    }
    for (coord_index, column) in ecol_columns.iter().enumerate() {
        let column_index = EF::DIMENSION + coord_index;
        packed[column_index * domain_size..(column_index + 1) * domain_size]
            .copy_from_slice(column);
    }
    let (commitment, data) = <Pcs as MlePcs<E>>::commit(config, &packed, challenger)?;

    Ok((
        SparkReadProverData {
            data,
            marker: PhantomData,
        },
        SparkReadCommitments { commitment },
    ))
}

fn prepare_spark_fixed_openings<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    prover_data: SparkFixedProverData<E, Pcs>,
    challenger: &mut E::Challenger,
) -> Result<SparkFixedProverData<E, Pcs>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
{
    Ok(SparkFixedProverData {
        value: <Pcs as ProtocolPcs<E>>::prepare_committed_opening(
            fixed_value_config,
            prover_data.value,
            challenger,
        )?,
        audit: <Pcs as ProtocolPcs<E>>::prepare_committed_opening(
            audit_config,
            prover_data.audit,
            challenger,
        )?,
        marker: PhantomData,
    })
}

fn open_spark_fixed_tables<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    prover_data: SparkFixedProverData<E, Pcs>,
    commitments: SparkFixedCommitments<<Pcs as MlePcs<E>>::Commitment>,
    tables: &crate::SparkTables,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    challenger: &mut E::Challenger,
) -> Result<SparkFixedOpeningProof<E, Pcs>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let (value_claims, value_evals) = fixed_value_opening_claims_from_prover_data(
        fixed_value_config,
        &prover_data.value,
        product_claims,
    )?;
    let expected_weights = [
        value_evals.val_a_low,
        value_evals.val_a_high,
        value_evals.val_b_low,
        value_evals.val_b_high,
        value_evals.val_c_low,
        value_evals.val_c_high,
    ];
    if product_claims.ops.dotproduct_weight_evals.as_slice() != expected_weights {
        return Err(SpartanWhirError::SumcheckFailed);
    }
    let value_statement = point_eval_statement::<E, EF>(&value_claims)?;
    let value_proof = <Pcs as MlePcs<E>>::open(
        fixed_value_config,
        prover_data.value,
        &value_statement,
        challenger,
    )?;

    let (audit_claims, audit_evals) = fixed_audit_opening_claims_from_prover_data(
        audit_config,
        &prover_data.audit,
        tables.row_memory_size,
        tables.col_memory_size,
        product_claims,
    )?;
    let audit_statement = point_eval_statement::<E, EF>(&audit_claims)?;
    let audit_proof = <Pcs as MlePcs<E>>::open(
        audit_config,
        prover_data.audit,
        &audit_statement,
        challenger,
    )?;

    Ok(SparkFixedOpeningProof {
        value_num_variables: fixed_value_config.num_variables,
        value_column_bits: fixed_value_column_bits(),
        audit_num_variables: audit_config.num_variables,
        audit_column_bits: fixed_audit_column_bits(),
        value_commitment: commitments.value,
        audit_commitment: commitments.audit,
        evals: SparkFixedTableOpeningEvals {
            val_a_low: value_evals.val_a_low,
            val_a_high: value_evals.val_a_high,
            val_b_low: value_evals.val_b_low,
            val_b_high: value_evals.val_b_high,
            val_c_low: value_evals.val_c_low,
            val_c_high: value_evals.val_c_high,
            row_addr: value_evals.row_addr,
            col_addr: value_evals.col_addr,
            row_read_ts: value_evals.row_read_ts,
            col_read_ts: value_evals.col_read_ts,
            row_audit_ts: audit_evals.row_audit_ts,
            col_audit_ts: audit_evals.col_audit_ts,
        },
        value_proof,
        audit_proof,
        marker: PhantomData,
    })
}

fn open_spark_read_tables<E, EF, Pcs>(
    config: &WhirPcsConfig,
    prover_data: SparkReadProverData<E, Pcs>,
    commitments: SparkReadCommitments<<Pcs as MlePcs<E>>::Commitment>,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    challenger: &mut E::Challenger,
) -> Result<SparkReadOpeningProof<E, Pcs>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::ProverData: Clone + CommittedPolynomialView<EF>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let value_num_variables = config
        .num_variables
        .checked_sub(read_column_bits::<EF>())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if product_claims.ops.product_point.0.len() != value_num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    let (claims, erow_evals, ecol_evals) =
        read_opening_claims_from_prover_data(config, &prover_data.data, product_claims)?;
    let read_evals = split_read_coordinate_evals::<EF>(&erow_evals, &ecol_evals)?;
    let expected_left = [
        read_evals.erow_low,
        read_evals.erow_high,
        read_evals.erow_low,
        read_evals.erow_high,
        read_evals.erow_low,
        read_evals.erow_high,
    ];
    let expected_right = [
        read_evals.ecol_low,
        read_evals.ecol_high,
        read_evals.ecol_low,
        read_evals.ecol_high,
        read_evals.ecol_low,
        read_evals.ecol_high,
    ];
    if product_claims.ops.dotproduct_left_evals.as_slice() != expected_left
        || product_claims.ops.dotproduct_right_evals.as_slice() != expected_right
        || product_claims.ops.product_evals.len() != 4
    {
        return Err(SpartanWhirError::SumcheckFailed);
    }
    let statement = point_eval_statement::<E, EF>(&claims)?;
    let proof = <Pcs as MlePcs<E>>::open(config, prover_data.data, &statement, challenger)?;

    Ok(SparkReadOpeningProof {
        num_variables: config.num_variables,
        column_bits: read_column_bits::<EF>(),
        commitment: commitments.commitment,
        erow_low_evals: erow_evals[0].clone(),
        erow_high_evals: erow_evals[1].clone(),
        ecol_low_evals: ecol_evals[0].clone(),
        ecol_high_evals: ecol_evals[1].clone(),
        erow_ops_evals: erow_evals[2].clone(),
        ecol_ops_evals: ecol_evals[2].clone(),
        proof,
        marker: PhantomData,
    })
}

fn parse_spark_fixed_openings<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    proof: &SparkFixedOpeningProof<E, Pcs>,
    challenger: &mut E::Challenger,
) -> Result<ParsedSparkFixedOpenings<E, Pcs>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    validate_spark_fixed_opening_shape::<E, EF, Pcs>(fixed_value_config, audit_config, proof)?;
    Ok(ParsedSparkFixedOpenings {
        value: <Pcs as ProtocolPcs<E>>::verify_parse_commitment(
            fixed_value_config,
            &proof.value_commitment,
            &proof.value_proof,
            challenger,
        )?,
        audit: <Pcs as ProtocolPcs<E>>::verify_parse_commitment(
            audit_config,
            &proof.audit_commitment,
            &proof.audit_proof,
            challenger,
        )?,
    })
}

fn parse_spark_read_openings<E, EF, Pcs>(
    config: &WhirPcsConfig,
    proof: &SparkReadOpeningProof<E, Pcs>,
    challenger: &mut E::Challenger,
) -> Result<ParsedSparkReadOpenings<E, Pcs>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    validate_spark_read_opening_shape::<E, EF, Pcs>(config, proof)?;
    Ok(ParsedSparkReadOpenings {
        commitment: <Pcs as ProtocolPcs<E>>::verify_parse_commitment(
            config,
            &proof.commitment,
            &proof.proof,
            challenger,
        )?,
    })
}

fn finalize_spark_fixed_openings<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    row_memory_size: usize,
    col_memory_size: usize,
    proof: &SparkFixedOpeningProof<E, Pcs>,
    parsed: ParsedSparkFixedOpenings<E, Pcs>,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    challenger: &mut E::Challenger,
) -> Result<(), SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    validate_spark_fixed_opening_shape::<E, EF, Pcs>(fixed_value_config, audit_config, proof)?;
    let value_claims = fixed_value_opening_claims_from_evals(product_claims, &proof.evals)?;
    let value_statement = point_eval_statement::<E, EF>(&value_claims)?;
    <Pcs as ProtocolPcs<E>>::verify_finalize(
        fixed_value_config,
        &parsed.value,
        &value_statement,
        &proof.value_proof,
        challenger,
    )?;

    let audit_claims = fixed_audit_opening_claims_from_evals(
        audit_config,
        row_memory_size,
        col_memory_size,
        product_claims,
        &proof.evals,
    )?;
    let audit_statement = point_eval_statement::<E, EF>(&audit_claims)?;
    <Pcs as ProtocolPcs<E>>::verify_finalize(
        audit_config,
        &parsed.audit,
        &audit_statement,
        &proof.audit_proof,
        challenger,
    )
}

fn finalize_spark_read_openings<E, EF, Pcs>(
    config: &WhirPcsConfig,
    proof: &SparkReadOpeningProof<E, Pcs>,
    parsed: ParsedSparkReadOpenings<E, Pcs>,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    challenger: &mut E::Challenger,
) -> Result<SparkReadTableOpeningEvals<EF>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: ProtocolPcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    validate_spark_read_opening_shape::<E, EF, Pcs>(config, proof)?;
    let value_num_variables = config
        .num_variables
        .checked_sub(read_column_bits::<EF>())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if product_claims.ops.product_point.0.len() != value_num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    let erow_evals = [
        proof.erow_low_evals.as_slice(),
        proof.erow_high_evals.as_slice(),
        proof.erow_ops_evals.as_slice(),
    ];
    let ecol_evals = [
        proof.ecol_low_evals.as_slice(),
        proof.ecol_high_evals.as_slice(),
        proof.ecol_ops_evals.as_slice(),
    ];
    let claims = read_opening_claims_from_evals(product_claims, &erow_evals, &ecol_evals)?;
    let statement = point_eval_statement::<E, EF>(&claims)?;
    <Pcs as ProtocolPcs<E>>::verify_finalize(
        config,
        &parsed.commitment,
        &statement,
        &proof.proof,
        challenger,
    )?;
    split_read_coordinate_evals(
        &[
            proof.erow_low_evals.clone(),
            proof.erow_high_evals.clone(),
            proof.erow_ops_evals.clone(),
        ],
        &[
            proof.ecol_low_evals.clone(),
            proof.ecol_high_evals.clone(),
            proof.ecol_ops_evals.clone(),
        ],
    )
}

fn fixed_value_opening_claims_from_prover_data<EF, D>(
    config: &WhirPcsConfig,
    prover_data: &D,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
) -> Result<
    (
        Vec<(MultilinearPoint<EF>, EF)>,
        SparkFixedValueOpeningEvals<EF>,
    ),
    SpartanWhirError,
>
where
    EF: ExtField,
    D: CommittedPolynomialView<EF>,
{
    if prover_data.num_variables() != config.num_variables {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let value_num_variables = config
        .num_variables
        .checked_sub(fixed_value_column_bits())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if product_claims.ops.product_point.0.len() != value_num_variables {
        return Err(SpartanWhirError::InvalidNumVariables);
    }
    let poly_ext: Vec<EF> = prover_data
        .polynomial()
        .iter()
        .map(|&value| EF::from(value))
        .collect();
    let (dot_low_point, dot_high_point) = dotproduct_full_domain_points(&product_claims.ops)?;
    let mut claims = Vec::with_capacity(10);
    let row_addr = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        0,
        &product_claims.ops.product_point,
        &mut claims,
    )?;
    let col_addr = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        1,
        &product_claims.ops.product_point,
        &mut claims,
    )?;
    let val_a_low = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        2,
        &dot_low_point,
        &mut claims,
    )?;
    let val_a_high = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        2,
        &dot_high_point,
        &mut claims,
    )?;
    let val_b_low = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        3,
        &dot_low_point,
        &mut claims,
    )?;
    let val_b_high = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        3,
        &dot_high_point,
        &mut claims,
    )?;
    let val_c_low = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        4,
        &dot_low_point,
        &mut claims,
    )?;
    let val_c_high = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        4,
        &dot_high_point,
        &mut claims,
    )?;
    let row_read_ts = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        5,
        &product_claims.ops.product_point,
        &mut claims,
    )?;
    let col_read_ts = push_rectangular_opening_claim(
        &poly_ext,
        fixed_value_column_bits(),
        6,
        &product_claims.ops.product_point,
        &mut claims,
    )?;
    Ok((
        claims,
        SparkFixedValueOpeningEvals {
            val_a_low,
            val_a_high,
            val_b_low,
            val_b_high,
            val_c_low,
            val_c_high,
            row_addr,
            col_addr,
            row_read_ts,
            col_read_ts,
        },
    ))
}

fn fixed_value_opening_claims_from_evals<EF>(
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    evals: &SparkFixedTableOpeningEvals<EF>,
) -> Result<Vec<(MultilinearPoint<EF>, EF)>, SpartanWhirError>
where
    EF: ExtField,
{
    let (dot_low_point, dot_high_point) = dotproduct_full_domain_points(&product_claims.ops)?;
    Ok(vec![
        (
            rectangular_point::<EF>(
                0,
                fixed_value_column_bits(),
                &product_claims.ops.product_point,
            )?,
            evals.row_addr,
        ),
        (
            rectangular_point::<EF>(
                1,
                fixed_value_column_bits(),
                &product_claims.ops.product_point,
            )?,
            evals.col_addr,
        ),
        (
            rectangular_point::<EF>(2, fixed_value_column_bits(), &dot_low_point)?,
            evals.val_a_low,
        ),
        (
            rectangular_point::<EF>(2, fixed_value_column_bits(), &dot_high_point)?,
            evals.val_a_high,
        ),
        (
            rectangular_point::<EF>(3, fixed_value_column_bits(), &dot_low_point)?,
            evals.val_b_low,
        ),
        (
            rectangular_point::<EF>(3, fixed_value_column_bits(), &dot_high_point)?,
            evals.val_b_high,
        ),
        (
            rectangular_point::<EF>(4, fixed_value_column_bits(), &dot_low_point)?,
            evals.val_c_low,
        ),
        (
            rectangular_point::<EF>(4, fixed_value_column_bits(), &dot_high_point)?,
            evals.val_c_high,
        ),
        (
            rectangular_point::<EF>(
                5,
                fixed_value_column_bits(),
                &product_claims.ops.product_point,
            )?,
            evals.row_read_ts,
        ),
        (
            rectangular_point::<EF>(
                6,
                fixed_value_column_bits(),
                &product_claims.ops.product_point,
            )?,
            evals.col_read_ts,
        ),
    ])
}

fn fixed_audit_opening_claims_from_prover_data<EF, D>(
    config: &WhirPcsConfig,
    prover_data: &D,
    row_memory_size: usize,
    col_memory_size: usize,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
) -> Result<
    (
        Vec<(MultilinearPoint<EF>, EF)>,
        SparkFixedAuditOpeningEvals<EF>,
    ),
    SpartanWhirError,
>
where
    EF: ExtField,
    D: CommittedPolynomialView<EF>,
{
    if prover_data.num_variables() != config.num_variables {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let audit_memory_bits = config
        .num_variables
        .checked_sub(fixed_audit_column_bits())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    let poly_ext: Vec<EF> = prover_data
        .polynomial()
        .iter()
        .map(|&value| EF::from(value))
        .collect();
    let row_point = low_block_memory_point(
        &product_claims.mem.product_point,
        row_memory_size,
        audit_memory_bits,
    )?;
    let col_point = low_block_memory_point(
        &product_claims.mem.product_point,
        col_memory_size,
        audit_memory_bits,
    )?;
    let mut claims = Vec::with_capacity(2);
    let row_audit_ts = push_rectangular_opening_claim(
        &poly_ext,
        fixed_audit_column_bits(),
        0,
        &row_point,
        &mut claims,
    )?;
    let col_audit_ts = push_rectangular_opening_claim(
        &poly_ext,
        fixed_audit_column_bits(),
        1,
        &col_point,
        &mut claims,
    )?;
    Ok((
        claims,
        SparkFixedAuditOpeningEvals {
            row_audit_ts,
            col_audit_ts,
        },
    ))
}

fn fixed_audit_opening_claims_from_evals<EF>(
    config: &WhirPcsConfig,
    row_memory_size: usize,
    col_memory_size: usize,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    evals: &SparkFixedTableOpeningEvals<EF>,
) -> Result<Vec<(MultilinearPoint<EF>, EF)>, SpartanWhirError>
where
    EF: ExtField,
{
    let audit_memory_bits = config
        .num_variables
        .checked_sub(fixed_audit_column_bits())
        .ok_or(SpartanWhirError::InvalidConfig)?;
    let row_point = low_block_memory_point(
        &product_claims.mem.product_point,
        row_memory_size,
        audit_memory_bits,
    )?;
    let col_point = low_block_memory_point(
        &product_claims.mem.product_point,
        col_memory_size,
        audit_memory_bits,
    )?;
    Ok(vec![
        (
            rectangular_point::<EF>(0, fixed_audit_column_bits(), &row_point)?,
            evals.row_audit_ts,
        ),
        (
            rectangular_point::<EF>(1, fixed_audit_column_bits(), &col_point)?,
            evals.col_audit_ts,
        ),
    ])
}

#[derive(Debug, Clone, Copy)]
struct SparkFixedValueOpeningEvals<EF> {
    val_a_low: EF,
    val_a_high: EF,
    val_b_low: EF,
    val_b_high: EF,
    val_c_low: EF,
    val_c_high: EF,
    row_addr: EF,
    col_addr: EF,
    row_read_ts: EF,
    col_read_ts: EF,
}

#[derive(Debug, Clone, Copy)]
struct SparkFixedAuditOpeningEvals<EF> {
    row_audit_ts: EF,
    col_audit_ts: EF,
}

type ReadCoordinateEvals<EF> = [Vec<EF>; 3];

fn read_opening_claims_from_prover_data<EF, D>(
    config: &WhirPcsConfig,
    prover_data: &D,
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
) -> Result<
    (
        Vec<(MultilinearPoint<EF>, EF)>,
        ReadCoordinateEvals<EF>,
        ReadCoordinateEvals<EF>,
    ),
    SpartanWhirError,
>
where
    EF: ExtField,
    D: CommittedPolynomialView<EF>,
{
    if prover_data.num_variables() != config.num_variables {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let poly_ext: Vec<EF> = prover_data
        .polynomial()
        .iter()
        .map(|&v| EF::from(v))
        .collect();
    let points = read_opening_points(product_claims)?;
    let mut claims = Vec::with_capacity(6 * EF::DIMENSION);
    let mut erow_evals = [
        Vec::with_capacity(EF::DIMENSION),
        Vec::with_capacity(EF::DIMENSION),
        Vec::with_capacity(EF::DIMENSION),
    ];
    let mut ecol_evals = [
        Vec::with_capacity(EF::DIMENSION),
        Vec::with_capacity(EF::DIMENSION),
        Vec::with_capacity(EF::DIMENSION),
    ];

    for column in 0..EF::DIMENSION {
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.erow_low,
            &mut erow_evals[0],
            &mut claims,
        )?;
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.erow_high,
            &mut erow_evals[1],
            &mut claims,
        )?;
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.erow_ops,
            &mut erow_evals[2],
            &mut claims,
        )?;
    }
    for coordinate in 0..EF::DIMENSION {
        let column = EF::DIMENSION + coordinate;
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.ecol_low,
            &mut ecol_evals[0],
            &mut claims,
        )?;
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.ecol_high,
            &mut ecol_evals[1],
            &mut claims,
        )?;
        push_read_opening_claim(
            &poly_ext,
            column,
            &points.ecol_ops,
            &mut ecol_evals[2],
            &mut claims,
        )?;
    }

    Ok((claims, erow_evals, ecol_evals))
}

struct SparkReadOpeningPoints<EF> {
    erow_low: MultilinearPoint<EF>,
    erow_high: MultilinearPoint<EF>,
    erow_ops: MultilinearPoint<EF>,
    ecol_low: MultilinearPoint<EF>,
    ecol_high: MultilinearPoint<EF>,
    ecol_ops: MultilinearPoint<EF>,
}

fn read_opening_points<EF>(
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
) -> Result<SparkReadOpeningPoints<EF>, SpartanWhirError>
where
    EF: ExtField,
{
    let (low, high) = dotproduct_full_domain_points(&product_claims.ops)?;
    Ok(SparkReadOpeningPoints {
        erow_low: low.clone(),
        erow_high: high.clone(),
        erow_ops: product_claims.ops.product_point.clone(),
        ecol_low: low,
        ecol_high: high,
        ecol_ops: product_claims.ops.product_point.clone(),
    })
}

fn read_opening_claims_from_evals<EF>(
    product_claims: &SparkBatchedMemoryProductsLeafClaims<EF>,
    erow_evals: &[&[EF]; 3],
    ecol_evals: &[&[EF]; 3],
) -> Result<Vec<(MultilinearPoint<EF>, EF)>, SpartanWhirError>
where
    EF: ExtField,
{
    if erow_evals.iter().any(|evals| evals.len() != EF::DIMENSION)
        || ecol_evals.iter().any(|evals| evals.len() != EF::DIMENSION)
    {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let points = read_opening_points(product_claims)?;
    let mut claims = Vec::with_capacity(6 * EF::DIMENSION);
    for column in 0..EF::DIMENSION {
        claims.push((
            read_rectangular_point::<EF>(column, &points.erow_low)?,
            erow_evals[0][column],
        ));
        claims.push((
            read_rectangular_point::<EF>(column, &points.erow_high)?,
            erow_evals[1][column],
        ));
        claims.push((
            read_rectangular_point::<EF>(column, &points.erow_ops)?,
            erow_evals[2][column],
        ));
    }
    for coordinate in 0..EF::DIMENSION {
        let column = EF::DIMENSION + coordinate;
        claims.push((
            read_rectangular_point::<EF>(column, &points.ecol_low)?,
            ecol_evals[0][coordinate],
        ));
        claims.push((
            read_rectangular_point::<EF>(column, &points.ecol_high)?,
            ecol_evals[1][coordinate],
        ));
        claims.push((
            read_rectangular_point::<EF>(column, &points.ecol_ops)?,
            ecol_evals[2][coordinate],
        ));
    }
    Ok(claims)
}

fn push_read_opening_claim<EF>(
    poly_ext: &[EF],
    column: usize,
    base_point: &MultilinearPoint<EF>,
    evals: &mut Vec<EF>,
    claims: &mut Vec<(MultilinearPoint<EF>, EF)>,
) -> Result<(), SpartanWhirError>
where
    EF: ExtField,
{
    let point = read_rectangular_point::<EF>(column, base_point)?;
    let value = push_opening_claim_at_point(poly_ext, point, claims)?;
    evals.push(value);
    Ok(())
}

fn read_rectangular_point<EF>(
    column: usize,
    base_point: &MultilinearPoint<EF>,
) -> Result<MultilinearPoint<EF>, SpartanWhirError>
where
    EF: ExtField,
{
    if column >= read_column_count::<EF>() {
        return Err(SpartanWhirError::InvalidConfig);
    }
    rectangular_point(column, read_column_bits::<EF>(), base_point)
}

fn dotproduct_full_domain_points<EF>(
    claims: &crate::SparkBatchedProductLeafClaims<EF>,
) -> Result<(MultilinearPoint<EF>, MultilinearPoint<EF>), SpartanWhirError>
where
    EF: ExtField,
{
    let mut low = Vec::with_capacity(claims.dotproduct_point.0.len() + 1);
    low.push(EF::ZERO);
    low.extend_from_slice(&claims.dotproduct_point.0);
    let mut high = Vec::with_capacity(claims.dotproduct_point.0.len() + 1);
    high.push(EF::ONE);
    high.extend_from_slice(&claims.dotproduct_point.0);
    if claims.product_point.0.len() != low.len() {
        return Err(SpartanWhirError::InvalidRoundCount);
    }
    Ok((MultilinearPoint(low), MultilinearPoint(high)))
}

fn low_block_memory_point<EF>(
    padded_point: &MultilinearPoint<EF>,
    memory_size: usize,
    target_len: usize,
) -> Result<MultilinearPoint<EF>, SpartanWhirError>
where
    EF: ExtField,
{
    if memory_size == 0 || !memory_size.is_power_of_two() {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let memory_bits = memory_size.ilog2() as usize;
    if memory_bits > target_len || padded_point.0.len() < memory_bits {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let suffix_start = padded_point.0.len() - memory_bits;
    let mut point = vec![EF::ZERO; target_len - memory_bits];
    point.extend_from_slice(&padded_point.0[suffix_start..]);
    Ok(MultilinearPoint(point))
}

fn push_rectangular_opening_claim<EF>(
    poly_ext: &[EF],
    column_bits: usize,
    column: usize,
    base_point: &MultilinearPoint<EF>,
    claims: &mut Vec<(MultilinearPoint<EF>, EF)>,
) -> Result<EF, SpartanWhirError>
where
    EF: ExtField,
{
    let point = rectangular_point(column, column_bits, base_point)?;
    push_opening_claim_at_point(poly_ext, point, claims)
}

fn push_opening_claim_at_point<EF>(
    poly_ext: &[EF],
    point: MultilinearPoint<EF>,
    claims: &mut Vec<(MultilinearPoint<EF>, EF)>,
) -> Result<EF, SpartanWhirError>
where
    EF: ExtField,
{
    let value = evaluate_mle_table(poly_ext, &point.0)?;
    claims.push((point, value));
    Ok(value)
}

fn rectangular_point<EF>(
    column: usize,
    column_bits: usize,
    base_point: &MultilinearPoint<EF>,
) -> Result<MultilinearPoint<EF>, SpartanWhirError>
where
    EF: ExtField,
{
    let column_count = 1usize
        .checked_shl(column_bits as u32)
        .ok_or(SpartanWhirError::InvalidConfig)?;
    if column >= column_count {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let mut point = Vec::with_capacity(column_bits + base_point.0.len());
    for i in 0..column_bits {
        let bit = (column >> (column_bits - i - 1)) & 1;
        point.push(if bit == 0 { EF::ZERO } else { EF::ONE });
    }
    point.extend_from_slice(&base_point.0);
    Ok(MultilinearPoint(point))
}

fn read_column_count<EF>() -> usize
where
    EF: ExtField,
{
    (2 * EF::DIMENSION).next_power_of_two()
}

fn read_column_bits<EF>() -> usize
where
    EF: ExtField,
{
    read_column_count::<EF>().ilog2() as usize
}

fn fixed_value_column_count() -> usize {
    8
}

fn fixed_value_column_bits() -> usize {
    3
}

fn fixed_audit_column_count() -> usize {
    2
}

fn fixed_audit_column_bits() -> usize {
    1
}

fn point_eval_statement<E, EF>(
    claims: &[(MultilinearPoint<EF>, EF)],
) -> Result<crate::PcsStatement<E>, SpartanWhirError>
where
    EF: ExtField,
    E: SpartanWhirEngine<F = F, EF = EF>,
{
    let mut builder = PcsStatementBuilder::<E>::new();
    for (point, value) in claims {
        builder = builder.add_point_eval(PointEvalClaim {
            point: point.clone(),
            value: *value,
        });
    }
    builder.finalize()
}

fn validate_spark_fixed_opening_shape<E, EF, Pcs>(
    fixed_value_config: &WhirPcsConfig,
    audit_config: &WhirPcsConfig,
    proof: &SparkFixedOpeningProof<E, Pcs>,
) -> Result<(), SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: MlePcs<E, Config = WhirPcsConfig>,
{
    if proof.value_num_variables != fixed_value_config.num_variables
        || proof.value_column_bits != fixed_value_column_bits()
        || proof.audit_num_variables != audit_config.num_variables
        || proof.audit_column_bits != fixed_audit_column_bits()
    {
        return Err(SpartanWhirError::InvalidConfig);
    }
    Ok(())
}

fn validate_spark_fixed_commitments<E, EF, Pcs>(
    proof: &SparkFixedOpeningProof<E, Pcs>,
    expected: &SparkFixedCommitments<<Pcs as MlePcs<E>>::Commitment>,
) -> Result<(), SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: MlePcs<E, Config = WhirPcsConfig>,
    <Pcs as MlePcs<E>>::Commitment: Clone + PartialEq,
{
    let actual = SparkFixedCommitments {
        value: proof.value_commitment.clone(),
        audit: proof.audit_commitment.clone(),
    };
    if &actual != expected {
        return Err(SpartanWhirError::CommitmentMismatch);
    }
    Ok(())
}

fn validate_spark_read_opening_shape<E, EF, Pcs>(
    config: &WhirPcsConfig,
    proof: &SparkReadOpeningProof<E, Pcs>,
) -> Result<(), SpartanWhirError>
where
    EF: ExtField,
    E: SpartanContextEngine<EF = EF>,
    Pcs: MlePcs<E, Config = WhirPcsConfig>,
{
    if proof.num_variables != config.num_variables
        || proof.column_bits != read_column_bits::<EF>()
        || proof.erow_low_evals.len() != EF::DIMENSION
        || proof.erow_high_evals.len() != EF::DIMENSION
        || proof.ecol_low_evals.len() != EF::DIMENSION
        || proof.ecol_high_evals.len() != EF::DIMENSION
        || proof.erow_ops_evals.len() != EF::DIMENSION
        || proof.ecol_ops_evals.len() != EF::DIMENSION
    {
        return Err(SpartanWhirError::InvalidConfig);
    }
    Ok(())
}

fn split_read_coordinate_evals<EF>(
    erow_evals: &[Vec<EF>],
    ecol_evals: &[Vec<EF>],
) -> Result<SparkReadTableOpeningEvals<EF>, SpartanWhirError>
where
    EF: ExtField,
{
    if erow_evals.len() != 3 || ecol_evals.len() != 3 {
        return Err(SpartanWhirError::InvalidConfig);
    }
    Ok(SparkReadTableOpeningEvals {
        erow_low: recombine_coordinate_evals::<EF>(&erow_evals[0])?,
        erow_high: recombine_coordinate_evals::<EF>(&erow_evals[1])?,
        erow_ops: recombine_coordinate_evals::<EF>(&erow_evals[2])?,
        ecol_low: recombine_coordinate_evals::<EF>(&ecol_evals[0])?,
        ecol_high: recombine_coordinate_evals::<EF>(&ecol_evals[1])?,
        ecol_ops: recombine_coordinate_evals::<EF>(&ecol_evals[2])?,
    })
}

fn extension_table_to_base_columns<EF>(table: &[EF]) -> Result<Vec<Vec<F>>, SpartanWhirError>
where
    EF: ExtField,
{
    if table.is_empty() || !table.len().is_power_of_two() {
        return Err(SpartanWhirError::InvalidPolynomialLength);
    }
    let mut columns = vec![vec![F::ZERO; table.len()]; EF::DIMENSION];
    for (row, value) in table.iter().enumerate() {
        for (col, &coeff) in value.as_basis_coefficients_slice().iter().enumerate() {
            columns[col][row] = coeff;
        }
    }
    Ok(columns)
}

fn recombine_coordinate_evals<EF>(evals: &[EF]) -> Result<EF, SpartanWhirError>
where
    EF: ExtField,
{
    if evals.len() != EF::DIMENSION {
        return Err(SpartanWhirError::InvalidConfig);
    }
    let mut out = EF::ZERO;
    for (i, &eval) in evals.iter().enumerate() {
        let basis = EF::ith_basis_element(i).ok_or(SpartanWhirError::InvalidConfig)?;
        out += eval * basis;
    }
    Ok(out)
}

fn build_public_half(num_vars: usize, public_inputs: &[F]) -> Vec<F> {
    let mut out = vec![F::ZERO; num_vars];
    out[0] = F::ONE;
    for (i, &x) in public_inputs.iter().enumerate() {
        out[i + 1] = x;
    }
    out
}

fn public_half_as_extension<Ext>(num_vars: usize, public_inputs: &[F]) -> Vec<Ext>
where
    Ext: ExtField,
{
    build_public_half(num_vars, public_inputs)
        .into_iter()
        .map(Ext::from)
        .collect()
}

fn build_matrix_z(witness: &[F], public_inputs: &[F]) -> Vec<F> {
    let mut z = Vec::with_capacity(witness.len() + 1 + public_inputs.len());
    z.extend_from_slice(witness);
    z.push(F::ONE);
    z.extend_from_slice(public_inputs);
    z
}

fn eq_point_eval<Ext>(a: &[Ext], b: &[Ext]) -> Ext
where
    Ext: Field,
{
    a.iter().zip(b.iter()).fold(Ext::ONE, |acc, (&x, &y)| {
        acc * ((Ext::ONE - x) * (Ext::ONE - y) + x * y)
    })
}

fn recover_witness_eval<EF: Field>(r0: EF, eval_z: EF, eval_x: EF) -> Result<EF, SpartanWhirError> {
    let denom = EF::ONE - r0;
    let denom_inv = denom
        .try_inverse()
        .ok_or(SpartanWhirError::NonInvertibleElement)?;
    Ok((eval_z - r0 * eval_x) * denom_inv)
}

#[cfg(test)]
mod tests {
    use super::recover_witness_eval;
    use crate::{engine::F, QuarticBinExtension};
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn recover_witness_eval_rejects_non_invertible_denominator() {
        let result = recover_witness_eval(
            QuarticBinExtension::ONE,
            QuarticBinExtension::ONE,
            QuarticBinExtension::ONE,
        );
        assert_eq!(result, Err(crate::SpartanWhirError::NonInvertibleElement));
    }

    #[test]
    fn recover_witness_eval_matches_formula() {
        let r0 = QuarticBinExtension::from(F::from_u32(5));
        let eval_z = QuarticBinExtension::from(F::from_u32(17));
        let eval_x = QuarticBinExtension::from(F::from_u32(3));
        let got = recover_witness_eval(r0, eval_z, eval_x).unwrap();

        let recomposed = (QuarticBinExtension::ONE - r0) * got + r0 * eval_x;
        assert_eq!(recomposed, eval_z);
    }
}
