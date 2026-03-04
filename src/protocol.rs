use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, Hash};

use crate::{engine::KoalaKeccakEngine, KoalaExtension, KoalaField};
use crate::{
    evaluate_mle_table, prove_inner, prove_outer, verify_finalize, verify_inner, verify_outer,
    verify_parse_commitment, DomainSeparator, EqPolynomial, InnerSumcheckProof, MlePcs,
    MultilinearPoint, NoopObserver, OuterSumcheckProof, PcsStatementBuilder, PointEvalClaim,
    ProtocolObserver, ProtocolStage, R1csInstance, R1csShape, R1csWitness, SecurityConfig,
    SpartanWhirEngine, SpartanWhirError, WhirParams, WhirPcs, WhirPcsConfig,
};

pub struct ProvingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub shape_canonical: R1csShape<E::F>,
    pub num_cons_unpadded: usize,
    pub num_vars_unpadded: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub pcs_config: Pcs::Config,
    pub domain_separator: DomainSeparator,
    pub observer: Option<NoopObserver>,
    marker: PhantomData<(E, Pcs)>,
}

pub struct VerifyingKey<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    pub shape_canonical: R1csShape<E::F>,
    pub num_cons_unpadded: usize,
    pub num_vars_unpadded: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub pcs_config: Pcs::Config,
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

pub struct SpartanProtocol<E: SpartanWhirEngine, Pcs: MlePcs<E>> {
    marker: PhantomData<(E, Pcs)>,
}

impl SpartanProtocol<KoalaKeccakEngine, WhirPcs> {
    pub fn setup(
        shape: &R1csShape<KoalaField>,
        security: &SecurityConfig,
        whir_params: &WhirParams,
        pcs_config: &WhirPcsConfig,
    ) -> Result<
        (
            ProvingKey<KoalaKeccakEngine, WhirPcs>,
            VerifyingKey<KoalaKeccakEngine, WhirPcs>,
        ),
        SpartanWhirError,
    > {
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

        let domain_separator = DomainSeparator::new(&shape_canonical, security, whir_params);

        let pk = ProvingKey {
            shape_canonical: shape_canonical.clone(),
            num_cons_unpadded: shape.num_cons,
            num_vars_unpadded: shape.num_vars,
            num_io: shape.num_io,
            security: *security,
            whir_params: *whir_params,
            pcs_config: canonical_pcs_config,
            domain_separator: domain_separator.clone(),
            observer: Some(NoopObserver),
            marker: PhantomData,
        };

        let vk = VerifyingKey {
            shape_canonical,
            num_cons_unpadded: shape.num_cons,
            num_vars_unpadded: shape.num_vars,
            num_io: shape.num_io,
            security: *security,
            whir_params: *whir_params,
            pcs_config: canonical_pcs_config,
            domain_separator,
            observer: Some(NoopObserver),
            marker: PhantomData,
        };

        observer.on_stage(ProtocolStage::SetupEnd);
        Ok((pk, vk))
    }

    pub fn prove(
        pk: &ProvingKey<KoalaKeccakEngine, WhirPcs>,
        public_inputs: &[KoalaField],
        witness: &R1csWitness<KoalaField>,
        challenger: &mut <KoalaKeccakEngine as SpartanWhirEngine>::Challenger,
    ) -> Result<
        (
            R1csInstance<KoalaField, <WhirPcs as MlePcs<KoalaKeccakEngine>>::Commitment>,
            SpartanProof<KoalaKeccakEngine, WhirPcs>,
        ),
        SpartanWhirError,
    > {
        let mut observer = pk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::ProveStart);

        if public_inputs.len() != pk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }
        if witness.w.len() != pk.num_vars_unpadded {
            return Err(SpartanWhirError::InvalidWitnessLength);
        }

        observe_spartan_context(challenger, &pk.domain_separator, public_inputs)?;

        let mut witness_padded = witness.w.clone();
        witness_padded.resize(pk.shape_canonical.num_vars, KoalaField::ZERO);
        let witness_mle = pk.shape_canonical.witness_to_mle(&witness_padded)?;

        observer.on_stage(ProtocolStage::PcsCommit);
        let (witness_commitment, prover_data) =
            WhirPcs::commit(&pk.pcs_config, &witness_mle, challenger)?;
        let instance = R1csInstance {
            public_inputs: public_inputs.to_vec(),
            witness_commitment,
        };

        let z_witness_half = witness_padded;
        let z_public_half = build_public_half(pk.shape_canonical.num_vars, public_inputs);
        let z_full = [z_witness_half.clone(), z_public_half.clone()].concat();
        let z_short = build_matrix_z(&z_witness_half, public_inputs);

        let (az_f, bz_f, cz_f) = pk.shape_canonical.multiply_vec(&z_short)?;
        let az: Vec<KoalaExtension> = az_f.iter().map(|&v| KoalaExtension::from(v)).collect();
        let bz: Vec<KoalaExtension> = bz_f.iter().map(|&v| KoalaExtension::from(v)).collect();
        let cz: Vec<KoalaExtension> = cz_f.iter().map(|&v| KoalaExtension::from(v)).collect();

        let num_rounds_x = pk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec(challenger, num_rounds_x);
        let tau_point = MultilinearPoint(tau.clone());

        let (outer_sumcheck, r_x, outer_claims) = prove_outer::<KoalaField, KoalaExtension, _>(
            &pk.shape_canonical,
            &az,
            &bz,
            &cz,
            &tau_point,
            challenger,
        )?;

        challenger.observe_algebra_slice(&[outer_claims.0, outer_claims.1, outer_claims.2]);
        let r = challenger.sample_algebra_element::<KoalaExtension>();
        let claim_inner_joint = outer_claims.0 + r * outer_claims.1 + r * r * outer_claims.2;

        let t_x = EqPolynomial::evals_from_point(&r_x.0);
        let (evals_a, evals_b, evals_c) =
            pk.shape_canonical.bind_row_vars::<KoalaExtension>(&t_x)?;
        let poly_abc: Vec<KoalaExtension> = evals_a
            .iter()
            .zip(evals_b.iter())
            .zip(evals_c.iter())
            .map(|((&a, &b), &c)| a + r * b + r * r * c)
            .collect();
        let z_lifted: Vec<KoalaExtension> =
            z_full.iter().map(|&v| KoalaExtension::from(v)).collect();

        let (inner_sumcheck, r_y, eval_z) = prove_inner::<KoalaField, KoalaExtension, _>(
            &pk.shape_canonical,
            claim_inner_joint,
            &poly_abc,
            &z_lifted,
            challenger,
        )?;

        let eval_x_table = public_half_as_extension(pk.shape_canonical.num_vars, public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let witness_eval = recover_witness_eval(r_y.0[0], eval_z, eval_x)?;

        let pcs_statement = PcsStatementBuilder::<KoalaKeccakEngine>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: witness_eval,
            })
            .finalize()?;

        observer.on_stage(ProtocolStage::PcsOpen);
        let pcs_proof = WhirPcs::open(&pk.pcs_config, prover_data, &pcs_statement, challenger)?;
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
        vk: &VerifyingKey<KoalaKeccakEngine, WhirPcs>,
        instance: &R1csInstance<KoalaField, <WhirPcs as MlePcs<KoalaKeccakEngine>>::Commitment>,
        proof: &SpartanProof<KoalaKeccakEngine, WhirPcs>,
        challenger: &mut <KoalaKeccakEngine as SpartanWhirEngine>::Challenger,
    ) -> Result<(), SpartanWhirError> {
        let mut observer = vk.observer.unwrap_or_default();
        observer.on_stage(ProtocolStage::VerifyStart);

        if instance.public_inputs.len() != vk.num_io {
            return Err(SpartanWhirError::InvalidPublicInputLength);
        }

        observe_spartan_context(challenger, &vk.domain_separator, &instance.public_inputs)?;

        observer.on_stage(ProtocolStage::PcsVerify);
        let parsed_commitment = verify_parse_commitment(
            &vk.pcs_config,
            &instance.witness_commitment,
            &proof.pcs_proof,
            challenger,
        )?;

        let num_rounds_x = vk.shape_canonical.num_cons.ilog2() as usize;
        let tau = sample_algebra_vec(challenger, num_rounds_x);
        let (r_x, final_outer_claim) = verify_outer::<KoalaField, KoalaExtension, _>(
            &proof.outer_sumcheck,
            KoalaExtension::ZERO,
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
        let r = challenger.sample_algebra_element::<KoalaExtension>();
        let claim_inner_joint =
            proof.outer_claims.0 + r * proof.outer_claims.1 + r * r * proof.outer_claims.2;

        let num_rounds_y = vk.shape_canonical.num_vars.ilog2() as usize + 1;
        let (r_y, inner_final_claim) = verify_inner::<KoalaField, KoalaExtension, _>(
            &proof.inner_sumcheck,
            claim_inner_joint,
            num_rounds_y,
            challenger,
        )?;

        let t_x = EqPolynomial::evals_from_point(&r_x.0);
        let t_y = EqPolynomial::evals_from_point(&r_y.0);
        let (eval_a, eval_b, eval_c) = vk
            .shape_canonical
            .evaluate_with_tables::<KoalaExtension>(&t_x, &t_y)?;

        let eval_x_table =
            public_half_as_extension(vk.shape_canonical.num_vars, &instance.public_inputs);
        let eval_x = evaluate_mle_table(&eval_x_table, &r_y.0[1..])?;
        let eval_z = (KoalaExtension::ONE - r_y.0[0]) * proof.witness_eval + r_y.0[0] * eval_x;
        let expected_inner = (eval_a + r * eval_b + r * r * eval_c) * eval_z;
        if inner_final_claim != expected_inner {
            return Err(SpartanWhirError::SumcheckFailed);
        }

        let pcs_statement = PcsStatementBuilder::<KoalaKeccakEngine>::new()
            .add_point_eval(PointEvalClaim {
                point: MultilinearPoint(r_y.0[1..].to_vec()),
                value: proof.witness_eval,
            })
            .finalize()?;

        verify_finalize(
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

fn observe_spartan_context(
    challenger: &mut <KoalaKeccakEngine as SpartanWhirEngine>::Challenger,
    domain_separator: &DomainSeparator,
    public_inputs: &[KoalaField],
) -> Result<(), SpartanWhirError> {
    let digest_bytes = Keccak256Hash {}.hash_iter(domain_separator.to_bytes());
    let digest_hash: Hash<KoalaField, u8, 32> = digest_bytes.into();
    challenger.observe(digest_hash);
    for &input in public_inputs {
        challenger.observe(input);
    }
    Ok(())
}

fn sample_algebra_vec(
    challenger: &mut <KoalaKeccakEngine as SpartanWhirEngine>::Challenger,
    len: usize,
) -> Vec<KoalaExtension> {
    (0..len)
        .map(|_| challenger.sample_algebra_element::<KoalaExtension>())
        .collect()
}

fn build_public_half(num_vars: usize, public_inputs: &[KoalaField]) -> Vec<KoalaField> {
    let mut out = vec![KoalaField::ZERO; num_vars];
    out[0] = KoalaField::ONE;
    for (i, &x) in public_inputs.iter().enumerate() {
        out[i + 1] = x;
    }
    out
}

fn public_half_as_extension(num_vars: usize, public_inputs: &[KoalaField]) -> Vec<KoalaExtension> {
    build_public_half(num_vars, public_inputs)
        .into_iter()
        .map(KoalaExtension::from)
        .collect()
}

fn build_matrix_z(witness: &[KoalaField], public_inputs: &[KoalaField]) -> Vec<KoalaField> {
    let mut z = Vec::with_capacity(witness.len() + 1 + public_inputs.len());
    z.extend_from_slice(witness);
    z.push(KoalaField::ONE);
    z.extend_from_slice(public_inputs);
    z
}

fn eq_point_eval(a: &[KoalaExtension], b: &[KoalaExtension]) -> KoalaExtension {
    a.iter()
        .zip(b.iter())
        .fold(KoalaExtension::ONE, |acc, (&x, &y)| {
            acc * ((KoalaExtension::ONE - x) * (KoalaExtension::ONE - y) + x * y)
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
    use crate::KoalaExtension;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn recover_witness_eval_rejects_non_invertible_denominator() {
        let result = recover_witness_eval(
            KoalaExtension::ONE,
            KoalaExtension::ONE,
            KoalaExtension::ONE,
        );
        assert_eq!(result, Err(crate::SpartanWhirError::NonInvertibleElement));
    }

    #[test]
    fn recover_witness_eval_matches_formula() {
        let r0 = KoalaExtension::from(crate::KoalaField::from_u32(5));
        let eval_z = KoalaExtension::from(crate::KoalaField::from_u32(17));
        let eval_x = KoalaExtension::from(crate::KoalaField::from_u32(3));
        let got = recover_witness_eval(r0, eval_z, eval_x).unwrap();

        let recomposed = (KoalaExtension::ONE - r0) * got + r0 * eval_x;
        assert_eq!(recomposed, eval_z);
    }
}
