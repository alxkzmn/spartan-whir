mod common;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use spartan_whir::{
    decode_spartan_blob_v1, encode_spartan_blob_v1, encode_spartan_blob_v1_with_report,
    engine::{ExtField, F},
    observe_whir_fs_domain_separator, profile_spartan_blob_v1, KeccakEngine, MlePcs,
    MultilinearPoint, PcsStatementBuilder, PointEvalClaim, ProofCodecConfig, QuarticBinExtension,
    QuinticExtension, SpartanBlobDecodeContext, SpartanProtocol, SpartanWhirError, WhirParams,
    WhirPcs, WhirPcsConfig,
};
use whir_p3::poly::{
    evals::EvaluationsList as WhirEvaluations, multilinear::MultilinearPoint as WhirPoint,
};

fn test_whir_config(num_variables: usize) -> WhirPcsConfig {
    WhirPcsConfig {
        num_variables,
        security: common::phase3_security(),
        whir: WhirParams {
            pow_bits: 0,
            folding_factor: 1,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 1,
        },
        sumcheck_strategy: common::phase3_pcs_config().sumcheck_strategy,
    }
}

fn sample_poly(num_variables: usize) -> Vec<F> {
    (0..(1 << num_variables))
        .map(|i| F::from_u32((i + 1) as u32))
        .collect()
}

fn statement_with_seed<Ext>(
    poly: &[F],
    num_variables: usize,
    seed: u32,
) -> spartan_whir::PcsStatement<KeccakEngine<Ext>>
where
    Ext: ExtField,
{
    let point = WhirPoint::expand_from_univariate(Ext::from(F::from_u32(seed)), num_variables);
    let value = WhirEvaluations::new(poly.to_vec()).evaluate_hypercube_base(&point);

    PcsStatementBuilder::<KeccakEngine<Ext>>::new()
        .add_point_eval(PointEvalClaim {
            point: MultilinearPoint(point.as_slice().to_vec()),
            value,
        })
        .finalize()
        .expect("point-eval statement must finalize")
}

fn prove_fixture<Ext>() -> (
    spartan_whir::VerifyingKey<KeccakEngine<Ext>, WhirPcs>,
    spartan_whir::R1csInstance<F, [u64; 4]>,
    spartan_whir::SpartanProof<KeccakEngine<Ext>, WhirPcs>,
    WhirPcsConfig,
)
where
    Ext: ExtField,
{
    let shape = common::koala_shape_single_constraint(2);
    let (pk, vk) = SpartanProtocol::<KeccakEngine<Ext>, WhirPcs>::setup(
        &shape,
        &common::phase3_security(),
        &common::phase3_whir_params(),
        &common::phase3_pcs_config(),
    )
    .expect("setup succeeds");

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (instance, proof) = SpartanProtocol::<KeccakEngine<Ext>, WhirPcs>::prove(
        &pk,
        &common::koala_public_inputs(9),
        &common::koala_witness(9),
        &mut prover_challenger,
    )
    .expect("prove succeeds");

    let pcs_config = vk.pcs_config;
    (vk, instance, proof, pcs_config)
}

fn witness_eval_section_len(blob: &[u8]) -> usize {
    const HEADER_PREFIX_BYTES: usize = 4 + 2 + 2 + 1 + 1 + 1;
    const WITNESS_EVAL_SECTION_INDEX: usize = 4;
    let offset = HEADER_PREFIX_BYTES + (WITNESS_EVAL_SECTION_INDEX * 4);
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&blob[offset..offset + 4]);
    u32::from_be_bytes(bytes) as usize
}

#[test]
fn whir_pcs_supports_quartic_and_quintic_extensions() {
    fn run<Ext>()
    where
        Ext: ExtField,
    {
        let config = test_whir_config(6);
        let poly = sample_poly(config.num_variables);
        let statement = statement_with_seed::<Ext>(&poly, config.num_variables, 7);

        let mut prover_challenger = spartan_whir::new_keccak_challenger();
        let (commitment, prover_data) =
            <WhirPcs as MlePcs<KeccakEngine<Ext>>>::commit(&config, &poly, &mut prover_challenger)
                .expect("commit succeeds");
        let proof = <WhirPcs as MlePcs<KeccakEngine<Ext>>>::open(
            &config,
            prover_data,
            &statement,
            &mut prover_challenger,
        )
        .expect("open succeeds");

        let mut verifier_challenger = spartan_whir::new_keccak_challenger();
        let verified = <WhirPcs as MlePcs<KeccakEngine<Ext>>>::verify(
            &config,
            &commitment,
            &statement,
            &proof,
            &mut verifier_challenger,
        );
        assert_eq!(verified, Ok(()));
    }

    run::<QuarticBinExtension>();
    run::<QuinticExtension>();
}

#[test]
fn spartan_protocol_supports_quartic_and_quintic_extensions() {
    fn run<Ext>()
    where
        Ext: ExtField,
    {
        let (vk, instance, proof, _) = prove_fixture::<Ext>();
        let mut verifier_challenger = spartan_whir::new_keccak_challenger();
        let verified = SpartanProtocol::<KeccakEngine<Ext>, WhirPcs>::verify(
            &vk,
            &instance,
            &proof,
            &mut verifier_challenger,
        );
        assert_eq!(verified, Ok(()));
    }

    run::<QuarticBinExtension>();
    run::<QuinticExtension>();
}

#[test]
fn codec_v1_roundtrip_and_profile_support_quartic_and_quintic_extensions() {
    fn run<Ext>(expected_degree: usize, expected_witness_eval_bytes: usize)
    where
        Ext: ExtField,
    {
        let codec = ProofCodecConfig::default();
        let (vk, instance, proof, pcs_config) = prove_fixture::<Ext>();

        let blob = encode_spartan_blob_v1(&codec, &pcs_config, &instance, &proof)
            .expect("encode succeeds");
        let ctx = SpartanBlobDecodeContext::from_vk(&vk).expect("decode context derives from vk");
        assert_eq!(ctx.expected_extension_degree, expected_degree);
        assert_eq!(blob[9] as usize, expected_degree);
        assert_eq!(witness_eval_section_len(&blob), expected_witness_eval_bytes);

        let (decoded_instance, decoded_proof) =
            decode_spartan_blob_v1(&codec, &ctx, &blob).expect("decode succeeds");

        let mut verifier_challenger = spartan_whir::new_keccak_challenger();
        let verified = SpartanProtocol::<KeccakEngine<Ext>, WhirPcs>::verify(
            &vk,
            &decoded_instance,
            &decoded_proof,
            &mut verifier_challenger,
        );
        assert_eq!(verified, Ok(()));

        let (_, report) =
            encode_spartan_blob_v1_with_report(&codec, &pcs_config, &instance, &proof)
                .expect("profiled encode succeeds");
        let profile = profile_spartan_blob_v1(&codec, &pcs_config, &instance, &proof)
            .expect("profile succeeds");
        assert_eq!(profile, report);
    }

    run::<QuarticBinExtension>(4, 16);
    run::<QuinticExtension>(5, 20);
}

#[test]
fn codec_v1_rejects_mismatched_extension_contexts() {
    let codec = ProofCodecConfig::default();

    let (quartic_vk, quartic_instance, quartic_proof, quartic_pcs_config) =
        prove_fixture::<QuarticBinExtension>();
    let (quintic_vk, quintic_instance, quintic_proof, quintic_pcs_config) =
        prove_fixture::<QuinticExtension>();

    let quartic_blob = encode_spartan_blob_v1(
        &codec,
        &quartic_pcs_config,
        &quartic_instance,
        &quartic_proof,
    )
    .expect("quartic encode succeeds");
    let quintic_blob = encode_spartan_blob_v1(
        &codec,
        &quintic_pcs_config,
        &quintic_instance,
        &quintic_proof,
    )
    .expect("quintic encode succeeds");

    let quartic_ctx = SpartanBlobDecodeContext::from_vk(&quartic_vk).expect("quartic ctx");
    let quintic_ctx = SpartanBlobDecodeContext::from_vk(&quintic_vk).expect("quintic ctx");

    let quartic_under_quintic = decode_spartan_blob_v1(&codec, &quintic_ctx, &quartic_blob);
    assert!(matches!(
        quartic_under_quintic,
        Err(SpartanWhirError::InvalidBlobHeader)
    ));

    let quintic_under_quartic = decode_spartan_blob_v1(&codec, &quartic_ctx, &quintic_blob);
    assert!(matches!(
        quintic_under_quartic,
        Err(SpartanWhirError::InvalidBlobHeader)
    ));
}

#[test]
fn quintic_live_whir_limit_accepts_boundary_and_rejects_above() {
    let boundary = test_whir_config(24);
    let mut boundary_challenger = spartan_whir::new_keccak_challenger();
    let boundary_result =
        observe_whir_fs_domain_separator::<QuinticExtension>(&boundary, &mut boundary_challenger);
    assert_eq!(boundary_result, Ok(()));

    let above = test_whir_config(25);
    let mut above_challenger = spartan_whir::new_keccak_challenger();
    let above_result =
        observe_whir_fs_domain_separator::<QuinticExtension>(&above, &mut above_challenger);
    assert_eq!(above_result, Err(SpartanWhirError::InvalidConfig));
}

#[test]
fn engine_aliases_match_expected_extension_dimensions() {
    let quartic_degree = <QuarticBinExtension as BasedVectorSpace<F>>::DIMENSION;
    let quintic_degree = <QuinticExtension as BasedVectorSpace<F>>::DIMENSION;

    assert_eq!(quartic_degree, 4);
    assert_eq!(quintic_degree, 5);
}
