mod common;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use spartan_whir::{
    engine::{ExtField, F},
    evaluate_mle_table, MatrixClosingMode, MlePcs, MultilinearPoint, PcsStatementBuilder,
    Plonky3WhirPcs, PointEvalClaim, PoseidonEngine, QuarticBinExtension, QuinticExtension,
    SpartanProtocol, SpartanSnarkConfig, WhirParams, WhirPcsConfig,
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
            ..WhirParams::default()
        },
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
) -> spartan_whir::PcsStatement<PoseidonEngine<Ext>>
where
    Ext: ExtField,
{
    let point = MultilinearPoint(
        (0..num_variables)
            .map(|i| Ext::from_u32(seed + i as u32))
            .collect(),
    );
    let poly_ext = poly.iter().copied().map(Ext::from).collect::<Vec<_>>();
    let value = evaluate_mle_table(&poly_ext, &point.0).expect("point evaluates");

    PcsStatementBuilder::<PoseidonEngine<Ext>>::new()
        .add_point_eval(PointEvalClaim { point, value })
        .finalize()
        .expect("point-eval statement finalizes")
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

        let mut prover_challenger = spartan_whir::poseidon_challenger();
        let (commitment, prover_data) = <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::commit(
            &config,
            &poly,
            &mut prover_challenger,
        )
        .expect("commit succeeds");
        let proof = <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::open(
            &config,
            prover_data,
            &statement,
            &mut prover_challenger,
        )
        .expect("open succeeds");

        let mut verifier_challenger = spartan_whir::poseidon_challenger();
        <Plonky3WhirPcs as MlePcs<PoseidonEngine<Ext>>>::verify(
            &config,
            &commitment,
            &statement,
            &proof,
            &mut verifier_challenger,
        )
        .expect("verify succeeds");
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
        let shape = common::koala_shape_single_constraint(2);
        let (pk, vk) = SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::setup_with_config(
            &shape,
            &SpartanSnarkConfig {
                matrix_closing: MatrixClosingMode::DirectSparse,
                security: common::phase3_security(),
                whir_params: common::phase3_whir_params(),
                pcs_config: common::phase3_pcs_config(),
                spark_whir_params: None,
            },
        )
        .expect("setup succeeds");

        let mut prover_challenger = spartan_whir::poseidon_challenger();
        let (instance, proof) = SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::prove(
            &pk,
            &common::koala_public_inputs(9),
            &common::koala_witness(9),
            &mut prover_challenger,
        )
        .expect("prove succeeds");

        let mut verifier_challenger = spartan_whir::poseidon_challenger();
        SpartanProtocol::<PoseidonEngine<Ext>, Plonky3WhirPcs>::verify(
            &vk,
            &instance,
            &proof,
            &mut verifier_challenger,
        )
        .expect("verify succeeds");
    }

    run::<QuarticBinExtension>();
    run::<QuinticExtension>();
}

#[test]
fn engine_aliases_match_expected_extension_dimensions() {
    assert_eq!(<QuarticBinExtension as BasedVectorSpace<F>>::DIMENSION, 4);
    assert_eq!(<QuinticExtension as BasedVectorSpace<F>>::DIMENSION, 5);
}
