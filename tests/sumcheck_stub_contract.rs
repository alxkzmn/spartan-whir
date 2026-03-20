mod common;

use p3_field::PrimeCharacteristicRing;

use spartan_whir::{
    engine::F, evaluate_mle_table, prove_inner, prove_outer, verify_inner, verify_outer,
    CubicRoundPoly, EqPolynomial, MultilinearPoint, QuadraticRoundPoly, QuarticBinExtension as EF,
    SpartanWhirError,
};

fn eq_eval(a: &[EF], b: &[EF]) -> EF {
    a.iter().zip(b.iter()).fold(EF::ONE, |acc, (&x, &y)| {
        acc * ((EF::ONE - x) * (EF::ONE - y) + x * y)
    })
}

#[test]
fn outer_sumcheck_roundtrip_and_tamper_detection() {
    let shape = common::koala_shape_single_constraint(2);
    let z = vec![F::from_u32(9), F::ONE, F::from_u32(9)];
    let (az_f, bz_f, cz_f) = shape.multiply_vec(&z).expect("multiply succeeds");
    let az: Vec<EF> = az_f.into_iter().map(EF::from).collect();
    let bz: Vec<EF> = bz_f.into_iter().map(EF::from).collect();
    let cz: Vec<EF> = cz_f.into_iter().map(EF::from).collect();

    let tau = MultilinearPoint(vec![EF::from(F::from_u32(7))]);
    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (proof, claims_point, claims) =
        prove_outer::<F, EF, _>(&shape, &az, &bz, &cz, &tau, &mut prover_challenger)
            .expect("outer prove succeeds");
    assert_eq!(claims_point.0.len(), 1);

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let (r_x, final_claim) =
        verify_outer::<F, EF, _>(&proof, EF::ZERO, 1, &mut verifier_challenger)
            .expect("outer verify transcript succeeds");

    let expected = eq_eval(&tau.0, &r_x.0) * (claims.0 * claims.1 - claims.2);
    assert_eq!(final_claim, expected);

    let mut tampered = proof.clone();
    tampered.rounds[0] = CubicRoundPoly([
        tampered.rounds[0].0[0] + EF::ONE,
        tampered.rounds[0].0[1],
        tampered.rounds[0].0[2],
    ]);

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let (bad_r_x, bad_final) =
        verify_outer::<F, EF, _>(&tampered, EF::ZERO, 1, &mut verifier_challenger)
            .expect("tampered transcript still parses");
    let bad_expected = eq_eval(&tau.0, &bad_r_x.0) * (claims.0 * claims.1 - claims.2);
    assert_ne!(bad_final, bad_expected);
}

#[test]
fn inner_sumcheck_roundtrip_and_round_count_guard() {
    let shape = common::koala_shape_single_constraint(2);
    let poly_abc = vec![
        EF::from(F::from_u32(1)),
        EF::from(F::from_u32(2)),
        EF::from(F::from_u32(3)),
        EF::from(F::from_u32(4)),
    ];
    let z = vec![
        EF::from(F::from_u32(5)),
        EF::from(F::from_u32(6)),
        EF::from(F::from_u32(7)),
        EF::from(F::from_u32(8)),
    ];
    let initial_claim = poly_abc
        .iter()
        .zip(z.iter())
        .fold(EF::ZERO, |acc, (&a, &b)| acc + a * b);

    let mut prover_challenger = spartan_whir::new_keccak_challenger();
    let (proof, r_y, _eval_z) =
        prove_inner::<F, EF, _>(&shape, initial_claim, &poly_abc, &z, &mut prover_challenger)
            .expect("inner prove succeeds");
    assert_eq!(proof.rounds.len(), 2);
    assert_eq!(r_y.0.len(), 2);

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let (r_y_verify, final_claim) =
        verify_inner::<F, EF, _>(&proof, initial_claim, 2, &mut verifier_challenger)
            .expect("inner verify transcript succeeds");

    let expected = evaluate_mle_table(&poly_abc, &r_y_verify.0).unwrap()
        * evaluate_mle_table(&z, &r_y_verify.0).unwrap();
    assert_eq!(final_claim, expected);

    let mut verifier_challenger = spartan_whir::new_keccak_challenger();
    let bad_round_count =
        verify_inner::<F, EF, _>(&proof, initial_claim, 1, &mut verifier_challenger);
    assert_eq!(bad_round_count, Err(SpartanWhirError::InvalidRoundCount));
}

#[test]
fn eq_polynomial_table_generation_is_consistent() {
    let point = vec![EF::from(F::from_u32(3)), EF::from(F::from_u32(5))];
    let table = EqPolynomial::evals_from_point(&point);
    assert_eq!(table.len(), 4);

    let eval = evaluate_mle_table(&table, &point).unwrap();
    assert_eq!(eval, eq_eval(&point, &point));

    let sum = table.iter().fold(EF::ZERO, |acc, &v| acc + v);
    assert_eq!(sum, EF::ONE);
}

#[test]
fn round_poly_endpoint_evaluations_match_expected_values() {
    let claim_quad = EF::from(F::from_u32(11));
    let quad = QuadraticRoundPoly([EF::from(F::from_u32(4)), EF::from(F::from_u32(9))]);
    assert_eq!(quad.evaluate_at(EF::ZERO, claim_quad), quad.eval_at_zero());
    assert_eq!(
        quad.evaluate_at(EF::ONE, claim_quad),
        quad.eval_at_one_from_claim(claim_quad)
    );
    assert_eq!(
        quad.evaluate_at(EF::from(F::from_u32(2)), claim_quad),
        quad.eval_at_two()
    );

    let claim_cubic = EF::from(F::from_u32(13));
    let cubic = CubicRoundPoly([
        EF::from(F::from_u32(3)),
        EF::from(F::from_u32(7)),
        EF::from(F::from_u32(10)),
    ]);
    assert_eq!(
        cubic.evaluate_at(EF::ZERO, claim_cubic),
        cubic.eval_at_zero()
    );
    assert_eq!(
        cubic.evaluate_at(EF::ONE, claim_cubic),
        cubic.eval_at_one_from_claim(claim_cubic)
    );
    assert_eq!(
        cubic.evaluate_at(EF::from(F::from_u32(2)), claim_cubic),
        cubic.eval_at_two()
    );
    assert_eq!(
        cubic.evaluate_at(EF::from(F::from_u32(3)), claim_cubic),
        cubic.eval_at_three()
    );
}
