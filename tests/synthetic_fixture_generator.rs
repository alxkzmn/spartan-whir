use p3_field::PrimeCharacteristicRing;

use spartan_whir::{
    engine::F, generate_satisfiable_fixture, generate_satisfiable_fixture_for_pow2,
    SpartanWhirError, SyntheticR1csConfig,
};

fn assignment_vector(witness: &[F], public_inputs: &[F]) -> Vec<F> {
    let mut z = Vec::with_capacity(witness.len() + 1 + public_inputs.len());
    z.extend_from_slice(witness);
    z.push(F::ONE);
    z.extend_from_slice(public_inputs);
    z
}

#[test]
fn generator_rejects_invalid_target_log2() {
    let cfg = SyntheticR1csConfig {
        target_log2_witness_poly: 0,
        num_constraints: 1,
        num_io: 1,
        a_terms_per_constraint: 1,
        b_terms_per_constraint: 1,
        seed: 1,
    };
    let result = generate_satisfiable_fixture(&cfg);
    assert_eq!(result, Err(SpartanWhirError::InvalidConfig));
}

#[test]
fn generator_rejects_zero_constraints() {
    let cfg = SyntheticR1csConfig {
        target_log2_witness_poly: 4,
        num_constraints: 0,
        num_io: 1,
        a_terms_per_constraint: 1,
        b_terms_per_constraint: 1,
        seed: 1,
    };
    let result = generate_satisfiable_fixture(&cfg);
    assert_eq!(result, Err(SpartanWhirError::InvalidConfig));
}

#[test]
fn generator_rejects_num_io_ge_target_size() {
    let cfg = SyntheticR1csConfig {
        target_log2_witness_poly: 3,
        num_constraints: 1,
        num_io: 8,
        a_terms_per_constraint: 1,
        b_terms_per_constraint: 1,
        seed: 1,
    };
    let result = generate_satisfiable_fixture(&cfg);
    assert_eq!(result, Err(SpartanWhirError::InvalidConfig));
}

#[test]
fn generator_rejects_terms_per_constraint_exceed_num_cols() {
    let cfg = SyntheticR1csConfig {
        target_log2_witness_poly: 1,
        num_constraints: 1,
        num_io: 1,
        a_terms_per_constraint: 100,
        b_terms_per_constraint: 1,
        seed: 1,
    };
    let result = generate_satisfiable_fixture(&cfg);
    assert_eq!(result, Err(SpartanWhirError::InvalidConfig));
}

#[test]
fn generator_outputs_shape_that_validates() {
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 8,
        num_constraints: 4,
        num_io: 2,
        a_terms_per_constraint: 3,
        b_terms_per_constraint: 5,
        seed: 42,
    })
    .expect("fixture generation succeeds");

    assert_eq!(fixture.target_log2, 8);
    assert_eq!(fixture.target_poly_size, 1 << 8);
    assert_eq!(fixture.witness.w.len(), 1 << 8);
    assert_eq!(fixture.public_inputs.len(), 2);
    assert_eq!(fixture.shape.validate(), Ok(()));
}

#[test]
fn generator_outputs_satisfiable_assignment_rowwise() {
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 8,
        num_constraints: 16,
        num_io: 3,
        a_terms_per_constraint: 4,
        b_terms_per_constraint: 4,
        seed: 7,
    })
    .expect("fixture generation succeeds");

    let z = assignment_vector(&fixture.witness.w, &fixture.public_inputs);
    let (az, bz, cz) = fixture
        .shape
        .multiply_vec(&z)
        .expect("matrix product works");
    assert_eq!(az.len(), fixture.shape.num_cons);
    assert_eq!(bz.len(), fixture.shape.num_cons);
    assert_eq!(cz.len(), fixture.shape.num_cons);

    for i in 0..fixture.shape.num_cons {
        assert_eq!(az[i] * bz[i], cz[i], "row {i} must satisfy Az*Bz=Cz");
    }
}

#[test]
fn generator_is_seed_deterministic() {
    let cfg = SyntheticR1csConfig {
        target_log2_witness_poly: 10,
        num_constraints: 8,
        num_io: 1,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 1337,
    };
    let fixture_a = generate_satisfiable_fixture(&cfg).expect("generation succeeds");
    let fixture_b = generate_satisfiable_fixture(&cfg).expect("generation succeeds");

    assert_eq!(fixture_a.shape, fixture_b.shape);
    assert_eq!(fixture_a.witness, fixture_b.witness);
    assert_eq!(fixture_a.public_inputs, fixture_b.public_inputs);
}

#[test]
fn generator_for_pow2_uses_expected_defaults() {
    let fixture = generate_satisfiable_fixture_for_pow2(6).expect("fixture generation succeeds");
    assert_eq!(fixture.target_poly_size, 1 << 6);
    assert_eq!(fixture.target_log2, 6);
    assert_eq!(fixture.shape.num_cons, 1);
    assert_eq!(fixture.shape.num_io, 1);
}
