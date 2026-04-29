use std::{cell::RefCell, rc::Rc};

use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use spartan_whir::{engine::F, CanonicalSerializingChallenger32, QuinticExtension};

const KOALABEAR_MODULUS: u128 = 0x7f00_0001;

#[test]
fn quintic_trinomial_is_irreducible_over_koalabear() {
    // f(X) = X^5 + X^2 - 1. A reducible degree-5 polynomial has a factor
    // of degree 1 or 2, so gcd(f, X^(p^2) - X) must be 1.
    let f = vec![F::NEG_ONE, F::ZERO, F::ONE, F::ZERO, F::ZERO, F::ONE];
    let x_p2_minus_x = poly_sub(
        &pow_x_mod(KOALABEAR_MODULUS * KOALABEAR_MODULUS, &f),
        &[F::ZERO, F::ONE],
    );
    let gcd = poly_gcd(f, x_p2_minus_x);
    assert_eq!(poly_degree(&gcd), 0);
    assert_eq!(gcd[0], F::ONE);
}

#[test]
fn quintic_trinomial_reduction_identity_matches_plonky3() {
    let x = QuinticExtension::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
    let x2 = x * x;
    let x5 = x2 * x2 * x;
    assert_eq!(x5, QuinticExtension::from(F::ONE) - x2);
}

#[test]
fn quintic_transcript_observes_exactly_five_little_endian_coefficients() {
    let value = QuinticExtension::from_basis_coefficients_fn(|i| F::from_u32((i as u32) + 1));
    let observed = Rc::new(RefCell::new(Vec::new()));
    let recorder = RecordingObserver {
        observed: observed.clone(),
    };
    let mut challenger = CanonicalSerializingChallenger32::<F, _>::new(recorder);
    for coeff in <QuinticExtension as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value) {
        challenger.observe(*coeff);
    }

    let expected: Vec<u8> = [1_u32, 2, 3, 4, 5]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(*observed.borrow(), expected);
}

#[derive(Clone, Debug)]
struct RecordingObserver {
    observed: Rc<RefCell<Vec<u8>>>,
}

impl CanObserve<u8> for RecordingObserver {
    fn observe(&mut self, value: u8) {
        self.observed.borrow_mut().push(value);
    }
}

fn pow_x_mod(mut exponent: u128, modulus: &[F]) -> Vec<F> {
    let mut result = vec![F::ONE];
    let mut base = vec![F::ZERO, F::ONE];
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = poly_mod(&poly_mul(&result, &base), modulus);
        }
        exponent >>= 1;
        if exponent > 0 {
            base = poly_mod(&poly_mul(&base, &base), modulus);
        }
    }
    result
}

fn poly_mul(a: &[F], b: &[F]) -> Vec<F> {
    let mut out = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] += ai * bj;
        }
    }
    trim(out)
}

fn poly_sub(a: &[F], b: &[F]) -> Vec<F> {
    let len = a.len().max(b.len());
    let mut out = vec![F::ZERO; len];
    for i in 0..len {
        let ai = a.get(i).copied().unwrap_or(F::ZERO);
        let bi = b.get(i).copied().unwrap_or(F::ZERO);
        out[i] = ai - bi;
    }
    trim(out)
}

fn poly_mod(poly: &[F], modulus: &[F]) -> Vec<F> {
    let mut rem = trim(poly.to_vec());
    let modulus_degree = poly_degree(modulus);
    let modulus_lead_inv = modulus[modulus_degree].inverse();

    while poly_degree(&rem) >= modulus_degree && !(rem.len() == 1 && rem[0].is_zero()) {
        let rem_degree = poly_degree(&rem);
        let shift = rem_degree - modulus_degree;
        let scale = rem[rem_degree] * modulus_lead_inv;
        for i in 0..=modulus_degree {
            rem[i + shift] -= scale * modulus[i];
        }
        rem = trim(rem);
    }

    rem
}

fn poly_gcd(mut a: Vec<F>, mut b: Vec<F>) -> Vec<F> {
    a = trim(a);
    b = trim(b);
    while !(b.len() == 1 && b[0].is_zero()) {
        let r = poly_mod(&a, &b);
        a = b;
        b = r;
    }
    let lead_inv = a[poly_degree(&a)].inverse();
    for coeff in &mut a {
        *coeff *= lead_inv;
    }
    trim(a)
}

fn poly_degree(poly: &[F]) -> usize {
    poly.iter().rposition(|coeff| !coeff.is_zero()).unwrap_or(0)
}

fn trim(mut poly: Vec<F>) -> Vec<F> {
    while poly.len() > 1 && poly.last().is_some_and(|coeff| coeff.is_zero()) {
        poly.pop();
    }
    if poly.is_empty() {
        vec![F::ZERO]
    } else {
        poly
    }
}
