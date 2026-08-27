use p3_field::PrimeCharacteristicRing;
use spartan_whir::engine::F;

#[test]
fn optimized_xor3_row_determines_boolean_parity() {
    for a in 0..=1 {
        for b in 0..=1 {
            for c in 0..=1 {
                let a_f = F::from_u32(a);
                let b_f = F::from_u32(b);
                let c_f = F::from_u32(c);
                let out = F::from_u32(a ^ b ^ c);
                let factor = -F::from_u32(6)
                    + F::from_u32(3) * a_f
                    + F::from_u32(4) * b_f
                    + F::from_u32(5) * c_f;

                assert_ne!(factor, F::ZERO);
                assert_eq!(
                    factor
                        * (F::from_u32(5) * out + F::ONE
                            - F::from_u32(4) * a_f
                            - F::from_u32(3) * b_f),
                    -F::from_u32(6)
                );
            }
        }
    }
}
