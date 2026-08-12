use rand::{rngs::StdRng, SeedableRng};
use spartan_whir::{
    engine::F, PoseidonProvingKey, QuarticBinExtension, R1csWitness,
};

fn reject(
    pk: &PoseidonProvingKey<QuarticBinExtension>,
    witness: R1csWitness<F>,
    public_inputs: Vec<F>,
) {
    let mut rng = StdRng::seed_from_u64(7);
    let _ = pk.prove_with_rng(witness, public_inputs, &mut rng);
}

fn main() {}
