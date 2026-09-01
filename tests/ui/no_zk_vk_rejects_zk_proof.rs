use spartan_whir::{
    PoseidonVerifyingKey, PoseidonZkProof, QuarticBinExtension,
};

fn reject(
    vk: &PoseidonVerifyingKey<QuarticBinExtension>,
    proof: &PoseidonZkProof<QuarticBinExtension>,
) {
    let _ = vk.verify(&[], proof);
}

fn main() {}
