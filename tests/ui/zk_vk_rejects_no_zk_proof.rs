use spartan_whir::{
    PoseidonProof, PoseidonZkVerifyingKey, QuarticBinExtension,
};

fn reject(
    vk: &PoseidonZkVerifyingKey<QuarticBinExtension>,
    proof: &PoseidonProof<QuarticBinExtension>,
) {
    let _ = vk.verify(proof);
}

fn main() {}
