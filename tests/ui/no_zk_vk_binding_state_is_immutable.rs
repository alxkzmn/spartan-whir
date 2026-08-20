use spartan_whir::{PoseidonVerifyingKey, QuarticBinExtension};

fn mutate(vk: &mut PoseidonVerifyingKey<QuarticBinExtension>) {
    vk.shape_canonical.a.entries.clear();
}

fn main() {}
