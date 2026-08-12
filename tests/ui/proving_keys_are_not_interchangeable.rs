use spartan_whir::{
    PoseidonProvingKey, PoseidonZkProvingKey, QuarticBinExtension,
};

fn require_no_zk(_: &PoseidonProvingKey<QuarticBinExtension>) {}
fn require_full_zk(_: &PoseidonZkProvingKey<QuarticBinExtension>) {}

fn reject_full_zk_as_no_zk(key: &PoseidonZkProvingKey<QuarticBinExtension>) {
    require_no_zk(key);
}

fn reject_no_zk_as_full_zk(key: &PoseidonProvingKey<QuarticBinExtension>) {
    require_full_zk(key);
}

fn main() {}
