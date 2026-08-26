use spartan_whir::{PoseidonSetupConfig, PoseidonZkSetupConfig};

fn require_no_zk(_: PoseidonSetupConfig) {}
fn require_full_zk(_: PoseidonZkSetupConfig) {}

fn reject_full_zk_as_no_zk(config: PoseidonZkSetupConfig) {
    require_no_zk(config);
}

fn reject_no_zk_as_full_zk(config: PoseidonSetupConfig) {
    require_full_zk(config);
}

fn main() {}
