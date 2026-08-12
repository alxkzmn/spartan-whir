use spartan_whir::{
    Plonky3HidingWhirPcs, PoseidonEngine, QuarticBinExtension, SpartanProtocol,
};

type Hidden = SpartanProtocol<PoseidonEngine<QuarticBinExtension>, Plonky3HidingWhirPcs>;

fn main() {
    let _ = Hidden::prove;
}
