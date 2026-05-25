use p3_field::PackedValue;

pub trait SpartanWhirEngine {
    type F;
    type EF;
    type Challenger;
    type Hash;
    type Compress;
    type W: Copy + Default;
    type PackedF: PackedValue<Value = Self::F> + Eq + Send + Sync;
    type PackedW: PackedValue<Value = Self::W> + Eq + Send + Sync;

    const DIGEST_ELEMS: usize;
}
