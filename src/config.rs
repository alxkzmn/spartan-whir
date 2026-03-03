pub trait SpartanWhirEngine {
    type F;
    type EF;
    type Challenger;
    type Hash;
    type Compress;
    type W: Copy + Default;

    const DIGEST_ELEMS: usize;
}
