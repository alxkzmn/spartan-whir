use alloc::vec;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;

use crate::hashers::{Keccak256NodeCompress, KeccakFieldLeafHasher};
use crate::SpartanWhirEngine;

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 4>;
pub type KeccakFieldHash = KeccakFieldLeafHasher;
pub type KeccakNodeCompress = Keccak256NodeCompress;
pub type KeccakChallenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeccakEngine;

impl SpartanWhirEngine for KeccakEngine {
    type F = F;
    type EF = EF;
    type Challenger = KeccakChallenger;
    type Hash = KeccakFieldHash;
    type Compress = KeccakNodeCompress;
    type W = u64;

    const DIGEST_ELEMS: usize = 4;
}

pub fn new_keccak_merkle_hash() -> KeccakFieldHash {
    KeccakFieldHash::default()
}

pub fn new_keccak_merkle_compress() -> KeccakNodeCompress {
    KeccakNodeCompress::default()
}

pub fn new_keccak_challenger() -> KeccakChallenger {
    let inner = HashChallenger::<u8, Keccak256Hash, 32>::new(vec![], Keccak256Hash {});
    KeccakChallenger::new(inner)
}
