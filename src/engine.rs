use alloc::vec;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;

use crate::hashers::{Keccak256NodeCompress, KeccakFieldLeafHasher};
use crate::SpartanWhirEngine;

pub type KoalaField = KoalaBear;
pub type KoalaExtension = BinomialExtensionField<KoalaField, 4>;
pub type KoalaKeccakFieldHash = KeccakFieldLeafHasher;
pub type KoalaKeccakCompress = Keccak256NodeCompress;
pub type KoalaKeccakChallenger =
    SerializingChallenger32<KoalaField, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KoalaKeccakEngine;

impl SpartanWhirEngine for KoalaKeccakEngine {
    type F = KoalaField;
    type EF = KoalaExtension;
    type Challenger = KoalaKeccakChallenger;
    type Hash = KoalaKeccakFieldHash;
    type Compress = KoalaKeccakCompress;
    type W = u64;

    const DIGEST_ELEMS: usize = 4;
}

pub fn new_koala_keccak_merkle_hash() -> KoalaKeccakFieldHash {
    KoalaKeccakFieldHash::default()
}

pub fn new_koala_keccak_merkle_compress() -> KoalaKeccakCompress {
    KoalaKeccakCompress::default()
}

pub fn new_koala_keccak_challenger() -> KoalaKeccakChallenger {
    let inner = HashChallenger::<u8, Keccak256Hash, 32>::new(vec![], Keccak256Hash {});
    KoalaKeccakChallenger::new(inner)
}
