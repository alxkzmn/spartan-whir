use alloc::vec;
use core::marker::PhantomData;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::{
    extension::{BinomialExtensionField, QuinticTrinomialExtensionField},
    BasedVectorSpace, ExtensionField, TwoAdicField,
};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;

use crate::hashers::{Keccak256NodeCompress, KeccakFieldLeafHasher};
use crate::SpartanWhirEngine;

pub type F = KoalaBear;
pub type QuarticBinExtension = BinomialExtensionField<F, 4>;
pub type OcticBinExtension = BinomialExtensionField<F, 8>;
pub type QuinticExtension = QuinticTrinomialExtensionField<F>;
pub type KeccakFieldHash = KeccakFieldLeafHasher;
pub type KeccakNodeCompress = Keccak256NodeCompress;
pub type KeccakChallenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

pub trait ExtField:
    ExtensionField<F> + BasedVectorSpace<F> + TwoAdicField + Copy + Send + Sync
{
}

impl<Ext> ExtField for Ext where
    Ext: ExtensionField<F> + BasedVectorSpace<F> + TwoAdicField + Copy + Send + Sync
{
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeccakEngine<EF>(PhantomData<EF>);

pub type KeccakQuarticEngine = KeccakEngine<QuarticBinExtension>;
/// Quartic and quintic engines are intentionally distinct types at the API boundary.
///
/// ```compile_fail
/// use spartan_whir::{KeccakQuarticEngine, KeccakQuinticEngine, SpartanProof, WhirPcs};
///
/// fn needs_quintic(_proof: SpartanProof<KeccakQuinticEngine, WhirPcs>) {}
///
/// let take_quartic: fn(SpartanProof<KeccakQuarticEngine, WhirPcs>) = needs_quintic;
/// ```
pub type KeccakQuinticEngine = KeccakEngine<QuinticExtension>;

impl<Ext: ExtField> SpartanWhirEngine for KeccakEngine<Ext> {
    type F = F;
    type EF = Ext;
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
