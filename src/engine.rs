use core::marker::PhantomData;

use p3_challenger::DuplexChallenger;
use p3_field::{
    extension::{BinomialExtensionField, QuinticTrinomialExtensionField},
    BasedVectorSpace, ExtensionField, Field, TwoAdicField,
};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, default_koalabear_poseidon2_24, KoalaBear, Poseidon2KoalaBear,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use crate::hashers::{Keccak256NodeCompress, KeccakFieldLeafHasher};
use crate::SpartanWhirEngine;
use crate::{CanonicalKeccakChallenger32, KeccakByteChallenger};

pub type F = KoalaBear;
pub type QuarticBinExtension = BinomialExtensionField<F, 4>;
pub type OcticBinExtension = BinomialExtensionField<F, 8>;
pub type QuinticExtension = QuinticTrinomialExtensionField<F>;
pub type KeccakFieldHash = KeccakFieldLeafHasher;
pub type KeccakNodeCompress = Keccak256NodeCompress;
pub type KeccakChallenger = CanonicalKeccakChallenger32<F>;
pub type Poseidon16 = Poseidon2KoalaBear<16>;
pub type Poseidon24 = Poseidon2KoalaBear<24>;
pub type PoseidonFieldHash = PaddingFreeSponge<Poseidon24, 24, 16, 8>;
pub type PoseidonNodeCompress = TruncatedPermutation<Poseidon16, 2, 8, 16>;
pub type PoseidonChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoseidonEngine<EF>(PhantomData<EF>);

pub type KeccakQuarticEngine = KeccakEngine<QuarticBinExtension>;
pub type KeccakOcticEngine = KeccakEngine<OcticBinExtension>;
pub type KeccakQuinticEngine = KeccakEngine<QuinticExtension>;
pub type PoseidonQuarticEngine = PoseidonEngine<QuarticBinExtension>;
pub type PoseidonOcticEngine = PoseidonEngine<OcticBinExtension>;
/// Quartic and quintic engines are intentionally distinct types at the API boundary.
///
/// ```compile_fail
/// use spartan_whir::{
///     Plonky3WhirPcs, PoseidonQuarticEngine, PoseidonQuinticEngine, SpartanProof,
/// };
///
/// fn needs_quintic(_proof: SpartanProof<PoseidonQuinticEngine, Plonky3WhirPcs>) {}
///
/// let take_quartic: fn(SpartanProof<PoseidonQuarticEngine, Plonky3WhirPcs>) = needs_quintic;
/// ```
pub type PoseidonQuinticEngine = PoseidonEngine<QuinticExtension>;

impl<Ext: ExtField> SpartanWhirEngine for KeccakEngine<Ext> {
    type F = F;
    type EF = Ext;
    type Challenger = KeccakChallenger;
    type Hash = KeccakFieldHash;
    type Compress = KeccakNodeCompress;
    type W = u64;
    type PackedF = F;
    type PackedW = u64;

    const DIGEST_ELEMS: usize = 4;
}

impl<Ext: ExtField> SpartanWhirEngine for PoseidonEngine<Ext> {
    type F = F;
    type EF = Ext;
    type Challenger = PoseidonChallenger;
    type Hash = PoseidonFieldHash;
    type Compress = PoseidonNodeCompress;
    type W = F;
    type PackedF = <F as Field>::Packing;
    type PackedW = <F as Field>::Packing;

    const DIGEST_ELEMS: usize = 8;
}

pub fn keccak_challenger() -> KeccakChallenger {
    KeccakChallenger::new(KeccakByteChallenger::default())
}

pub fn poseidon_merkle_hash() -> PoseidonFieldHash {
    PoseidonFieldHash::new(default_koalabear_poseidon2_24())
}

pub fn poseidon_merkle_compress() -> PoseidonNodeCompress {
    PoseidonNodeCompress::new(default_koalabear_poseidon2_16())
}

pub fn poseidon_challenger() -> PoseidonChallenger {
    PoseidonChallenger::new(default_koalabear_poseidon2_16())
}
