//! Keccak-backed challenger used by the production `spartan-whir` engine.
//!
//! This mirrors Plonky3's `HashChallenger<u8, Keccak256Hash, 32>` byte
//! semantics while keeping the current chained byte state locally visible to
//! the grinder. The important invariant is that `input_buffer` is not the full
//! transcript history: after a sampling flush it is replaced by the 32-byte
//! Keccak digest, which becomes the chained state for future observations.
//!
//! The optimized grinder depends on that invariant. It checks a candidate by
//! hashing `current_chained_state || witness_le` directly instead of cloning the
//! whole challenger and observing the witness into the clone.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeField32};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, Hash, Permutation};
use p3_util::log2_ceil_u64;
use tracing::instrument;

const KECCAK_RATE_BYTES: usize = 136;
const KECCAK_STATE_BYTES: usize = 200;
const KECCAK_DIGEST_BYTES: usize = 32;

/// Byte challenger with the same observe/sample behavior as Plonky3's
/// `HashChallenger<u8, Keccak256Hash, 32>`.
///
/// `output_buffer` is stored as a fixed array, but sampling still consumes it
/// from the tail. This tail-pop order is transcript-visible because
/// `sample_array()` receives bytes in pop order.
#[derive(Clone, Debug, Default)]
pub struct KeccakByteChallenger {
    input_buffer: Vec<u8>,
    output_buffer: [u8; KECCAK_DIGEST_BYTES],
    output_len: usize,
}

impl KeccakByteChallenger {
    /// Constructs a challenger from an existing chained byte state.
    ///
    /// Callers should pass the current `HashChallenger`-style chained state,
    /// not a replay of all observed transcript bytes.
    #[must_use]
    pub const fn new(initial_state: Vec<u8>) -> Self {
        Self {
            input_buffer: initial_state,
            output_buffer: [0; KECCAK_DIGEST_BYTES],
            output_len: 0,
        }
    }

    fn flush(&mut self) {
        // `HashChallenger::flush` drains the current input, hashes it, stores
        // the digest as the next chained input, and exposes the same digest for
        // tail-pop sampling.
        let output = keccak256(&self.input_buffer);
        self.input_buffer.clear();
        self.input_buffer.extend_from_slice(&output);
        self.output_buffer = output;
        self.output_len = KECCAK_DIGEST_BYTES;
    }

    /// Checks a base-field PoW witness without cloning the challenger.
    ///
    /// The witness is already a canonical `u32`; it is encoded as four
    /// little-endian bytes before hashing, matching `CanObserve<F>` below.
    #[must_use]
    pub fn check_witness_u32(&self, bits: usize, witness: u32) -> bool {
        check_witness_in_prefix(&self.input_buffer, bits, witness)
    }

    /// Checks a witness against an explicit chained prefix.
    ///
    /// This is the production predicate used by the optimized grinder. It uses
    /// Plonky3's `Keccak256Hash::hash_iter_slices` to avoid allocating
    /// `prefix || witness_le`.
    #[must_use]
    pub fn check_witness_in_prefix(prefix: &[u8], bits: usize, witness: u32) -> bool {
        check_witness_in_prefix(prefix, bits, witness)
    }

    /// Benchmark-only candidate check using the local fixed-state Keccak code.
    ///
    /// This remains public so the benchmark can compare it against the faster
    /// `hash_iter_slices` predicate. Production grinding uses
    /// [`Self::check_witness_in_prefix`].
    #[must_use]
    pub fn check_witness_in_prefix_fixed_state(prefix: &[u8], bits: usize, witness: u32) -> bool {
        check_witness_in_prefix_fixed_state(prefix, bits, witness)
    }
}

impl CanObserve<u8> for KeccakByteChallenger {
    fn observe(&mut self, value: u8) {
        // Any pending output was derived before this observation, so it must no
        // longer be sampled.
        self.output_len = 0;
        self.input_buffer.push(value);
    }

    fn observe_slice(&mut self, values: &[u8]) {
        if values.is_empty() {
            return;
        }
        self.output_len = 0;
        self.input_buffer.extend_from_slice(values);
    }
}

impl<const N: usize> CanObserve<[u8; N]> for KeccakByteChallenger {
    fn observe(&mut self, values: [u8; N]) {
        if N == 0 {
            return;
        }
        self.output_len = 0;
        self.input_buffer.extend_from_slice(&values);
    }
}

impl CanSample<u8> for KeccakByteChallenger {
    fn sample(&mut self) -> u8 {
        if self.output_len == 0 {
            self.flush();
        }
        // Match `Vec::pop` on `HashChallenger`'s output buffer.
        self.output_len -= 1;
        self.output_buffer[self.output_len]
    }
}

/// Field-aware wrapper over [`KeccakByteChallenger`].
///
/// This is a local equivalent of `CanonicalSerializingChallenger32<F, _>` for
/// the concrete Keccak byte challenger. Field observations use canonical
/// little-endian `u32` bytes, which is the transcript convention expected by
/// the Solidity verifier.
#[derive(Clone, Debug)]
pub struct CanonicalKeccakChallenger32<F> {
    inner: KeccakByteChallenger,
    _marker: PhantomData<F>,
}

impl<F: PrimeField32> CanonicalKeccakChallenger32<F> {
    /// Wraps a byte challenger in canonical field serialization.
    #[must_use]
    pub const fn new(inner: KeccakByteChallenger) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    /// Constructs the challenger from a current chained byte state.
    ///
    /// This exists mostly for semantic tests against the clone-based reference
    /// challenger.
    #[must_use]
    pub const fn from_chained_state(initial_state: Vec<u8>) -> Self {
        Self::new(KeccakByteChallenger::new(initial_state))
    }

    /// Checks a canonical `u32` witness against the current chained state.
    #[must_use]
    pub fn check_witness_u32(&self, bits: usize, witness: u32) -> bool {
        self.inner.check_witness_u32(bits, witness)
    }
}

impl<F: PrimeField32> CanObserve<F> for CanonicalKeccakChallenger32<F> {
    fn observe(&mut self, value: F) {
        self.inner
            .observe_slice(&value.as_canonical_u32().to_le_bytes());
    }
}

impl<F: PrimeField32, const N: usize> CanObserve<Hash<F, u8, N>>
    for CanonicalKeccakChallenger32<F>
{
    fn observe(&mut self, values: Hash<F, u8, N>) {
        for value in values {
            self.inner.observe(value);
        }
    }
}

impl<F: PrimeField32, const N: usize> CanObserve<Hash<F, u64, N>>
    for CanonicalKeccakChallenger32<F>
{
    fn observe(&mut self, values: Hash<F, u64, N>) {
        for value in values {
            self.inner.observe_slice(&value.to_le_bytes());
        }
    }
}

impl<F, EF> CanSample<EF> for CanonicalKeccakChallenger32<F>
where
    F: PrimeField32,
    EF: BasedVectorSpace<F>,
{
    fn sample(&mut self) -> EF {
        let modulus = F::ORDER_U32;
        let log_size = log2_ceil_u64(F::ORDER_U64);
        let pow_of_two_bound = ((1u64 << log_size) - 1) as u32;
        let sample_base = |inner: &mut KeccakByteChallenger| loop {
            let value = u32::from_le_bytes(inner.sample_array());
            let value = value & pow_of_two_bound;
            if value < modulus {
                return unsafe { F::from_canonical_unchecked(value) };
            }
        };
        EF::from_basis_coefficients_fn(|_| sample_base(&mut self.inner))
    }
}

impl<F> CanSampleBits<usize> for CanonicalKeccakChallenger32<F>
where
    F: PrimeField32,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) <= F::ORDER_U64 as usize);
        let rand_usize = u32::from_le_bytes(self.inner.sample_array()) as usize;
        rand_usize & ((1 << bits) - 1)
    }
}

impl<F> GrindingChallenger for CanonicalKeccakChallenger32<F>
where
    F: PrimeField32,
{
    type Witness = F;

    #[instrument(name = "grind for proof-of-work witness", skip_all)]
    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < (usize::BITS as usize));
        assert!((1 << bits) < F::ORDER_U32);
        if bits == 0 {
            let witness = F::ZERO;
            assert!(self.check_witness(bits, witness));
            return witness;
        }

        let witness = (0..F::ORDER_U32)
            .into_par_iter()
            // The predicate is equivalent to `self.clone().check_witness(...)`
            // but hashes the current chained byte state plus the candidate
            // witness directly.
            .find_any(|&i| self.inner.check_witness_u32(bits, i))
            .map(|i| unsafe { F::from_canonical_unchecked(i) })
            .expect("failed to find witness");
        // Mutate the real transcript exactly as the generic implementation
        // would after it finds the witness.
        assert!(self.check_witness(bits, witness));
        witness
    }
}

impl<F> FieldChallenger<F> for CanonicalKeccakChallenger32<F> where F: PrimeField32 {}

#[must_use]
fn check_witness_in_prefix(prefix: &[u8], bits: usize, witness: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let witness_bytes = witness.to_le_bytes();
    let digest = Keccak256Hash {}.hash_iter_slices([prefix, &witness_bytes]);
    digest_tail_bits_are_zero(&digest, bits)
}

#[must_use]
fn check_witness_in_prefix_fixed_state(prefix: &[u8], bits: usize, witness: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let witness_bytes = witness.to_le_bytes();
    let digest = keccak256_concat(prefix, &witness_bytes);
    digest_tail_bits_are_zero(&digest, bits)
}

#[must_use]
fn digest_tail_bits_are_zero(digest: &[u8; KECCAK_DIGEST_BYTES], bits: usize) -> bool {
    // `HashChallenger` samples bytes by popping from the digest tail. Therefore
    // `sample_array::<4>()` returns digest bytes 31, 30, 29, 28 in that order,
    // and `SerializingChallenger32::sample_bits` interprets that array as a
    // little-endian `u32`.
    let value = u32::from_le_bytes([
        digest[KECCAK_DIGEST_BYTES - 1],
        digest[KECCAK_DIGEST_BYTES - 2],
        digest[KECCAK_DIGEST_BYTES - 3],
        digest[KECCAK_DIGEST_BYTES - 4],
    ]) as usize;
    value & ((1 << bits) - 1) == 0
}

#[must_use]
fn keccak256(input: &[u8]) -> [u8; KECCAK_DIGEST_BYTES] {
    keccak256_slices(&[input])
}

#[must_use]
fn keccak256_concat(a: &[u8], b: &[u8; 4]) -> [u8; KECCAK_DIGEST_BYTES] {
    keccak256_slices(&[a, b])
}

/// Minimal Keccak-256 implementation over borrowed byte slices.
///
/// This is kept for the fixed-state benchmark path and for checking boundary
/// behavior against Plonky3's hasher. The padding is Keccak padding
/// (`0x01 ... 0x80`), not SHA3 padding.
#[must_use]
fn keccak256_slices(slices: &[&[u8]]) -> [u8; KECCAK_DIGEST_BYTES] {
    let mut state = [0u8; KECCAK_STATE_BYTES];
    let mut block = [0u8; KECCAK_RATE_BYTES];
    let mut block_len = 0usize;

    for slice in slices {
        let mut offset = 0usize;
        while offset < slice.len() {
            let take = (KECCAK_RATE_BYTES - block_len).min(slice.len() - offset);
            block[block_len..block_len + take].copy_from_slice(&slice[offset..offset + take]);
            block_len += take;
            offset += take;

            if block_len == KECCAK_RATE_BYTES {
                absorb_block(&mut state, &block);
                KeccakF.permute_mut(&mut state);
                block.fill(0);
                block_len = 0;
            }
        }
    }

    block[block_len] ^= 0x01;
    block[KECCAK_RATE_BYTES - 1] ^= 0x80;
    absorb_block(&mut state, &block);
    KeccakF.permute_mut(&mut state);

    let mut digest = [0u8; KECCAK_DIGEST_BYTES];
    digest.copy_from_slice(&state[..KECCAK_DIGEST_BYTES]);
    digest
}

fn absorb_block(state: &mut [u8; KECCAK_STATE_BYTES], block: &[u8; KECCAK_RATE_BYTES]) {
    for i in 0..KECCAK_RATE_BYTES {
        state[i] ^= block[i];
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, CanSampleBits, GrindingChallenger, HashChallenger};
    use p3_field::integers::QuotientMap;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_keccak::Keccak256Hash;
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::CryptographicHasher;

    use super::*;
    use crate::CanonicalSerializingChallenger32;

    type ReferenceChallenger =
        CanonicalSerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256Hash, 32>>;

    fn reference_from_prefix(prefix: &[u8]) -> ReferenceChallenger {
        ReferenceChallenger::from_hasher(prefix.to_vec(), Keccak256Hash {})
    }

    #[test]
    fn keccak_matches_plonky3_hash_for_boundary_lengths() {
        for len in [0usize, 1, 31, 32, 33, 95, 96, 135, 136, 137, 271, 272] {
            let input = (0..len)
                .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
                .collect::<Vec<_>>();
            assert_eq!(keccak256(&input), Keccak256Hash {}.hash_iter(input));
        }
    }

    #[test]
    fn optimized_candidate_check_matches_reference_for_prefixes() {
        let candidates = [
            0,
            1,
            2,
            3,
            17,
            255,
            256,
            65_535,
            1_000_000,
            KoalaBear::ORDER_U32 - 1,
        ];
        for len in [0usize, 1, 31, 32, 33, 95, 96, 135, 136, 137] {
            let prefix = (0..len)
                .map(|i| (i.wrapping_mul(13).wrapping_add(9)) as u8)
                .collect::<Vec<_>>();
            let optimized =
                CanonicalKeccakChallenger32::<KoalaBear>::from_chained_state(prefix.clone());
            for bits in [0usize, 1, 8, 16, 24, 30] {
                for candidate in candidates {
                    let witness = unsafe { KoalaBear::from_canonical_unchecked(candidate) };
                    let expected = reference_from_prefix(&prefix).check_witness(bits, witness);
                    assert_eq!(
                        optimized.check_witness_u32(bits, candidate),
                        expected,
                        "len={len} bits={bits} candidate={candidate}"
                    );
                }
            }
        }
    }

    #[test]
    fn optimized_candidate_check_matches_reference_after_flush() {
        let candidates = [0, 1, 17, 65_535, KoalaBear::ORDER_U32 - 1];
        for len in [0usize, 1, 31, 32, 33, 95, 96, 135, 136, 137] {
            let prefix = (0..len)
                .map(|i| (i.wrapping_mul(7).wrapping_add(11)) as u8)
                .collect::<Vec<_>>();
            for consumed in [1usize, 2, 31, 32] {
                let mut reference = reference_from_prefix(&prefix);
                for _ in 0..consumed {
                    let _: usize = reference.sample_bits(1);
                }
                let flushes = (consumed - 1) / 8 + 1;
                let mut chained_prefix = prefix.clone();
                for _ in 0..flushes {
                    chained_prefix = keccak256(&chained_prefix).to_vec();
                }
                let optimized = CanonicalKeccakChallenger32::<KoalaBear>::from_chained_state(
                    chained_prefix.clone(),
                );
                for bits in [0usize, 1, 8, 16, 24, 30] {
                    for candidate in candidates {
                        let witness = unsafe { KoalaBear::from_canonical_unchecked(candidate) };
                        let expected = reference.clone().check_witness(bits, witness);
                        assert_eq!(
                            optimized.check_witness_u32(bits, candidate),
                            expected,
                            "len={len} consumed={consumed} bits={bits} candidate={candidate}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn local_keccak_challenger_matches_reference_sampling() {
        let mut reference = reference_from_prefix(&[]);
        let mut optimized =
            CanonicalKeccakChallenger32::<KoalaBear>::from_chained_state(Vec::new());
        for i in 0..64u32 {
            let value = KoalaBear::from_u32(i.wrapping_mul(19).wrapping_add(5));
            reference.observe(value);
            optimized.observe(value);
            if i % 7 == 0 {
                assert_eq!(
                    reference.sample_bits(30),
                    optimized.sample_bits(30),
                    "i={i}"
                );
            }
        }
        for _ in 0..64 {
            assert_eq!(reference.sample_bits(30), optimized.sample_bits(30));
        }
    }
}
