use alloc::vec::Vec;

use p3_field::{PackedValue, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use whir_p3::metrics::{add_leaf_hash_call, add_node_hash_call};

pub const KECCAK_DIGEST_ELEMS: usize = 4;
const KECCAK_DIGEST_BYTES: usize = 32;

#[inline]
fn maybe_push_leaf_prefix(buf: &mut Vec<u8>) {
    #[cfg(feature = "keccak_no_prefix")]
    let _ = buf;

    #[cfg(not(feature = "keccak_no_prefix"))]
    {
        buf.push(0x00);
    }
}

#[must_use]
pub const fn effective_digest_bytes_for_security_bits(security_bits: usize) -> usize {
    let bits = security_bits.saturating_mul(2);
    let bytes = bits.div_ceil(8);
    if bytes == 0 {
        1
    } else if bytes > KECCAK_DIGEST_BYTES {
        KECCAK_DIGEST_BYTES
    } else {
        bytes
    }
}

#[must_use]
pub const fn merkle_security_bits_or_default(
    security_bits: usize,
    merkle_security_bits_override: Option<usize>,
) -> usize {
    match merkle_security_bits_override {
        Some(bits) => bits,
        None => security_bits,
    }
}

#[inline]
const fn clamp_effective_digest_bytes(effective_digest_bytes: usize) -> usize {
    if effective_digest_bytes == 0 {
        1
    } else if effective_digest_bytes > KECCAK_DIGEST_BYTES {
        KECCAK_DIGEST_BYTES
    } else {
        effective_digest_bytes
    }
}

#[inline]
fn mask_digest_tail(bytes: &mut [u8; KECCAK_DIGEST_BYTES], effective_digest_bytes: usize) {
    let keep = clamp_effective_digest_bytes(effective_digest_bytes);
    bytes[keep..].fill(0);
}

pub fn digest_to_bytes(digest: &[u64; KECCAK_DIGEST_ELEMS]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (i, word) in digest.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn digest_from_bytes(bytes: &[u8; 32]) -> [u64; KECCAK_DIGEST_ELEMS] {
    let mut out = [0_u64; KECCAK_DIGEST_ELEMS];
    for i in 0..KECCAK_DIGEST_ELEMS {
        let mut word = [0_u8; 8];
        word.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_be_bytes(word);
    }
    out
}

#[derive(Clone, Copy, Debug)]
pub struct KeccakFieldLeafHasher {
    effective_digest_bytes: usize,
}

impl KeccakFieldLeafHasher {
    #[must_use]
    pub const fn new(effective_digest_bytes: usize) -> Self {
        Self {
            effective_digest_bytes,
        }
    }

    #[must_use]
    pub const fn for_security_bits(security_bits: usize) -> Self {
        Self::new(effective_digest_bytes_for_security_bits(security_bits))
    }

    #[must_use]
    pub const fn effective_digest_bytes(&self) -> usize {
        clamp_effective_digest_bytes(self.effective_digest_bytes)
    }
}

impl Default for KeccakFieldLeafHasher {
    fn default() -> Self {
        Self::new(KECCAK_DIGEST_BYTES)
    }
}

impl<P> CryptographicHasher<P, [u64; KECCAK_DIGEST_ELEMS]> for KeccakFieldLeafHasher
where
    P: PackedValue,
    P::Value: PrimeField32,
{
    fn hash_iter<I>(&self, input: I) -> [u64; KECCAK_DIGEST_ELEMS]
    where
        I: IntoIterator<Item = P>,
    {
        let mut iter = input.into_iter();
        let mut preimage = if let Some(first) = iter.next() {
            let elems_per_packed = first.as_slice().len();
            let (lower, _) = iter.size_hint();
            let mut buf = Vec::with_capacity(1 + (lower + 1) * elems_per_packed * 4);
            maybe_push_leaf_prefix(&mut buf);
            for &x in first.as_slice() {
                buf.extend_from_slice(&x.as_canonical_u32().to_be_bytes());
            }
            buf
        } else {
            let mut buf = Vec::new();
            maybe_push_leaf_prefix(&mut buf);
            buf
        };

        for packed in iter {
            for &x in packed.as_slice() {
                preimage.extend_from_slice(&x.as_canonical_u32().to_be_bytes());
            }
        }

        add_leaf_hash_call();
        let mut bytes: [u8; 32] = Keccak256Hash.hash_iter(preimage);
        mask_digest_tail(&mut bytes, self.effective_digest_bytes());
        digest_from_bytes(&bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Keccak256NodeCompress {
    effective_digest_bytes: usize,
}

impl Keccak256NodeCompress {
    #[must_use]
    pub const fn new(effective_digest_bytes: usize) -> Self {
        Self {
            effective_digest_bytes,
        }
    }

    #[must_use]
    pub const fn for_security_bits(security_bits: usize) -> Self {
        Self::new(effective_digest_bytes_for_security_bits(security_bits))
    }

    #[must_use]
    pub const fn effective_digest_bytes(&self) -> usize {
        clamp_effective_digest_bytes(self.effective_digest_bytes)
    }
}

impl Default for Keccak256NodeCompress {
    fn default() -> Self {
        Self::new(KECCAK_DIGEST_BYTES)
    }
}

impl PseudoCompressionFunction<[u64; KECCAK_DIGEST_ELEMS], 2> for Keccak256NodeCompress {
    fn compress(&self, input: [[u64; KECCAK_DIGEST_ELEMS]; 2]) -> [u64; KECCAK_DIGEST_ELEMS] {
        let left = digest_to_bytes(&input[0]);
        let right = digest_to_bytes(&input[1]);

        add_node_hash_call();

        #[cfg(feature = "keccak_no_prefix")]
        let mut bytes: [u8; 32] = Keccak256Hash.hash_iter_slices([&left[..], &right[..]]);
        #[cfg(not(feature = "keccak_no_prefix"))]
        let mut bytes: [u8; 32] =
            Keccak256Hash.hash_iter_slices([&[0x01_u8][..], &left[..], &right[..]]);

        mask_digest_tail(&mut bytes, self.effective_digest_bytes());
        digest_from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_digest_bytes_for_security_bits, merkle_security_bits_or_default};

    #[test]
    fn effective_digest_bytes_security_mapping() {
        assert_eq!(effective_digest_bytes_for_security_bits(0), 1);
        assert_eq!(effective_digest_bytes_for_security_bits(80), 20);
        assert_eq!(effective_digest_bytes_for_security_bits(100), 25);
        assert_eq!(effective_digest_bytes_for_security_bits(128), 32);
        assert_eq!(effective_digest_bytes_for_security_bits(200), 32);
    }

    #[test]
    fn merkle_security_bits_or_default_mapping() {
        assert_eq!(merkle_security_bits_or_default(128, None), 128);
        assert_eq!(merkle_security_bits_or_default(128, Some(100)), 100);
        assert_eq!(merkle_security_bits_or_default(128, Some(80)), 80);
    }
}
