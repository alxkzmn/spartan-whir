//! Fixed-count benchmark for Keccak grinding candidate predicates.
//!
//! This compares the old clone-based `HashChallenger` predicate with two
//! allocation-free predicate checks over the same chained transcript prefix.
//!
//! Run with:
//!   GRIND_REPEATS=1 GRIND_ATTEMPTS_LOG2=24,26,28 \
//!   cargo run --release -p spartan-whir --features parallel --example grind_predicate_bench

use std::env;
use std::time::Instant;

use p3_challenger::{GrindingChallenger, HashChallenger};
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::CryptographicHasher;
use spartan_whir::{CanonicalSerializingChallenger32, KeccakByteChallenger};

type ReferenceChallenger =
    CanonicalSerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256Hash, 32>>;

fn parse_list(var: &str, default: &[u32]) -> Vec<u32> {
    match env::var(var) {
        Ok(s) => s
            .split(',')
            .filter_map(|t| t.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    if n % 2 == 1 {
        xs[n / 2]
    } else {
        0.5 * (xs[n / 2 - 1] + xs[n / 2])
    }
}

fn make_prefix() -> Vec<u8> {
    let mut prefix = Vec::new();
    for i in 0..16u32 {
        prefix.extend_from_slice(&KoalaBear::from_u32(i + 1).as_canonical_u32().to_le_bytes());
    }
    prefix
}

fn make_reference(prefix: &[u8]) -> ReferenceChallenger {
    ReferenceChallenger::from_hasher(prefix.to_vec(), Keccak256Hash {})
}

fn check_hash_slices(prefix: &[u8], bits: usize, witness: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let witness_bytes = witness.to_le_bytes();
    let digest = Keccak256Hash {}.hash_iter_slices([prefix, &witness_bytes]);
    // Match `HashChallenger` sampling: pop bytes from the digest tail, then
    // interpret those popped bytes as a little-endian `u32`.
    let value = u32::from_le_bytes([digest[31], digest[30], digest[29], digest[28]]) as usize;
    value & ((1 << bits) - 1) == 0
}

fn run_variant<F>(name: &str, attempts: u64, repeats: usize, check: F) -> f64
where
    F: Fn(u32) -> bool + Sync,
{
    let mut times = Vec::with_capacity(repeats);
    let mut hits = 0u64;
    for _ in 0..repeats {
        let start = Instant::now();
        hits = (0u64..attempts)
            .into_par_iter()
            .map(|i| u64::from(check(i as u32)))
            .sum();
        times.push(start.elapsed().as_secs_f64());
    }
    let t = median(&mut times);
    let rate = attempts as f64 / t;
    println!("{name:>16} {attempts:>12} {t:>10.3} {rate:>14.2e} {hits:>8}");
    rate
}

fn main() {
    #[cfg(feature = "parallel")]
    let cores = p3_maybe_rayon::prelude::current_num_threads();
    #[cfg(not(feature = "parallel"))]
    let cores = 1usize;

    let attempt_counts: Vec<u64> = parse_list("GRIND_ATTEMPTS_LOG2", &[24, 26, 28])
        .into_iter()
        .map(|n| 1u64 << n)
        .collect();
    let repeats = env::var("GRIND_REPEATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let probe_bits = env::var("GRIND_PROBE_BITS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let prefix = make_prefix();

    println!("== Keccak grinding predicate benchmark ==");
    println!("rayon threads: {cores}");
    println!("probe bits: {probe_bits}");
    println!("repeats: {repeats}");
    println!(
        "{:>16} {:>12} {:>10} {:>14} {:>8}",
        "variant", "attempts", "seconds", "attempts/sec", "hits"
    );
    println!("{:->16} {:->12} {:->10} {:->14} {:->8}", "", "", "", "", "");

    for attempts in attempt_counts {
        let reference = make_reference(&prefix);
        let baseline = run_variant("clone", attempts, repeats, |candidate| {
            let mut local = reference.clone();
            let witness = unsafe { KoalaBear::from_canonical_unchecked(candidate) };
            local.check_witness(probe_bits, witness)
        });
        // This is the production fast predicate: same bytes as the clone path,
        // but no cloned `Vec` and no candidate append allocation.
        let slices = run_variant("hash_slices", attempts, repeats, |candidate| {
            check_hash_slices(&prefix, probe_bits, candidate)
        });
        // This path exists to measure the original fixed-state Keccak idea
        // separately from the faster Plonky3 slice hasher.
        let fixed = run_variant("fixed_state", attempts, repeats, |candidate| {
            KeccakByteChallenger::check_witness_in_prefix_fixed_state(
                &prefix, probe_bits, candidate,
            )
        });
        println!(
            "{:>16} {:>12} {:>10} {:>14.2} {:>8}",
            "fixed/clone",
            attempts,
            "",
            fixed / baseline,
            ""
        );
        println!(
            "{:>16} {:>12} {:>10} {:>14.2} {:>8}",
            "slices/clone",
            attempts,
            "",
            slices / baseline,
            ""
        );
    }
}
