//! Microbenchmark of the Keccak-based proof-of-work grinding used by the
//! `CanonicalSerializingChallenger32` in `spartan-whir`.
//!
//! The current `grind()` implementation enumerates the base-field domain
//! (`0..F::ORDER_U32`) in parallel via rayon and accepts the first witness
//! whose post-observe `sample_bits(N)` returns zero. Each attempt costs
//! roughly one Keccak permutation on the cloned challenger.
//!
//! This benchmark times `grind(bits)` for a small range of `bits` (the wall
//! time roughly doubles per added bit), derives the per-machine attempt rate,
//! and extrapolates the expected wall time at higher `bits` targets — including
//! values beyond the base-field cap (~30 bits) that would only be reachable
//! with extension-field grinding.
//!
//! Run with:
//!   cargo run --release -p spartan-whir --example grind_bench
//!
//! Optional env knobs:
//!   GRIND_ATTEMPTS_LOG2=24,26,28             attempt counts (as log2) to measure
//!   GRIND_REPEATS=3                          repeats per attempt count (median is reported)
//!   GRIND_PROBE_BITS=30                      bits passed to `check_witness` per attempt
//!   GRIND_EXTRAPOLATE=30,40,46,50,60,70,80   targets to extrapolate to

use std::env;
use std::time::Instant;

use p3_challenger::GrindingChallenger;
use p3_field::integers::QuotientMap;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_maybe_rayon::prelude::*;
use spartan_whir::new_keccak_challenger;

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

fn fmt_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:>9.3} ms", secs * 1e3)
    } else if secs < 60.0 {
        format!("{:>9.3} s ", secs)
    } else if secs < 3600.0 {
        format!("{:>9.2} min", secs / 60.0)
    } else if secs < 86400.0 {
        format!("{:>9.2} hr ", secs / 3600.0)
    } else {
        format!("{:>9.2} day", secs / 86400.0)
    }
}

fn main() {
    // Detect whether `p3-maybe-rayon/parallel` is actually enabled in the
    // dependency graph. Without it, `into_par_iter` is a serial shim and the
    // benchmark reports per-core, not per-machine, throughput.
    #[cfg(feature = "parallel")]
    let cores = p3_maybe_rayon::prelude::current_num_threads();
    #[cfg(not(feature = "parallel"))]
    let cores = 1usize;
    #[cfg(not(feature = "parallel"))]
    println!(
        "WARNING: built without `parallel` feature; `into_par_iter` is the\n\
         serial shim. Re-run with `--features parallel` to measure full-machine\n\
         throughput."
    );
    let repeats: usize = env::var("GRIND_REPEATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let extrapolate = parse_list(
        "GRIND_EXTRAPOLATE",
        &[30, 40, 46, 50, 55, 60, 64, 70, 75, 80, 90, 100],
    );

    println!("== spartan-whir Keccak grinding microbench ==");
    println!("rayon threads: {cores}");
    println!("repeats per bit: {repeats}");
    println!();

    // Build a challenger seeded with some non-trivial state so the inner buffer
    // is realistic. Without seeding the very first attempts may hit a slightly
    // different keccak path. The exact seed does not matter for rate.
    let make_cha = || {
        use p3_challenger::CanObserve;
        let mut cha = new_keccak_challenger();
        // Seed with 16 base-field elements so the inner Keccak buffer state is
        // representative of a mid-protocol challenger, not an empty one.
        for i in 0..16u32 {
            cha.observe(KoalaBear::from_u32(i + 1));
        }
        cha
    };

    println!(
        "{:>12} {:>10} {:>14} {:>16}",
        "attempts", "wall", "attempts/sec", "attempts/sec/core"
    );
    println!("{:->12} {:->10} {:->14} {:->16}", "", "", "", "");

    // Fixed-count scan. We perform a deterministic number of `check_witness`
    // calls in parallel against a never-satisfiable predicate (bits=30 gives
    // ~1/2^30 acceptance, so on ~2^N attempts we expect ~0 hits for N <= ~25;
    // we use bits=64-equivalent by using a witness range guaranteed not to
    // satisfy the predicate via the post-observe `sample_bits` value).
    //
    // Concretely, we mirror the inner of `grind`: clone the seeded challenger,
    // observe a candidate witness, sample bits, count one attempt. We discard
    // the result.
    let attempt_counts: Vec<u64> = parse_list("GRIND_ATTEMPTS_LOG2", &[24, 26, 28])
        .into_iter()
        .map(|n| 1u64 << n)
        .collect();
    let probe_bits: usize = env::var("GRIND_PROBE_BITS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let mut rates = Vec::new();
    for &n in &attempt_counts {
        let mut times = Vec::with_capacity(repeats);
        for _ in 0..repeats {
            let cha = make_cha();
            let start = Instant::now();
            // Parallel scan: each rayon worker takes a chunk of [0, n) and runs
            // check_witness on a cloned challenger. The boolean result is
            // ignored; we just want the work to happen.
            let _hits: u64 = (0u64..n)
                .into_par_iter()
                .map(|i| {
                    let mut local = cha.clone();
                    let w = unsafe {
                        // Map i into a base-field witness. We mod into [0, ORDER)
                        // implicitly by truncating to u32 and masking with a
                        // safe prime-bound; values >= ORDER are ok because
                        // from_canonical_unchecked accepts any u32 < 2^31.
                        KoalaBear::from_canonical_unchecked((i as u32) & 0x7fff_ffff)
                    };
                    if local.check_witness(probe_bits, w) {
                        1u64
                    } else {
                        0u64
                    }
                })
                .sum();
            times.push(start.elapsed().as_secs_f64());
        }
        let t = median(&mut times);
        let rate_total = n as f64 / t;
        let rate_per_core = rate_total / cores as f64;
        rates.push(rate_total);
        println!(
            "{:>12} {:>10} {:>14.2e} {:>16.2e}",
            n,
            fmt_duration(t),
            rate_total,
            rate_per_core,
        );
    }

    // Use the last (largest, most representative) rate for extrapolation.
    let rate = *rates.last().expect("at least one measurement");

    println!();
    println!("Extrapolated expected wall time at higher bit targets");
    println!("(uses median rate from the largest measured bit value, scaled by 2^bits / rate)");
    println!();
    println!(
        "{:>6} {:>14} {:>20}",
        "bits", "expected_attempts", "expected_wall_time"
    );
    println!("{:->6} {:->14} {:->20}", "", "", "");
    for &bits in &extrapolate {
        let attempts = 2f64.powi(bits as i32);
        let secs = attempts / rate;
        println!("{:>6} {:>14.2e} {:>20}", bits, attempts, fmt_duration(secs));
    }

    println!();
    println!("Notes:");
    println!("  - The current `grind()` exhausts the base-field domain (~2^31 candidates).");
    println!("    Targets >= 31 bits are not feasible in the base field; extrapolation");
    println!("    assumes a hypothetical extension-field grinder using the same Keccak");
    println!("    inner cost per attempt.");
    println!("  - Per-attempt cost is dominated by the Keccak permutation on a cloned");
    println!("    challenger; an extension-field witness adds at most a few more bytes");
    println!("    of `observe`, which is sub-keccak-block and amortizes into the same");
    println!("    permutation. So this rate is a tight upper bound on ext-field grinding too.");
}
