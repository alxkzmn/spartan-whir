# SHA-256 2048-byte schedule refresh

Date: 2026-08-27

This record selects the default WHIR schedules for the 2048-byte SHA-256
workload and measures all four DirectSparse/Spark and no-ZK/full-ZK variants
with those defaults.

#### Scope and configuration

- Apple M4 Pro, 12 cores, 48 GB memory
- `rustc 1.96.0-nightly (d9563937f 2026-03-03)`
- `parallel` feature and `RUSTFLAGS='-C target-cpu=native -C debuginfo=0'`
- 116-bit end-to-end security target
- 605,424 raw constraints and 1,048,576 padded rows
- R1CS SHA-256:
  `1f1c6beae387e938d86b5ca433abc024945f14c2763db0c29638613ebb206627`
- `ell_zk = 3` and `mask_log_inv_rate = 3` for full ZK
- Separate Spark fixed-value and read openings
- All Plonky3 crates loaded from the pinned Git revision `f64ae15d`

The schedule artifacts record the exact dirty working-tree provenance at
Spartan-WHIR HEAD `8000a37a3e53fe64eb25111cad888d53021805fc` and Plonky3 HEAD
`f64ae15da3807388b1a4e0a89a4fde8fdcdff515`. The selected parameter structs
were then copied into the default helpers. Exact-label tests cover every
selected helper, including the distinction between backend-derived round rates
and explicitly stored round rates.

#### Selection method

The calibrated component model constructs a measurement shortlist; it does not
decide close candidates. Heldout measurements use 21 shuffled round-robin
repeats, three warmups, randomized linked input bits, and 95% bootstrap median
confidence intervals.

DirectSparse is selected by prover time only. A measured slowdown of at most 1%
or an overlapping median confidence interval is a timing tie. Ties prefer lower
maximum PoW, then lower PoW work, then stable label order. Proof size is
reported but never selects a DirectSparse schedule. Candidate generation
covered quartic, quintic, and octic extensions; no quartic candidate passed the
security gate.

Spark retains the Pareto set across measured prover time and proof size. All
eight heldout rows were timing ties in each privacy mode, so proof size selected
the retained native finalist. The reports have no recursive verifier cycle or
trace row measurements. Proof size is not used as a proxy for recursive
verification, so the recursive schedule choice remains unresolved. The
calibrated Spark model's maximum heldout relative error was 0.17% without ZK
and 0.79% with full ZK.

#### Selected schedules

| Use | Variables | Schedule |
| --- | ---: | --- |
| DirectSparse, no ZK | 20 | `quintic_cfsr_pow2_ff8_rest7_lir1_rsv8_round_log_inv_rates_derived` |
| DirectSparse, full ZK | 20 | `quintic_cfsr_pow4_ff8_rest6_lir1_rsv6_round_log_inv_rates_4` |
| Spark witness, no ZK | 20 | `quintic_constant_pow6_ff8_lir1_rsv8_round_log_inv_rates_derived` |
| Spark witness, full ZK | 20 | `quintic_cfsr_pow7_ff8_rest3_lir1_rsv7_round_log_inv_rates_derived` |
| Spark fixed value | 25 | `quintic_cfsr_pow9_ff8_rest4_lir1_rsv8_round_log_inv_rates_derived` |
| Spark fixed audit | 22 | `quintic_constant_pow6_ff8_lir1_rsv8_round_log_inv_rates_derived` |
| Spark read groups | 25 and 23 | `quintic_cfsr_pow9_ff8_rest4_lir1_rsv8_round_log_inv_rates_derived` |

The fixed-audit columns are embedded in the fixed-value commitment for this
circuit. The one shared read schedule is valid for both read groups; the backend
derives each group's round rates independently.

#### Heldout results

Times are medians. Bracketed ranges are 95% bootstrap median confidence
intervals. Proof sizes are median serialized sizes.

| Mode | Prove | Proof size | Timing-tied rows |
| --- | ---: | ---: | ---: |
| no-ZK DirectSparse | 27.664 ms [27.375, 27.929] | 483,527 bytes | 6 |
| full-ZK DirectSparse | 48.827 ms [47.013, 49.726] | 1,226,564 bytes | 9 |
| no-ZK Spark | 817.529 ms [801.699, 826.035] | 2,038,328 bytes | 8 |
| full-ZK Spark | 825.117 ms [815.573, 832.829] | 2,740,781 bytes | 8 |

The DirectSparse proof-size columns are reporting only. The DirectSparse
tie-breaks did not inspect them.

#### Final Criterion results

The final run used 30 samples, a four-second warmup, a twelve-second target
measurement time, and a 16-proof corpus. Times are Criterion point estimates;
bracketed ranges are 95% confidence intervals. Criterion's slope estimate is
used where available and its mean otherwise. Proof sizes are median serialized
sizes over the corpus.

| Mode | Witness + prove | Verify | Proof size |
| --- | ---: | ---: | ---: |
| no-ZK DirectSparse | 46.746 ms [46.558, 46.966] | 31.910 ms [31.848, 31.999] | 483,383 bytes |
| no-ZK Spark | 789.761 ms [787.040, 792.668] | 22.573 ms [22.537, 22.618] | 2,037,240 bytes |
| full-ZK DirectSparse | 68.334 ms [67.648, 68.996] | 49.716 ms [49.538, 49.872] | 1,226,660 bytes |
| full-ZK Spark | 889.631 ms [882.292, 898.688] | 40.221 ms [40.077, 40.401] | 2,741,933 bytes |

For full ZK, the DirectSparse proof's median matrix-closing section is 4 bytes
and its PCS relation is 1,222,068 bytes. The Spark proof's corresponding
medians are 1,561,149 and 1,176,420 bytes. Within Spark matrix closing, the
separately measured medians are 36,352 bytes of products, 521,719 bytes of
fixed openings, and 1,003,442 bytes of read openings. Section medians need not
sum exactly to the median total.

#### Plonky3 comparison

A control run kept the previous schedules, security parameters, full-ZK
terminal budgets, and 16-proof corpus while resolving every Plonky3 crate to
the clean `f64ae15d` Git revision. Compared with the existing
`v6_final_all_four` baseline using the stashed Plonky3 changes, those changes
reduced the following timings:

| Mode | Witness + prove | Verify |
| --- | ---: | ---: |
| no-ZK DirectSparse | 5.83% | 2.01% |
| no-ZK Spark | 8.42% | 2.02% |
| full-ZK DirectSparse | 4.89% | 2.33% |
| full-ZK Spark | 5.13% | 2.89% |

Proof-size medians changed by less than 0.05%, consistent with identical proof
geometry and different sampled query overlap. The timing percentages compare
separately collected Criterion baselines, so ordinary between-run system
variation remains in the attribution.

#### Interpretation

Relative to DirectSparse in the same privacy mode, Spark is 16.89 times slower
to prove without ZK and 13.02 times slower with full ZK. Its proofs are 4.21
and 2.24 times larger. Spark's native verifier is 29.26% faster without ZK
and 19.10% faster with full ZK.

DirectSparse remains the default when prover time or proof size matters. Spark
has a native verifier time advantage, but these measurements do not establish
an advantage in a recursive verifier.

#### Command and artifacts

The final four-variant run was:

```sh
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' \
SHA256_BENCH_WORKDIR=target/sha256-optimized-cache \
SHA256_ZK_BENCH_SIZE=2048 \
SHA256_ZK_BENCH_EXTENSION=selected \
SHA256_ZK_BENCH_CORPUS_SIZE=16 \
SHA256_ZK_BENCH_SECURITY_BITS=116 \
SHA256_BENCH_ZK_ELL=3 \
SHA256_BENCH_ZK_MASK_LOG_INV_RATE=3 \
cargo +nightly-2026-03-04 bench --locked --offline \
  --features parallel --bench sha256_full_zk -- \
  --save-baseline f64ae15d_final_all_four_cold
```

Schedule search, calibration, heldout inputs, reports, and selected configs are
under `target/poseidon-schedule/refresh-2026-08-27-f64ae15d`. Criterion
estimates are under
`target/criterion/sha256_2048b_quintic_{witness_and_prove,verify}/*/f64ae15d_final_all_four_cold`.
The same-schedule Plonky3 control is stored under the
`f64ae15d_same_schedules_all_four` baseline.
These ignored `target` artifacts are local; this file is the durable result
summary. The complete schedule workflow and selection rules are in
[`AGENTS.md`](../AGENTS.md).

#### Prior experiments

The earlier Spark implementation measurements, rejected opening strategies,
and rejected Spark++ experiment are recorded in
[`2026-08-26-sha256-2048b-spark.md`](2026-08-26-sha256-2048b-spark.md). The
Spark++ prototype was removed. Its sparse logical messages do not make zeros
free in WHIR: Reed-Solomon encoding and Merkle commitment still process a dense
codeword. Replacing WHIR with a commitment scheme designed for sparse messages
would require a separate commitment, opening protocol, transcript, security
composition, key lifecycle, and recursive verifier.
