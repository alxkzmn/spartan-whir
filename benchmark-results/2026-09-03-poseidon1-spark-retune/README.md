# Poseidon1 full-ZK SPARK schedule retune

#### Result

The retune keeps the configured production schedule. On the linked 2,048-byte
SHA-256 workload, its median client `witness_and_prove` time is 1,011.992 ms
with a bootstrap median interval of 1,009.173 to 1,016.570 ms. Its median
serialized proof is 2,741,805 bytes. Native verification measures 75.412 ms
with one Rayon thread and 60.042 ms with 12 Rayon threads.

The selection order is client prover time first, restricted to schedules no
more than 1% slower than the measured fastest row. Within that set, schedules
whose one-thread verifier medians are within 1% or whose verifier median
intervals overlap are tied; serialized proof size breaks that tie. Four of the
six measured schedules entered the prover band. The configured schedule was
the only row in the verifier tie.

The selected configuration is:

- witness: `pow7`, `ConstantFromSecondRound { first: 8, rest: 3 }`,
  `starting_log_inv_rate = 1`, `rs_domain_initial_reduction_factor = 7`, and
  backend-derived round rates;
- fixed value and both read groups: `pow9`,
  `ConstantFromSecondRound { first: 8, rest: 4 }`,
  `starting_log_inv_rate = 1`, `rs_domain_initial_reduction_factor = 8`, and
  backend-derived round rates;
- fixed audit: `pow6`, `Constant(8)`, `starting_log_inv_rate = 1`,
  `rs_domain_initial_reduction_factor = 8`, and backend-derived round rates;
- `ell_zk = 3`, `mask_log_inv_rate = 3`, quintic extension, 116-bit composed
  security, 120-bit WHIR component security, and 123-bit Merkle binding.

Because the selected configuration is unchanged, the LeanVM guest fixture and
its 33,485,006-cycle ceiling check remain valid and were not regenerated.

#### Verifier estimator

The scorer records Merkle compressions, leaf field elements, opened row field
elements, extension operations, and proof-of-work checks. Calibration maps
those counters to one-thread native verifier time. An affine fit used three
calibration rows and three validation rows. Its maximum validation error is
0.8368%. The prover model's three held-out validation rows have a maximum
relative error of 1.2935%.

Verifier time and serialized proof size remain independent objectives. Their
product has units of byte-seconds and is not used as an estimate of recursive
work. A transport-aware latency estimate may instead add verification time to
`proof_bytes / effective_input_bandwidth`. One-thread native verification is a
screening proxy for the sequential LeanVM trace; LeanVM cycles and rows remain
the final recursive metrics.

The native verifier is not wholly single-threaded when the `parallel` feature
is enabled. Its equality-table construction reaches Plonky3's adaptively
parallel evaluator, while transcript progression and the small per-round
verification steps remain sequential. The measured 75.412 ms at one thread
and 60.042 ms at 12 threads show the modest parallel fraction for this proof.

#### Measurement environment

- Apple M4 Pro, 12 effective Rayon threads for the client prover measurement
- one Rayon thread for the verifier selection measurement
- `rustc 1.96.0-nightly (d9563937f 2026-03-03)`
- release profile, `parallel,poseidon1` features
- `RUSTFLAGS='-C target-cpu=native -C debuginfo=0'`
- linked witness generation with randomized SHA-style input bits
- one warmup and three interleaved repeats per schedule
- R1CS SHA-256:
  `1f1c6beae387e938d86b5ca433abc024945f14c2763db0c29638613ebb206627`
- 605,424 constraints and `log2_witness_variables = 20`

The source tree was dirty. The JSON artifacts record the branch, HEAD,
tracked-diff hash, untracked-file hashes, compiler, flags, feature set, workload
identity, samples, confidence intervals, and schedule data.

#### Artifacts

- `calibration.json`: Poseidon1 prover and verifier component measurements
- `heldout-parallel.json`: 12-thread client proving and native verification
- `heldout-verifier-1thread.json`: the one-thread verifier comparison
- `final-summary.json`: selected row, selection audit, and model validation

#### Commands

Calibration and component reports used native CPU tuning and the
`parallel,poseidon1` features. The witness, fixed-value, fixed-audit, and two
read reports used variable counts 20, 25, 22, 25, and 23. Candidate generation
used `--component-security-bits 120`,
`--component-merkle-security-bits 123`, and the references listed above.

The held-out command shape was:

```bash
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' \
RAYON_NUM_THREADS=12 \
cargo run --release --features parallel,poseidon1 \
  --bin poseidon-schedule-heldout -- \
  --r1cs target/sha256-optimized-cache/sha256_2048b/sha256_2048b.r1cs \
  --linked-witness-library target/sha256-optimized-cache/sha256_2048b/libsha256_2048b_witness.dylib \
  --linked-circuit-data target/sha256-optimized-cache/sha256_2048b/sha256_2048b_cpp/sha256_2048b.dat \
  --linked-input target/poseidon-schedule/sha256_2048b_input.bin \
  --linked-run-name sha256_2048b \
  --report /tmp/spark-full-zk-combined.json \
  --out /tmp/spark-heldout-parallel.json \
  --case-label sha256_2048b \
  --extension quintic \
  --row-source measurement-shortlist \
  --proof-mode full-zk \
  --max-rows 6 \
  --randomize-linked-input-bits \
  --repeats 3 \
  --warmups 1
```

The one-thread verifier run used the same command with
`RAYON_NUM_THREADS=1`. The final composer invocation passed the parallel file
as `--measurements` and the one-thread file as `--verifier-measurements`.
