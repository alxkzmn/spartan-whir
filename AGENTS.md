# spartan-whir — Agent Instructions

## Project Intent

`spartan-whir` is part of the client-side proving work on a proof system that is:

- post-quantum and transparent,
- competitive for client-side proving,
- suitable for comparison benchmarks against other WHIR-based systems.

There are two client-side SNARK lines to keep separate:

- The current off-chain verification line is a pure client-side SNARK. For this line, optimize WHIR schedules primarily for prover speed while keeping RAM low enough for mobile feasibility.
- A later recursive/on-chain-targeted line may care more about proof size and verifier-facing calldata, but that is contingent on future recursion/on-chain research and is not the default schedule-selection objective today.

Proof size and verifier-facing calldata are primary optimization targets only for SNARK paths that explicitly target on-chain deployment or recursive verification toward on-chain deployment. For the current off-chain client-side schedule work, use proof size only as a deterministic tie-breaker behind projected proving time.

## Default Path Invariants

- Keep the current off-chain client-side default path aligned with fast proving and feasible memory use.
- Keep the no-ZK and full-ZK APIs separate.
- Unqualified `Plonky3WhirPcs` means plain WHIR and is the no-ZK PCS. Full ZK uses dedicated Poseidon ZK keys and the lower-level hiding-WHIR committed-relation APIs.
- Treat privacy and matrix closing as independent axes: no ZK supports DirectSparse and Spark; full ZK supports DirectSparse and rejects Spark during setup.
- Preserve verifier-facing protocol details deliberately, but do not treat EVM verifier efficiency as the default objective for the off-chain client-side line.
- Do not switch transcript, hash, or commitment choices as a refactor convenience. Treat those as protocol choices that need an explicit benchmark or verifier-design reason.
- For explicitly on-chain-targeted or recursive/on-chain-targeted paths, keep the transcript and commitment choices aligned with that verifier story.
- Treat transcript ordering, proof encoding, digest layout, and other verifier-facing details as protocol surface, not incidental implementation details.
- The project is still pre-production / PoC. Protocol-surface changes are allowed when they improve the design, reduce meaningful complexity, or improve verifier/prover tradeoffs. Do not block them solely to preserve existing unpublished proofs or fixtures; instead, call out what changes and update affected Rust proof structs, codecs, tests, and benchmark fixtures.

## What Is Flexible

- Field choices, extension choices, proof-system tuning, and internal structure may evolve when supported by benchmarks and verifier-cost reasoning.
- Additive experimental paths are welcome when they are clearly separated from the default path.
- If you want to try a non-EVM-oriented primitive or alternative challenger, add it as an explicit experiment, feature, or separate API instead of silently changing the default.

## Refactoring Rules

- Do not broaden abstractions around cryptographic backends unless there is a concrete need in this crate.
- Do not make "cleanups" that change verifier-relevant behavior without calling that out explicitly.
- If a change can affect verifier gas, calldata size, proof size, transcript compatibility, or benchmark comparability, state that impact in your summary.
- When changing extension choices or adding a new extension, document extension-specific algebraic limits and support level explicitly. This includes `TWO_ADICITY`-dependent behavior, skip-path feasibility, and which paths are currently exercised by tests or benchmarks.
- Prefer changes that keep `spartan-whir` representative for future client-side proving comparison benchmarks.

## Docs and Benchmarks

- When you add, rename, or materially change a public benchmark target or its environment knobs, update `README.md` in the same change.
- Keep schedule calibration, candidate search, heldout validation, Pareto exploration, and model-interpretation workflows in this file rather than `README.md`.
- Keep benchmark commands, benchmark target names, environment knobs, and output examples aligned with the code.
- For SHA256 plain/full-ZK performance comparisons, use the Criterion target with native CPU tuning:
  `RUSTFLAGS='-C target-cpu=native -C debuginfo=0' cargo bench --features parallel --bench sha256_full_zk`.
- The Criterion target only loads existing circuit artifacts from `target/sha256-cache`; it must not compile the circuit as part of a benchmark run. Use `sha256_bench` for schedule screening and detailed tracing, and treat its `Instant` timings as diagnostic rather than comparison results.
- Benchmark/profiling output intended for direct human inspection should be stable and human-readable. Prefer labeled `key: value` fields and clear tree/group structure over raw debug dumps.
- If a benchmark fixture is only shape-similar to a real circuit, document that approximation explicitly instead of describing it as the real circuit.
- Keep `README.md` focused on the current codebase state rather than changelog-style history; describe the format and behavior that exist now.
- Any protocol change that affects Spark fixed-table commitments must regenerate serialized `spark_fixed_commitments` and fixtures containing them.

## Poseidon Schedule Optimization

The Poseidon Plonky3-WHIR prover uses an offline schedule-scoring workflow for
`MatrixClosingMode::DirectSparse` with Johnson-bound soundness. The scorer is
not part of setup. Generate and measure schedules for the target circuit, then
pass the selected `PoseidonSetupConfig` into `setup_poseidon`.

Optimize the client-side line for prover time while keeping memory feasible.
Use proof size as a deterministic tie-breaker between schedules whose measured
proving times overlap. Use the linked native witness generator for end-to-end
client benchmarks; reserve `.wtns` inputs for schedule-model calibration.

### Workflow

1. Measure local component costs:

```bash
RUSTFLAGS="-C target-cpu=native -C debuginfo=0" \
cargo run --release --features parallel \
  --bin poseidon-schedule-calibration -- \
  --out /tmp/poseidon-calibration.json
```

2. Enumerate backend-validated candidate schedules:

```bash
cargo run -q --bin poseidon-schedule-candidates -- \
  --num-variables 19 \
  --field koalabear \
  --security-bits 123 \
  --max-pow-bits 22 \
  --proof-mode no-zk \
  > /tmp/poseidon-candidates.json
```

Use `--proof-mode full-zk` for schedules that must satisfy hiding-WHIR mask
slack and extension-field two-adicity limits. The fallback parameter helpers
are `recommended_octic_whir_params` for no ZK and
`recommended_octic_zk_whir_params` for full ZK. Use scheduler-selected
`WhirParams` for benchmarked deployments.

3. Score a candidate file:

```bash
python3 scripts/poseidon_schedule_scorer.py \
  --candidates /tmp/poseidon-candidates.json \
  --calibration /tmp/poseidon-calibration.json \
  --constraint-work 519678 \
  --out-report /tmp/poseidon-report.json \
  --out-config /tmp/poseidon-config.json
```

For full-ZK tuning, let the scorer generate the joint WHIR and ZK parameter
grid:

```bash
python3 scripts/poseidon_schedule_scorer.py \
  --num-variables 20 \
  --calibration /tmp/poseidon-calibration.json \
  --constraint-work 922944 \
  --proof-mode full-zk \
  --measurement-shortlist-margin-ratio 0.01 \
  --out-report /tmp/poseidon-zk-report.json \
  --out-config /tmp/poseidon-zk-config.json
```

The default ZK sweep is `ell_zk = 3,4,8,16` and
`mask_log_inv_rate = 1,2,3,4,5`. Include low mask rates in the sweep and let
the backend slack checks reject invalid rows.

4. Measure shortlisted rows. For a `.wtns` calibration fixture:

```bash
RUSTFLAGS="-C target-cpu=native -C debuginfo=0" \
cargo run --release --features parallel \
  --bin poseidon-schedule-heldout -- \
  --r1cs circuit.r1cs \
  --wtns witness.wtns \
  --report /tmp/poseidon-report.json \
  --out /tmp/poseidon-heldout.json \
  --extension octic \
  --proof-mode no-zk \
  --row-source measurement-shortlist \
  --max-rows 5 \
  --repeats 21 \
  --warmups 3
```

For cached SHA-256 linked-witness artifacts:

```bash
RUSTFLAGS="-C target-cpu=native -C debuginfo=0" \
cargo run --release --features parallel \
  --bin poseidon-schedule-heldout -- \
  --r1cs target/sha256-cache/sha256_2048b/sha256_2048b.r1cs \
  --linked-witness-library target/sha256-cache/sha256_2048b/libsha256_2048b_witness.dylib \
  --linked-circuit-data target/sha256-cache/sha256_2048b/sha256_2048b_cpp/sha256_2048b.dat \
  --linked-input target/poseidon-schedule/sha256_2048b_input.bin \
  --linked-run-name sha256_2048b \
  --report /tmp/poseidon-report.json \
  --out /tmp/poseidon-heldout.json \
  --extension octic \
  --proof-mode full-zk \
  --row-source measurement-shortlist \
  --max-rows 10 \
  --randomize-linked-input-bits \
  --repeats 21 \
  --warmups 3
```

5. Build the ZK proving-time/proof-size Pareto report:

```bash
python3 scripts/poseidon_schedule_pareto.py \
  --report /tmp/poseidon-zk-report.json \
  --measurements /tmp/poseidon-heldout.json \
  --out /tmp/poseidon-zk-pareto.json \
  --out-svg /tmp/poseidon-zk-pareto.svg
```

Measure another Pareto batch by passing the compact report to heldout with
`--row-source measurement-candidates`. Keep
`--randomize-linked-input-bits` enabled for SHA-style linked witnesses.

6. Merge heldout measurements and refit component scales:

```bash
python3 scripts/poseidon_schedule_add_heldout.py \
  --calibration /tmp/poseidon-calibration.json \
  --heldout /tmp/poseidon-heldout.json \
  --out /tmp/poseidon-calibration-heldout.json \
  --replace \
  --recalibrate
```

Use `--proof-mode full-zk` throughout candidate generation, scoring, heldout
measurement, and rescoring for a full-ZK search. Full-ZK heldout rows must come
from the full-ZK prover; never relabel a full-ZK report as no ZK. Pass
`--measurements /tmp/poseidon-heldout.json` to the scorer to add
`selected_measured` without replacing the model's `selected` row.

### Selection Rules

- Treat the scorer as a pruning model, not a sub-percent ordering oracle.
- Use an untruncated report before pinning a schedule. Audit the best row from
  each extension, folding, and rate family inside the model-resolution band.
- Interpret overlapping bootstrap median confidence intervals as a time tie.
- Prefer smaller proofs among time-tied rows. Prefer lower PoW before label
  order because it has lower grind variance.
- A higher-PoW row can win a median-time tie on proof size, but it carries a
  tail-latency cost. Revisit the PoW-free tied row if p99 proving latency becomes
  an objective.
- Compare absolute timings only within one heldout run. Cite the heldout
  artifact when quoting a value because medians drift across batches.
- Use full-proof Criterion benchmarks as the final decision point.

`poseidon-schedule-heldout` runs repeats in shuffled round-robin passes. With
`--randomize-linked-input-bits`, it varies SHA-style inputs per repeat to
average deterministic PoW grind luck. Its output includes samples, the median,
the mean, and a bootstrap median confidence interval.

### Artifacts and Model Limits

- `poseidon-schedule-calibration` writes component coefficients and raw
  microbenchmark measurements by extension.
- `poseidon-schedule-candidates` writes backend-derived schedules, security,
  PoW, round data, work units, mode-specific setup configuration, and
  `proof_mode`. Full-ZK rows also contain `ell_zk`, `mask_log_inv_rate`, `zk_*`
  work, and proof-size estimates.
- `poseidon_schedule_scorer.py` writes projected time, `cost_breakdown`,
  validation status, `selected`, and `measurement_shortlist`. With measured
  input it also writes `selected_measured`.
- `poseidon-schedule-heldout` consumes `measurement_shortlist`,
  `measurement_candidates`, `scores`, or `candidates`, in that order. Use
  `--include-strata` to sample across the accepted ranking.
- `poseidon_schedule_add_heldout.py` merges heldout rows and refits component
  scales. Heldout rows must contain every modeled component metric.
- `poseidon_schedule_pareto.py` separates measured and interpolated frontier
  rows and emits `measurement_candidates` for the next batch.

Candidate validity and achieved security come from constructing Plonky3 WHIR
configs; the scorer has no independent security derivation. Rows are rejected
when backend derivation fails, achieved security is below target, PoW exceeds
the cap, or field two-adicity is insufficient.

The linear model is:

```text
projected_time = fixed_overhead + dft + merkle + merkle_path + row_opening + sumcheck + pow + spartan
```

Recommendations are trusted only after heldout error for the target circuit and
extension falls within tolerance. The model omits cache behavior and shared
backend interactions, so clustered schedules require heldout confirmation.
`proof_size_bytes_estimate` counts opened field elements, Merkle path digests,
and round commitments; it is a ranking proxy rather than a serialized byte
count.

The `--field babybear` mode tests schedule validity and ranking under BabyBear's
two-adicity; it is not a BabyBear prover benchmark. The relevant validity bound
is `num_variables + starting_log_inv_rate - first_folding_factor <=
F::TWO_ADICITY`. Heldout recalibration updates only extensions represented in
the measured rows.

## Decision Heuristic

If a change improves software neatness but makes the current off-chain client-side path slower, less representative, or materially harder to benchmark on realistic devices, reject it by default.
