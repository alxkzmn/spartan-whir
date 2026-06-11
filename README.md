# spartan-whir

`spartan-whir` is a Spartan-oriented proving system built on Plonky3 fields.
The Poseidon instantiation uses upstream Plonky3 WHIR as its multilinear PCS
backend. The Keccak instantiation uses the legacy `whir-p3` backend behind the
`whir-p3-backend` feature.

## SNARK Instantiations

`spartan-whir` supports two hash instantiations with different deployment
targets:

- `KeccakEngine<Ext>` is the on-chain-verifier instantiation. It keeps the
  Keccak transcript and Keccak Merkle hashing needed by the Solidity verifier
  work.
- `PoseidonEngine<Ext>` is the client-side-oriented instantiation. It uses the
  KoalaBear Poseidon2 permutation shape used by Plonky3 WHIR and is the intended
  path for Circom frontend benchmarks.

The Circom frontend circuits are written over KoalaBear in both cases.

#### Poseidon Deployment Witness Generation

The Poseidon deployment API uses a linked native witness generator. A
`PoseidonWitnessGenerator` loads a circuit `.dat` payload once through the
linked loader and stores the returned circuit handle plus FFI function pointers.
`PoseidonProvingKey::prove_from_witness_generator` passes an application-defined
binary input buffer into the linked function, which fills private/internal
witness and public-value buffers directly as canonical KoalaBear `u32` values.

Public values are ordered as `public_outputs || public_inputs`, matching the
Circom R1CS wire layout. The witness buffer contains witness columns only.
The default proving path does not run a separate full R1CS satisfaction pass
before proving; `prove_from_witness_generator_checked` is available when
debugging a linked witness generator and a row-level validation error is useful.
The path has no JSON file, `.wtns` file, subprocess, or witness re-import.

## Keccak Backend

The Keccak backend is enabled with the `whir-p3-backend` Cargo feature.

- Engine: `KeccakEngine<Ext>`
  - `QuarticBinExtension = BinomialExtensionField<F, 4>`
  - `QuinticExtension = QuinticTrinomialExtensionField<F>`
  - `OcticBinExtension = BinomialExtensionField<F, 8>`
  - Extension choice is a compile-time engine parameter, not a runtime switch
  - Fixed parameters: `F = KoalaBear`, `W = u64`, `DIGEST_ELEMS = 4`
- PCS: `WhirPcs`
- Protocol: `SpartanProtocol::setup/prove/verify`
- Transcript and commitment stack: Keccak challenger plus Keccak Merkle hashing

## Protocol Capabilities

- Real outer cubic and inner quadratic sumchecks
- Real R1CS operations: `pad_regular`, `multiply_vec`, `bind_row_vars`, `evaluate_with_tables`, `witness_to_mle`
- Public instance is external to the proof: `verify(vk, instance, proof, challenger)`
- `prove` returns `(instance, proof)`
- WHIR verification is split into commitment-parse and finalize phases to preserve transcript continuity
- The `SpartanProtocol` PCS statement path accepts point-evaluation claims
- Linear and tensor-product PCS constraints are unsupported by the Spartan/WHIR path
- Blob codec v1 encodes `Proof + Instance`
- `SpartanBlobDecodeContext::from_vk` derives an engine-typed decode context from the verifying key
- Codec v1 records extension degree explicitly in the header
- `profile_spartan_blob_v1` and `encode_spartan_blob_v1_with_report` provide deterministic size reporting

## Extension Support

- Quartic and quintic are covered by the PCS, protocol, codec, and profiling test matrix
- Octic is available in the engine surface and is used by the proof-size benchmark target
- Benchmarking with different extensions is expected to be workload-dependent; extension choice is part of the measurement surface

WHIR univariate-skip support is disabled. Extension-specific two-adicity limits
apply to any skip-enabled configuration; for KoalaBear quintic, skip width must
stay within 24.

## Implemented Modules

- `src/engine.rs`
  - Generic `KeccakEngine<Ext>` plus quartic/quintic/octic extension aliases and challenger constructors
- `src/hashers.rs`
  - EVM-compatible Keccak leaf/node hashing with digest masking controls
- `src/whir_pcs.rs`
  - WHIR-backed `MlePcs`
  - `verify_parse_commitment` / `verify_finalize` helpers
- `src/r1cs.rs`
  - Canonical padding and sparse-matrix evaluation helpers
- `src/sumcheck.rs`
  - Transcript-driven outer/inner sumcheck prove/verify
- `src/protocol.rs`
  - Real Spartan setup/prove/verify orchestration
- `src/codec.rs`, `src/codec_v1.rs`
  - Versioned blob encoding/decoding dispatch + v1 wire format implementation
- `src/profiling.rs`
  - No-op protocol hooks (`ProtocolObserver`, `ProtocolStage`)
  - Deterministic codec-driven byte accounting report
  - Tracing span emission for proof-size breakdown (`trace_proof_size_report`)

## Related Design Notes

- `Spartan-LC` (linear-constraint-based Spartan path) is documented separately:
  - See [`SPARTAN_LC_UPGRADE_PLAN.md`](SPARTAN_LC_UPGRADE_PLAN.md)
  - The implementation in this crate uses the R1CS-based Spartan path.

## Synthetic R1CS Fixtures

- `spartan-whir` provides synthetic fixture generators for targeted WHIR witness commitment sizes:
  - `generate_satisfiable_fixture(...)`
  - `generate_satisfiable_fixture_for_pow2(k)`
- These helpers produce satisfiable regular R1CS tuples `(shape, witness, public_inputs)` with witness length exactly `2^k`.
- This is intended for large-size protocol tests and benchmark scaffolding.
- The benchmark fixtures are synthetic and only shape-similar to target circuits such as Spartan2 SHA-256.
- They model rough constraint count / witness size / row sparsity for benchmark scaffolding.

## Poseidon Schedule Scoring

The Poseidon Plonky3-WHIR prover has a manual schedule-scoring workflow for
`MatrixClosingMode::DirectSparse` with Johnson-bound soundness. The scorer does
not run during setup. A user generates candidate schedules, scores them with a
calibration file, optionally validates the top rows with proof-only heldout
measurements, and then passes the selected `PoseidonSetupConfig` into
`setup_poseidon`. Deployment prover benchmarks should use the linked native
witness-generator path and report `witness_and_prove_ms`; `.wtns` inputs in this
workflow are only for schedule-model calibration.

#### Workflow

1. Measure local component costs:

```bash
RUSTFLAGS="-C target-cpu=native" \
cargo run --release -p spartan-whir --features parallel \
  --bin poseidon-schedule-calibration -- \
  --out /tmp/poseidon-calibration.json
```

2. Enumerate backend-derived candidate schedules:

```bash
cargo run -q -p spartan-whir --bin poseidon-schedule-candidates -- \
  --num-variables 19 \
  --security-bits 128 \
  --max-pow-bits 22 \
  > /tmp/poseidon-candidates.json
```

3. Score candidates and write the selected setup config:

```bash
python3 scripts/poseidon_schedule_scorer.py \
  --candidates /tmp/poseidon-candidates.json \
  --calibration /tmp/poseidon-calibration.json \
  --constraint-work 519678 \
  --out-report /tmp/poseidon-report.json \
  --out-config /tmp/poseidon-config.json
```

4. Measure proof-only heldout rows for schedule-model calibration:

```bash
RUSTFLAGS="-C target-cpu=native" \
cargo run --release -p spartan-whir --features circom,parallel \
  --bin poseidon-schedule-heldout -- \
  --r1cs circuit.r1cs \
  --wtns witness.wtns \
  --report /tmp/poseidon-report.json \
  --out /tmp/poseidon-heldout.json \
  --extension octic \
  --max-rows 5 \
  --include-strata
```

5. Add heldout measurements to the calibration and refit component scales:

```bash
python3 scripts/poseidon_schedule_add_heldout.py \
  --calibration /tmp/poseidon-calibration.json \
  --heldout /tmp/poseidon-heldout.json \
  --out /tmp/poseidon-calibration-heldout.json \
  --replace \
  --recalibrate
```

#### Artifacts

- `poseidon-schedule-calibration` writes component coefficients and raw
  microbenchmark measurements. Sumcheck coefficients are stored per extension
  (`quartic`, `quintic`, `octic`).
- `poseidon-schedule-candidates` writes the backend-derived schedule rows,
  achieved security, derived PoW bits, WHIR round data, work units, and the
  candidate `PoseidonSetupConfig`.
- `poseidon_schedule_scorer.py` writes a ranked report with projected time,
  per-component `cost_breakdown`, validation status, and one selected config.
- `poseidon-schedule-heldout` writes proof-only heldout rows for the selected
  circuit. With `--include-strata`, it samples across the accepted ranking
  instead of measuring only the first `--max-rows` rows.
- `poseidon_schedule_add_heldout.py` merges heldout rows into the calibration
  and can refit component scale factors.
  Heldout files must contain every component metric used by the scorer. Re-run
  `poseidon-schedule-heldout` after adding calibration components such as
  `merkle_path`.

#### Scope And Trust

Candidate validity and achieved security come from constructing Plonky3 WHIR
configs. The scorer has no independent security derivation. Rows are rejected
when backend derivation fails, achieved security is below the target, derived
PoW exceeds the policy cap, or the schedule exceeds field two-adicity limits.

The scorer is a linear component model:

```text
projected_time = fixed_overhead + dft + merkle + merkle_path + row_opening + sumcheck + pow + spartan
```

The report marks recommendations as untrusted until heldout rows for the target
circuit and extension are within the configured error tolerance. The model is
intended for schedule selection. Full-proof benchmarks remain the deployment
check.

Heldout recalibration updates the sumcheck coefficient only for extensions that
appear in the measured rows. A calibration validated with octic heldouts does
not make quintic or quartic recommendations trusted.

The Merkle commitment term is calibrated against opened matrix field elements,
and the Merkle-path term is calibrated against path depth. The row-opening term
tracks opened row field elements separately. Clustered schedules should still be
confirmed with heldout measurements because cache behavior and shared backend
work are intentionally not modeled as separate interaction terms.

Candidate rows include `proof_size_bytes_estimate`, a verifier-facing proxy that
counts opened field elements, Merkle path digests, and round commitments. It is
used as the ranking tie-breaker when projected times match. It is not a
byte-exact serialization size.

The PoW term counts expected Bernoulli trials for each grind slot. The hard cap
is `--max-pow-bits`; the default candidate set is
`0, 4, 8, 12, 16, 20, 22`.

## Unsupported Features

- Zero-knowledge mode
- Full EVM verifier contract implementation
- Gas-cost modeling and on-chain calldata benchmarking

## Run Tests

```bash
cargo test
cargo test --features keccak_no_prefix
```

Test suite includes:

- WHIR PCS lifecycle and ordering regression tests
- Codec v1 roundtrip/rejection/structural-validation tests
- Profiling determinism and byte-invariant tests
- R1CS canonicalization and table-evaluation consistency tests
- Sumcheck roundtrip and tamper/round-count checks
- Direct quadratic/cubic round-polynomial interpolation spot checks
- Spartan protocol end-to-end success/failure scenarios
  - tampered commitment rejection
  - tampered outer claims rejection
  - tampered `witness_eval` rejection
  - tampered PCS proof rejection
  - wrong public-input rejection
- Transcript checkpoint consistency tests
- Non-invertible witness recovery denominator guard tests

Additional targeted-size commands:

```bash
cargo test protocol_e2e_target_2_pow_18
cargo test protocol_e2e_target_2_pow_22 -- --ignored
cargo test sparsity_sweep_target_2_pow_18 -- --ignored --nocapture
```

## Run Benchmarks

`spartan-whir` includes a Criterion benchmark target for proof-size roundtrip measurement:

```bash
cargo bench --bench proof_size_roundtrip -- --noplot
```

For realistic local timing, prefer native CPU tuning:

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench proof_size_roundtrip -- --noplot
```

The benchmark currently:

- uses Criterion with `sample_size(10)`
- generates a synthetic satisfiable R1CS fixture
- proves and verifies with `KeccakEngine<OcticBinExtension>` and `WhirPcs`
- emits a tracing-style proof-size tree before the Criterion timing output

Supported benchmark environment overrides:

- `SPARTAN_WHIR_BENCH_K`
- `SPARTAN_WHIR_BENCH_NUM_CONSTRAINTS`
- `SPARTAN_WHIR_BENCH_NUM_IO`
- `SPARTAN_WHIR_BENCH_A_TERMS`
- `SPARTAN_WHIR_BENCH_B_TERMS`
- `SPARTAN_WHIR_BENCH_SEED`

The default benchmark configuration is the SHA-like comparison case discussed in this repository:

- `k = 19`
- `num_constraints = 2^19`
- `num_io = 256`
- `a_terms = 2`
- `b_terms = 1`

The proof-size tracing output is intended for human inspection and is rendered as an `INFO` tree with labeled `key: value` fields, for example:

```text
INFO     proof_size_roundtrip | total_bytes: ...
INFO     ┝━ header | bytes: ... | pct_of_parent: ... | pct_of_total: ...
INFO     ┕━ whir | bytes: ... | pct_of_parent: ... | pct_of_total: ...
INFO        ┝━ whir_initial | ...
INFO        ┕━ whir_final | ...
```
