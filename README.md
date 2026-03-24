# spartan-whir

`spartan-whir` is a Spartan-oriented proving system built on Plonky3 fields with `whir-p3` as the multilinear PCS backend.

## Current Backend

- Engine: `KeccakEngine<Ext>`
  - `QuarticBinExtension = BinomialExtensionField<F, 4>`
  - `QuinticExtension = QuinticTrinomialExtensionField<F>`
  - `OcticBinExtension = BinomialExtensionField<F, 8>`
  - Extension choice is a compile-time engine parameter, not a runtime switch
  - Fixed parameters: `F = KoalaBear`, `W = u64`, `DIGEST_ELEMS = 4`
- PCS: `WhirPcs`
- Protocol: `SpartanProtocol::setup/prove/verify`
- Transcript and commitment stack: Keccak challenger plus Keccak Merkle hashing

## Current Capabilities

- Real outer cubic and inner quadratic sumchecks
- Real R1CS operations: `pad_regular`, `multiply_vec`, `bind_row_vars`, `evaluate_with_tables`, `witness_to_mle`
- Public instance is external to the proof: `verify(vk, instance, proof, challenger)`
- `prove` returns `(instance, proof)`
- WHIR verification is split into commitment-parse and finalize phases to preserve transcript continuity
- The implemented PCS statement path used by `SpartanProtocol` is point-evaluation-only today
- Linear and tensor-product PCS constraints are still roadmap items and are rejected by the current live Spartan/WHIR path
- Blob codec v1 encodes `Proof + Instance`
- `SpartanBlobDecodeContext::from_vk` derives an engine-typed decode context from the verifying key
- Codec v1 records extension degree explicitly in the header
- `profile_spartan_blob_v1` and `encode_spartan_blob_v1_with_report` provide deterministic size reporting

## Extension Support

- Quartic and quintic are covered by the PCS, protocol, codec, and profiling test matrix
- Octic is available in the engine surface and is used by the proof-size benchmark target
- Benchmarking with different extensions is expected to be workload-dependent; extension choice is part of the measurement surface

Current WHIR integration does not enable the univariate-skip path. If skip support is added later, extension-specific two-adicity limits will need to be reviewed; for KoalaBear quintic, skip width must stay within 24.

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

## Potential Future Upgrade

- `Spartan-LC` (linear-constraint-based Spartan path) is documented as a possible future protocol upgrade:
  - See [`SPARTAN_LC_UPGRADE_PLAN.md`](SPARTAN_LC_UPGRADE_PLAN.md)
  - The plan includes two tracks:
    - Dense/tensor now (limited path)
    - Sparse-linear extension (scalable long-term path)
  - This is not implemented yet and is roadmap-only at this stage.

## Synthetic R1CS Fixtures

- `spartan-whir` now includes synthetic fixture generators for targeted WHIR witness commitment sizes:
  - `generate_satisfiable_fixture(...)`
  - `generate_satisfiable_fixture_for_pow2(k)`
- These helpers produce satisfiable regular R1CS tuples `(shape, witness, public_inputs)` with witness length exactly `2^k`.
- This is intended for large-size protocol tests and benchmark scaffolding.
- The benchmark fixtures are synthetic and only shape-similar to target circuits such as Spartan2 SHA-256.
- They are useful for matching rough constraint count / witness size / row sparsity, but they are not literal SHA-256 gadgets and should be described that way.

## Still Out of Scope

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
