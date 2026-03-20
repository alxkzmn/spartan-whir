# spartan-whir

`spartan-whir` is a Spartan-oriented proving system built on Plonky3 fields with `whir-p3` as the multilinear PCS backend.

## Phase 4 Status

Phases 3 and 4 are implemented for the KoalaBear + Keccak backend:

- Engine: `KeccakEngine<Ext>`
  - Alias: `KeccakQuarticEngine` with `QuarticExtension = BinomialExtensionField<F, 4>`
  - Alias: `KeccakQuinticEngine` with `QuinticExtension = QuinticTrinomialExtensionField<F>`
  - Fixed parameters: `F = KoalaBear`, `W = u64`, `DIGEST_ELEMS = 4`
- PCS: `WhirPcs` (`commit -> open -> verify`)
- Spartan core:
  - Real `SpartanProtocol::setup/prove/verify`
  - Real outer cubic and inner quadratic sumchecks
  - Real R1CS operations (`pad_regular`, `multiply_vec`, `bind_row_vars`, `evaluate_with_tables`, `witness_to_mle`)
  - Public instance is external to proof (`verify(vk, instance, proof, challenger)`)
  - `prove` returns `(instance, proof)`
- Transcript correctness:
  - Spartan domain separator + public inputs are absorbed before PCS commit
  - WHIR verify is split into commitment-parse and finalize phases to preserve transcript continuity
- Codec and profiling:
  - Canonical Spartan blob codec v1 (`Proof + Instance`) with strict decode checks
  - Decoder context is engine-typed and derived from VK (`SpartanBlobDecodeContext::from_vk`)
  - Blob header includes explicit extension degree; quartic and quintic blobs are self-describing
  - Deterministic size reporting (`profile_spartan_blob_v1`, `encode_spartan_blob_v1_with_report`)

## Implemented Modules

- `src/engine.rs`
  - Generic `KeccakEngine<Ext>` plus quartic/quintic engine aliases and challenger constructors
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
