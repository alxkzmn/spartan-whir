# spartan-whir

`spartan-whir` is a Spartan-oriented proving system built on Plonky3 fields with `whir-p3` as the multilinear PCS backend.

## Phase 3 Status

Phase 3 is now implemented for the concrete backend:

- Engine: `KoalaKeccakEngine`
  - `F = KoalaBear`
  - `EF = BinomialExtensionField<F, 4>`
  - `W = u64`, `DIGEST_ELEMS = 4`
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

## Implemented Modules

- `src/engine.rs`
  - Concrete Koala+Keccak engine/challenger constructors
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
- `src/profiling.rs`
  - No-op structural hooks (`ProtocolObserver`, `ProtocolStage`)

## Still Out of Scope

- Zero-knowledge mode
- Full EVM verifier contract implementation
- Proof-size/gas accounting implementation (hooks exist, accounting logic not implemented)
- Non-Koala/non-WHIR backend generalization for Spartan execution path

## Run Tests

```bash
cargo test
cargo test --features keccak_no_prefix
```

Test suite includes:

- WHIR PCS lifecycle and ordering regression tests
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
