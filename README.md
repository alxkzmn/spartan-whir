# spartan-whir

`spartan-whir` implements a Spartan-oriented API surface with a concrete WHIR multilinear PCS adapter for KoalaBear + Keccak.

Phase 2 adds a real vertical slice for PCS operations:

- `commit -> open -> verify` works through `whir-p3` via `MlePcs`.
- Engine is concrete (`KoalaKeccakEngine`) with:
  - `F = KoalaBear`
  - `EF = BinomialExtensionField<F, 4>`
  - `W = u64`, `DIGEST_ELEMS = 4`
  - Keccak-based Merkle hash/compression and challenger.
  - Merkle hashers are `KeccakFieldLeafHasher` and `Keccak256NodeCompress`.
  - Digest truncation is controlled by `merkle_security_bits` via
    `effective_digest_bytes_for_security_bits(...)`.
- Point-evaluation statements are supported.
- Unsupported statement modes (linear/tensor constraints) are rejected in this phase.

## Implemented in Phase 2

- `src/engine.rs`
  - `KoalaKeccakEngine` and constructors for hash/compress/challenger.
- `src/hashers.rs`
  - Keccak256 byte-level leaf/node hashers with domain prefixes and digest-byte masking.
  - Types: `KeccakFieldLeafHasher` and `Keccak256NodeCompress`.
  - Optional feature: `keccak_no_prefix` disables `0x00`/`0x01` domain prefixes for hash inputs.
  - EVM-compatible `[u64;4] <-> bytes32` conversions.
- `src/whir_pcs.rs`
  - `WhirPcsConfig`, `WhirPcs`, `WhirProverData`.
  - Real WHIR-backed `MlePcs` implementation.
  - Correct WHIR Fiat-Shamir domain-separator sequence.
  - Correct statement ordering (`user claims` then `OOD`) on prover side.
  - Verify path that relies on verifier-side OOD concatenation from parsed commitment.
- `src/statement.rs`
  - `PointEvalClaim.point` is now `MultilinearPoint<E::EF>`.
- `src/error.rs`
  - Adapter-specific errors for commit/open/verify/mismatch/shape issues.

## Still Stubbed in Phase 2

- Full Spartan protocol (`SpartanProtocol::setup/prove/verify`)
- Spartan outer/inner sumcheck protocol internals
- EVM codec/proof-size profiling implementation
- Zero-knowledge mode

## Run Tests

```bash
cargo test
```

The suite includes Phase 1 contract tests and Phase 2 WHIR adapter tests:

- roundtrip point-eval proofs
- constraint-ordering regression guard
- tampered commitment rejection
- wrong-evaluation rejection
- polynomial shape/variable mismatch rejections
- transcript checkpoint consistency
- explicit domain-separator sequence alignment
