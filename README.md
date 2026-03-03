# spartan-whir

`spartan-whir` is the Phase 1 contract crate for a Spartan SNARK built on Plonky3-style field/challenger APIs, with WHIR intended as the multilinear PCS backend.

This phase is intentionally **API-first**:

- Public traits and type contracts are defined.
- Methods are stubbed and return typed `Unimplemented` errors where implementation is deferred.
- Tests focus on contract shape, invariants, and stub behavior.

No prover/verifier cryptographic logic is implemented yet.

## Phase 1 Scope

Implemented in this crate:

- Engine/config contracts (`SpartanWhirEngine`, security, WHIR params, codec levers)
- R1CS data model (`R1csShape`, `R1csWitness`, `R1csInstance`, `SparseMatrix`)
- PCS statement builder/finalized types (`PcsStatementBuilder` -> `PcsStatement`)
- PCS trait surface (`MlePcs`)
- Protocol/key/proof type surface (`SpartanProtocol`, `ProvingKey`, `VerifyingKey`, `SpartanProof`)
- Sumcheck contract surfaces (outer cubic / inner quadratic round data)
- Domain separator contract and deterministic encoding

Out of scope in Phase 1:

- Real `setup/prove/verify` internals
- Real WHIR `commit/open/verify` adapter internals
- EVM proof encoding/profiling implementation
- Zero-knowledge mode

## Module Map

- `src/config.rs`: engine trait
- `src/security.rs`: security config + invariants
- `src/whir_params.rs`: WHIR-only knobs
- `src/codec.rs`: proof encoding levers
- `src/error.rs`: typed error taxonomy
- `src/poly.rs`: polynomial and compressed round-poly types
- `src/r1cs.rs`: R1CS model and shape validation
- `src/statement.rs`: PCS statement builder/finalized split
- `src/pcs.rs`: PCS trait
- `src/sumcheck.rs`: outer/inner sumcheck contract stubs
- `src/domain_separator.rs`: transcript/domain binding surface
- `src/protocol.rs`: protocol/key/proof contract stubs

## Current Status

- `#![cfg_attr(not(test), no_std)]` is enabled.
- Stubs return `SpartanWhirError::Unimplemented(...)` for deferred logic paths.
- One linear-constraint future-path test is intentionally `#[ignore]`.

## Run Tests

```bash
cargo test
```

## Next Phase

Phase 2 will wire these contracts to concrete WHIR prover/verifier flows, replace stubs with real protocol logic, and begin integrating proof-size and EVM-oriented profiling hooks.
