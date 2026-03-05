# Spartan-LC Upgrade Plan: Dense/Tensor Now (Limited) + Sparse-Linear Extension (Real Path)

## Summary

1. Add a new Spartan linearized proving path that uses WHIR linear constraints to remove Spartan's inner sumcheck from the proof.
2. Deliver this in two tracks:
3. Track A (now): use existing `whir-p3` dense/tensor linear constraints; implement a working `Spartan-LC` path with clear limits.
4. Track B (real path): extend `whir-p3` with sparse linear constraints and switch `Spartan-LC` to sparse weights for scalability.
5. Keep current classic Spartan path untouched and default; ship `Spartan-LC` as additive APIs until metrics confirm migration.

## Why This Improves Spartan

1. Current classic proof includes inner sumcheck + `witness_eval`.
2. `Spartan-LC` replaces inner sumcheck with a single PCS linear opening claim over committed witness `W`.
3. Expected blob-size reduction per proof (vs classic) is deterministic:
4. Saved bytes = `20 + 32 * (log2(num_vars_padded) + 1)` in current sectioned encoding model.
5. Example at `num_vars_padded = 2^16`: save `564` bytes before any WHIR-level tuning.

---

## Track A: Dense/Tensor Now (Limited, Implementable in `spartan-whir` Today)

## A1. Public API Changes (additive, no breaking removals)

1. Keep existing classic APIs/types unchanged.
2. Add new proof type in `src/protocol.rs`:
3. `pub struct SpartanLcProof<E, Pcs> { outer_sumcheck, outer_claims, pcs_proof }`.
4. Add new protocol methods:
5. `SpartanProtocol::prove_lc_dense(...) -> Result<(R1csInstance<...>, SpartanLcProof<...>), SpartanWhirError>`.
6. `SpartanProtocol::verify_lc_dense(...) -> Result<(), SpartanWhirError>`.
7. Extend statement surface in `src/statement.rs`:
8. Replace current linear claim payload with an explicit kind enum:
9. `Dense { coefficients: Evaluations<E::EF> }`.
10. `TensorProduct { range_start, log_range_len, row_weights: Evaluations<E::EF>, col_weights: Evaluations<E::EF> }`.
11. Keep `expected: E::EF`.
12. Add builder helpers:
13. `add_dense_linear_constraint(...)`.
14. `add_tensor_linear_constraint(...)`.
15. Keep `add_linear_constraint(claim)` as compatibility wrapper.
16. Add/rename error variants in `src/error.rs`:
17. `InvalidLinearConstraint`.
18. Keep `UnsupportedStatementType` only for modes still intentionally excluded (none after A2 except future sparse-only guards).

## A2. WHIR Adapter Changes (`whir_pcs.rs`)

1. Remove hard rejection of linear constraints in `src/whir_pcs.rs`.
2. In `build_user_statement`, map each finalized claim to WHIR `EqStatement<KoalaExtension>`:
3. Point eval claims -> `add_evaluated_constraint`.
4. Dense linear claims -> `add_linear_constraint`.
5. Tensor claims -> `add_tensor_product_constraint`.
6. Validation rules before WHIR call:
7. Dense coefficients length must be exactly `1 << num_variables`.
8. Tensor block must satisfy WHIR alignment and power-of-two conditions.
9. All coefficient vectors must be extension-field vectors (`EF`), not base-field vectors.
10. Keep existing commit/open/verify transcript ordering and OOD ordering rules unchanged.

## A3. Spartan-LC Dense Algorithm (new protocol path)

1. In prover, keep setup/commit/outer-sumcheck transcript order identical to current classic path.
2. After outer sumcheck:
3. Sample `r`.
4. Compute `claim_inner_joint = Az + r*Bz + r^2*Cz`.
5. Compute `T_x = EqPolynomial::evals_from_point(r_x)`.
6. Compute bound rows `(Abar, Bbar, Cbar)` via `bind_row_vars`.
7. Compute `J = Abar + r*Bbar + r^2*Cbar` (length `2*num_vars_padded`).
8. Split `J` into `J_w` (first half, witness part) and `J_pub` (second half, public/constant part).
9. Compute known `public_contrib = <J_pub, [1, public_inputs..., 0...]>`.
10. Compute linear witness claim `claim_w = claim_inner_joint - public_contrib`.
11. Build finalized PCS statement with one dense linear constraint:
12. `weights = J_w`, `expected = claim_w`.
13. Run PCS `open`.
14. Return `(instance, SpartanLcProof { outer_sumcheck, outer_claims, pcs_proof })`.
15. In verifier, repeat deterministic reconstruction of `J_w` and `claim_w`, then call PCS `verify` with the same linear statement.
16. No inner sumcheck and no `witness_eval` in `SpartanLcProof`.

## A4. Codec + Profiling for LC Proofs

1. Keep classic blob codec `v1` unchanged.
2. Add LC codec `v2` in new module `codec_v2.rs` (or `codec_lc_v1.rs`, pick one and keep naming consistent):
3. Header keeps same magic family, `version=2`.
4. Sections for LC proof are fixed and minimal:
5. `instance`.
6. `outer_sumcheck`.
7. `outer_claims`.
8. `pcs_whir_proof`.
9. Add API wrappers in `src/codec.rs`:
10. `encode_spartan_lc_blob_v2`.
11. `decode_spartan_lc_blob_v2`.
12. `encode_spartan_lc_blob_v2_with_report`.
13. Add deterministic profile support for LC sections in `src/profiling.rs`, reusing shared traversal.
14. Keep decode context derived from VK and WHIR expectations as in v1 strict model.

## A5. Track A Tests

1. Statement tests:
2. Dense linear claim finalize/validation.
3. Tensor linear claim finalize/validation.
4. WHIR PCS tests:
5. Dense linear roundtrip success.
6. Tensor linear roundtrip success.
7. Tampered expected value fails.
8. Invalid dense length fails with `InvalidLinearConstraint`.
9. Invalid tensor alignment/shape fails with `InvalidLinearConstraint`.
10. Spartan-LC protocol tests:
11. Roundtrip success (regular and auto-padded shapes).
12. Tampered commitment fails.
13. Tampered outer claims fail.
14. Tampered PCS proof fails.
15. Transcript checkpoint equivalence.
16. Codec/profile tests:
17. LC blob v2 roundtrip.
18. Section strictness rejections.
19. Profile total equals encoded length.
20. All classic Phase 2/3/4 tests remain green.

## A6. Track A Limits (explicit)

1. Dense weights are full-length `2^k` vectors and can be expensive in prover memory/time for large `k`.
2. Tensor constraints are only useful when constraints naturally admit rank-1 contiguous block form.
3. No automatic dense->tensor decomposition in Track A.

---

## Track B: Sparse-Linear Extension (Real Path, Requires `whir-p3` Changes)

## B1. `whir-p3` Core Extension

1. Extend `LinearConstraint` in WHIR statement layer with a sparse variant:
2. `Sparse { indices: Vec<usize>, values: Vec<F> }` with strict invariants.
3. Add constructor API:
4. `EqStatement::add_sparse_linear_constraint(indices, values, eval)`.
5. Extend WHIR constraint logic:
6. Statement verification path supports sparse dot-product checks.
7. Combined-weight construction handles sparse accumulation.
8. Constraint evaluator path handles sparse MLE basis evaluation at random points.
9. Add packed/unpacked parity tests and existing-roundtrip parity tests for sparse.

## B2. `spartan-whir` Sparse Claim Surface

1. Extend statement claim enum with `Sparse` variant:
2. `Sparse { indices: Vec<u32>, values: Evaluations<E::EF>, domain_size_log2: u8 }`.
3. Add builder helper:
4. `add_sparse_linear_constraint(...)`.
5. In adapter conversion, map to WHIR sparse constraint.
6. Add strict validation:
7. sorted unique indices.
8. index bounds.
9. values length matches indices length.
10. domain log matches `num_variables`.

## B3. Spartan-LC Sparse Protocol Path

1. Keep proof type and verifier equations from Track A unchanged.
2. Replace dense `J_w` materialization with sparse derivation:
3. Add `R1csShape::bind_row_vars_sparse` producing sparse column accumulators directly from matrix entries and `eq_rx`.
4. Form sparse joint weights `J_w_sparse = A_sparse + r*B_sparse + r^2*C_sparse`.
5. Compute `public_contrib` from sparse public-half terms.
6. Build sparse linear PCS statement and open/verify.
7. Dense path remains for fallback/comparison until sparse reaches parity.

## B4. Track B Tests

1. `whir-p3` tests:
2. sparse constraint validity/rejections.
3. sparse vs dense equivalence on random polynomials.
4. packed vs unpacked sparse parity.
5. `spartan-whir` tests:
6. sparse linear statement roundtrip.
7. sparse vs dense `prove_lc` verification equivalence.
8. same acceptance/rejection behavior under tampering.
9. Optional perf test targets:
10. no full `2^k` witness-weight allocation in sparse path.
11. prove-time and memory improved on large synthetic shapes.

---

## Rollout and Decision Gates

1. Milestone 1: Track A A1+A2 (functional Spartan-LC dense + tensor pass-through).
2. Milestone 2: Track A A4 (LC codec/profile) and publish comparative size report against classic.
3. Milestone 3: Track B `whir-p3` sparse extension landed (local patch first, upstream later).
4. Milestone 4: Track B `spartan-whir` sparse integration and dense-vs-sparse parity.
5. Promotion rule:
6. Keep classic default until LC sparse passes parity and profiling gates.
7. After promotion, keep classic as compatibility mode for at least one codec version cycle.

## Acceptance Criteria

1. Track A:
2. `prove_lc_dense/verify_lc_dense` works end-to-end and remains transcript-consistent.
3. WHIR adapter supports point + dense/tensor constraints correctly.
4. LC blob codec version is strict and deterministic.
5. Classic APIs and tests are unaffected.
6. Track B:
7. Sparse constraints are fully supported in WHIR and `spartan-whir`.
8. Spartan-LC sparse verifies exactly where dense verifies.
9. Sparse path removes full dense weight allocation from Spartan-LC proving.
10. Codec and profile outputs remain deterministic and strict.

## Assumptions and Defaults

1. Default proving APIs remain classic (`SpartanProof`) until LC sparse is mature.
2. `Spartan-LC` ships as additive APIs (`SpartanLcProof`, `prove_lc_dense`, `verify_lc_dense`).
3. Track A uses dense witness linear constraint for Spartan-LC; tensor is pass-through/manual only.
4. LC serialization uses a new codec version; classic codec v1 remains frozen.
5. Non-ZK mode remains unchanged in both tracks.
