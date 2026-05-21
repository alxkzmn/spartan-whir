# SPARK-Powered Spartan-WHIR Verifier Plan

## Summary

1. The scalable full-Spartan verifier path is SPARK-powered sparse-matrix closing over WHIR.
2. Direct sparse R1CS evaluation remains only a small-fixture oracle and negative-control benchmark.
3. Spartan-LC is deferred until classic Spartan-with-SPARK has Rust measurements and Solidity gas numbers.
4. This plan is quintic-only.

## Current State

#### Rust Paths

`spartan-whir` now supports both matrix-closing modes through
`MatrixClosingMode` / `SpartanSnarkConfig`:

1. `DirectSparse` runs the original direct sparse matrix evaluation. It is useful
   for tests and small correctness oracles only.
2. `Spark` runs the SPARK sparse-matrix closing path in
   `spartan-whir/src/spark.rs` and
   `SpartanProtocol::{prove_spark, verify_spark}`.

The selected mode is bound into the Spartan domain separator and into the
proving/verifying keys. Proof-kind or key-mode mismatches reject with
`ProofKindMismatch`.

#### Direct Sparse Closing

The direct verifier closes the R1CS relation by scanning sparse matrix entries:

```text
sum_{(row, col, val) in M} eq_rx[row] * eq_y[col] * val
```

The Rust code path is:

1. `spartan-whir/src/protocol.rs` calls `shape_canonical.evaluate_with_tables`.
2. `spartan-whir/src/r1cs.rs` implements `evaluate_sparse_matrix_with_tables`.

This algorithm is not deployable on EVM for SHA-scale circuits. The Solidity
negative-control model measured the direct sparse-scan kernel at `8,466,956`
gas for only `192` synthetic A/B/C entries; scaling the same primitive to
measured SHA shapes lands in tens to hundreds of billions of gas. That result
only rules out direct scanning, not Spartan.

#### SPARK Closing

The Rust SPARK path uses:

1. `2` rectangular setup commitments:
   - value bundle: `row`, `col`, `val_A`, `val_B`, `val_C`, `read_ts_row`,
     `read_ts_col`, and one zero padding column;
   - audit bundle: `audit_ts_row`, `audit_ts_col`.
2. `1` rectangular per-proof read commitment:
   - `erow` and `ecol`, decomposed into quintic base-coordinate columns and
     padded to `16` selector columns.
3. A measurement-gated shared union skeleton when
   `union_ratio <= 1.5`.
4. A compatibility fallback branch for shapes above the threshold. That branch
   is functional in Rust but is not the final Spartan-style independent-stream
   product layer.
5. `proof_ops`, which batches row read/write products, column read/write
   products, and six split `val_A` / `val_B` / `val_C` dotproduct claims.
6. `proof_mem`, which batches row init/audit and column init/audit products over
   the padded memory domain.

Fixed/read WHIR openings are derived from `proof_ops.product_point`,
`proof_ops.dotproduct_point`, and `proof_mem.product_point`.

## Reference Implementations

The current SPARK design was cross-checked against the original Spartan
implementation and the arkworks Spartan port:

1. Microsoft Spartan: <https://github.com/microsoft/Spartan>.
2. arkworks Spartan: <https://github.com/arkworks-rs/spartan>.

Their sparse multilinear-polynomial modules provide the reference shape for
sparse matrix preprocessing, memory timestamp checks, `proof_ops`, `proof_mem`,
and split dotproduct claims. Their product-tree modules provide the reference
shape for batched product proofs and `DotProductCircuit`.

`spartan-whir` deliberately differs in two places:

1. It uses WHIR commitments and rectangular bundled openings instead of the
   original PCS interface.
2. It prefers a shared union skeleton when the measured union ratio is small.
   If the union ratio is too large, the implementation falls back to the
   compatibility branch rather than forcing the shared layout.

## SPARK Target

#### Layout Decision

The gas-oriented layout decision is measurement-first:

```text
union_ratio = |nnz(A) union nnz(B) union nnz(C)| / max(nnz_A, nnz_B, nnz_C)
```

Use the shared union skeleton only when `union_ratio <= 1.5`. The shared union
skeleton:

1. aggregates duplicate `(row, col)` entries within each matrix;
2. sorts union entries lexicographically by `(row, col)`;
3. stores one row stream and one column stream;
4. stores `val_A`, `val_B`, and `val_C`, using zero where a matrix is absent;
5. pads with `(row=0, col=0, val_A=val_B=val_C=0)`.

The `32N -> 8N` fixed-bundle and `64N -> 16N` read-bundle reductions apply only
when the union ratio is close to `1`.

#### Verifier-Key Binding

The verifier key / generated verifier must bind:

1. the R1CS shape;
2. the matrix-closing mode;
3. the row/column bit widths and packed-index bounds;
4. the chosen SPARK layout, union-ordering rule, and padded sparse-entry domain
   sizes;
5. the fixed sparse-table commitments;
6. the WHIR schedule and Fiat-Shamir domain data for those commitments.

The prover must not choose matrix data. If the verifier key embeds commitments
rather than full tables, matrix correctness moves to fixture generation /
verifier generation; the on-chain verifier checks openings against those
commitments.

#### Product-Layer Shape

`SparkSpartanProof` carries the batched product-layer proof object:

1. `proof_ops` runs over the value domain and batches:
   - row read;
   - row write;
   - column read;
   - column write;
   - split dotproduct claims ordered as `A_low`, `A_high`, `B_low`, `B_high`,
     `C_low`, `C_high`.
2. `proof_mem` runs over `max(row_memory_size, col_memory_size)` and batches:
   - row init;
   - row audit;
   - column init;
   - column audit.

The split dotproduct pairs reconstruct:

```text
eval_A = A_low + A_high
eval_B = B_low + B_high
eval_C = C_low + C_high
```

The Spartan closing then uses the existing inner-sumcheck matrix-combination
challenge `r`:

```text
spark_matrix_eval = eval_A + r * eval_B + r^2 * eval_C
inner_final_claim == spark_matrix_eval * eval_z
```

The top-level SPARK value sumcheck and independent grand-product helpers remain
as reference/test APIs only. They are not the `prove_spark` / `verify_spark`
proof path.

## Quintic Gas Model

#### Existing Anchors

Measured on `2026-05-19`:

| item                                               |   gas / bytes |
| -------------------------------------------------- | ------------: |
| current quintic native WHIR blob verifier test gas |     5,526,933 |
| current profiled phase sum                         |     4,768,297 |
| all current WHIR sumchecks                         |       146,153 |
| current standalone-WHIR proof blob                 |  54,330 bytes |
| Spartan inner-sumcheck transcript replay floor     |   134,577 gas |
| direct sparse scan for 192 synthetic A/B/C entries | 8,466,956 gas |

The direct sparse scan number is a negative-control result. It is not a
production-verifier estimate.

#### Shape Inputs

The SPARK model should be parameterized by:

```text
num_rows, num_cols, nnz_A, nnz_B, nnz_C, union_nnz
```

For Spartan2 SHA-256:

| input bytes | padded constraints | padded variables | total A/B/C nonzeros |
| ----------: | -----------------: | ---------------: | -------------------: |
|       1,024 |            524,288 |          524,288 |            2,440,431 |
|       2,048 |          1,048,576 |        1,048,576 |            4,780,623 |
|       4,096 |          2,097,152 |        2,097,152 |            9,461,007 |

For ProveKit SHA-256:

| input bytes | optimized constraints | committed witnesses | raw A/B/C entries before preprocessing |
| ----------: | --------------------: | ------------------: | -------------------------------------: |
|       1,024 |               196,940 |             339,764 |                              1,131,648 |
|       2,048 |               345,399 |             612,724 |                              2,058,122 |
|       4,096 |               605,463 |           1,059,124 |                              3,608,938 |

Do not use SHA input bytes as the primary parameter. Use the R1CS shape and
sparse matrix counts.

#### Rust Operation Report

`SparkVerifierOperationReport` reports the current batched product proof shape.
It distinguishes product-tree layers from replayed cubic sumcheck rounds: a
product proof over domain `2^k` has `k` layers and
`0 + 1 + ... + (k - 1)` cubic sumcheck rounds.

For the ProveKit SHA 2KiB optimized profile row used by the layout estimator:

| item                                                              |                         value |
| ----------------------------------------------------------------- | ----------------------------: |
| rows / columns                                                    |           `345,399 / 612,724` |
| modeled `nnz_A / nnz_B / nnz_C`                                   | `700,000 / 700,000 / 658,122` |
| modeled union nonzeros                                            |                     `760,000` |
| padded value domain                                               |                   `1,048,576` |
| padded memory domain                                              |                   `1,048,576` |
| setup commitments                                                 |                           `2` |
| per-proof commitments                                             |                           `1` |
| `proof_ops` layers / cubic rounds                                 |                    `20 / 190` |
| `proof_mem` layers / cubic rounds                                 |                    `20 / 190` |
| total product-layer cubic rounds                                  |                         `380` |
| fixed value bundle slots                                          |                   `8,388,608` |
| read bundle slots at quintic                                      |                  `16,777,216` |
| product-layer extension elements                                  |                       `1,505` |
| opening-evaluation extension elements                             |                          `42` |
| raw product-layer bytes at quintic, excluding WHIR opening proofs |                      `30,100` |
| raw opening-evaluation bytes at quintic                           |                         `840` |
| duplicated commitment bytes in the current Rust proof object      |                          `96` |
| raw SPARK payload bytes excluding WHIR opening proofs             |                      `31,036` |

These bytes are Rust-side canonical-element estimates, not final Solidity
calldata numbers. They intentionally exclude the three WHIR opening proofs for
the fixed value bundle, fixed audit bundle, and read bundle.

`SparkVerifierOperationReport::estimate_solidity_gas` maps the report to:

1. product-layer cubic sumcheck replay gas;
2. three sparse-table WHIR opening execution costs;
3. raw SPARK payload calldata gas upper bound;
4. sparse-table WHIR opening calldata gas upper bound.

The estimator deliberately takes per-round and per-opening gas as inputs. Do
not freeze guessed constants in the Rust model.

## Spartan-LC After SPARK

Spartan-LC is no longer the scaling mechanism. It is a later comparison between
two SPARK-powered paths:

1. classic Spartan-with-SPARK verifies the outer sumcheck, inner sumcheck, and
   SPARK matrix closing;
2. Spartan-LC-with-SPARK removes the inner sumcheck and `witness_eval`;
3. both paths use the same SPARK sparse-matrix closing strategy.

The expected Spartan-LC proof body saving remains:

```text
saved_body_bytes = 4 + (2 * (log2(num_vars_padded) + 1) + 1) * ext_bytes
```

For k22 quintic:

```text
saved_body_bytes = 944
calldata_saving <= 944 * 16 = 15,104 gas
inner_sumcheck_replay_floor ~= 134,577 gas
```

This is useful only after the SPARK path has Solidity gas measurements.

## Next Work

#### Rust Measurements

1. Keep direct sparse and SPARK roundtrip tests in parallel.
2. Refresh `SparkVerifierOperationReport` on the target quintic shape whenever
   the SPARK proof object, WHIR opening strategy, or matrix layout changes.
3. Track proof bytes, opening counts, product-layer rounds, and estimated
   calldata bytes.

#### Solidity Work

Solidity implementation is on hold until the Rust report has stable counts. The
next Solidity-facing work is measurement, not a full verifier:

1. optimized replay kernel for SPARK cubic product-layer sumchecks;
2. optimized verifier model for the three sparse-table WHIR openings;
3. calldata accounting for the SPARK payload plus WHIR opening proofs.

#### Spartan-LC Re-evaluation

Reopen Spartan-LC only after classic Spartan-with-SPARK has both Rust proof-size
measurements and Solidity gas profiling. Promote Spartan-LC only if total
transaction gas and proof bytes both decrease on the same fixture.

## Acceptance Criteria

1. No production Solidity path scans sparse R1CS entries on-chain.
2. No production Solidity path materializes dense `2^k` matrix-weight vectors.
3. SPARK proof verification matches direct `evaluate_with_tables` on small Rust
   fixtures.
4. SPARK tamper tests fail for changed matrix values, row/column streams,
   timestamps, commitments, product claims, and opening evaluations.
5. The quintic SPARK verifier has measured Rust proof bytes and verifier
   operation counts before Solidity work starts.
6. Spartan-LC is evaluated only after classic Spartan-with-SPARK is measured.
