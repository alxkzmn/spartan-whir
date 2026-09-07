# SPARK proof size and LeanVM verifier work

#### Measured result

The optimized guest consumes **2,333,288 canonical input bytes**, down from **2,730,792** (14.556%), and executes in **28,394,906 cycles**, down from **33,485,006** (15.201%). Memory falls from **36,861,485 to 31,757,474 cells**. This crosses a padding boundary: the memory table drops from `2^26` to `2^25` cells. Extension operations fall from **1,622,974 to 1,590,309** (2.013%). Poseidon1 calls remain **100,106**. The other padded tables remain `2^25` execution rows, `2^21` extension rows and `2^17` Poseidon rows.

These are exact execution counts for the existing production SHA-256 fixture. Canonical input includes the application instance and framing. The original input also carries unused padding to 4,194,304 bytes; that padding is excluded from the 14.556% size comparison. The inner WHIR schedule, roots, sampled queries, security parameters and public statement are unchanged.

The implementation is opt-in through `SparkGuestOptimizations::recommended()` and `compile_full_zk_spark_poseidon1_guest_with_optimizations`. `compact_full_zk_spark_words` prepares its witness. The ordinary compile API retains its input format and exact execution counts. Added helper functions change compiled bytecode identities, including the lift and binary node that bind the child program. Their profiles and proof checks are refreshed. The optimized guest is also available through the binary-node command; its recursion check uses the same valid lifted proof in both ordered child slots.

#### Prover cost

Criterion measures preparation separately from execution-proof generation, native verification and serialization. On the same machine with 12 threads:

| Measurement | Ordinary guest | Optimized guest |
| --- | ---: | ---: |
| Execution-proof pipeline mean | 25.548 s | 24.394 s |
| 95% confidence interval | 25.484–25.612 s | 23.901–24.930 s |
| Compact input preparation | — | 0.418 ms (95% CI 0.415–0.421 ms) |
| One verified outer proof | 743,989 B | 718,613 B |

The measured pipeline is 4.516% faster. Every timed proof is verified natively. The outer proof sizes are individual samples; outer proof-of-work can change them. These are direct guest measurements. The lift and binary-node runs below are correctness checks, not a statistical recursion timing comparison.

#### Complete optimization rounds

Every candidate below was implemented and executed. The first six were tested separately against the ordinary guest, then combined. The next four were measured against the corresponding preceding combination; the two query changes were also measured separately before combination.

| Candidate | Change in guest cycles | Change in extension rows | Canonical bytes removed |
| --- | ---: | ---: | ---: |
| Fresh-row equation through the extension addition instruction | -260,500 | +10,420 | 0 |
| Newton-Horner SPARK cubic evaluation | -1,764 | -1,323 | 0 |
| SPARK equality-polynomial instruction | -18,604 | -882 | 0 |
| Factor equality from product endpoints | -43 | -129 | 0 |
| Reuse checked query bits during Merkle traversal | -3,115,375 | 0 | 0 |
| Share carried/fresh Merkle traversal | -1,075,100 | 0 | 0 |
| Reconstruct fresh rows inside their existing evaluation loop | +19,512 | 0 | 208,400 |
| Simplify query distinctness-product indexing | -595,994 | 0 | 0 |
| Reuse radix-sort zero prefixes | -417,174 | 0 | 0 |
| Hash and fold structured initial rows directly | +14,175 | -40,751 | 174,048 |

The Merkle savings overlap, so individual cycle savings must not be added. The full first round ends at 2,348,344 bytes, a 14.005% reduction from its starting input. Fresh-row omission trades a small instruction increase for fewer input values; structured rows trade a small instruction increase for fewer extension operations and input values.

The second round tries both remaining guest refinements separately and together:

| Candidate | Canonical bytes removed | Cycles | Memory | Extension rows |
| --- | ---: | ---: | ---: | ---: |
| Derive row lengths from checked geometry | 14,796 | -3,012 | -1,970 cells | unchanged |
| Derive SPARK challenge copies, repeated roots and matrix evaluations | 260 | unchanged | unchanged | unchanged |
| Combined | **15,056 (0.641%)** | -3,012 | -1,970 cells | unchanged |

The loop stops after this complete round. The stopping rule applies to the combined reduction from the round's starting representation, not the first candidate below 1%. This is a stopping result for the stated shortlist, not a lower bound over all possible protocols.

#### Guest implementation

Query bits are already Boolean and bound to transcript samples. A Merkle node retains one original query as its representative; its parity at level `l` is that query's bit `l`. Parent indices follow `(index - parity) / 2`. The representative is carried to the parent. This removes repeated bit decompositions while preserving every hash and root check.

Carried and fresh openings at the same positions have the same binary-tree traversal and sibling count. The paired verifier shares index arithmetic and queue control while retaining two digest streams, two authentication paths and two root checks. It checks equality of sibling counts and consumes every sibling.

The compact witness consists of retained intervals of the original logical layout. Named witness hints load those intervals directly into their original addresses. Omitted fields are assigned by existing checked equalities or by extension-operation equations. This avoids copying a compact stream into another array. Hints provide witness values; the verifier constraints establish their correctness.

For fresh hiding rows, the guest computes `fresh = blinded - gamma * carried` using the blinded polynomial evaluation it already needs. It hashes the recovered rows and verifies their existing authentication proofs. There is no transcript replay or repeated codeword evaluation.

Initial fixed-table rows have 56 zero coordinates. Read rows have one value repeated in positions 199 through 255. The guest hashes the conceptual full row using zero or repeated blocks. It folds only the independent values: fixed rows use their nonzero contiguous runs, and read rows combine the tail weights. The compact format uses the fixed production table layout; it is not a generic encoding for arbitrary table geometries.

Row lengths are assigned by the existing constant-length assertions, with explicit stores for the two hiding relation rounds. SPARK beta/gamma copies are assigned by transcript checks, repeated roots by equality with their canonical roots, and matrix evaluations by the checked split-dotproduct sums. The relation-round stores also remove dynamic branches around those fixed lengths. The other derivations add no execution instructions.

#### Other size candidates

The [native transport experiments](README.md) implement and measure field packing, compact integer metadata, factored product rounds, final-row reconstruction, derived product fields and duplicate-column detection. Their full transport reduction is 18.086%, but native decoding plus verification rises from about 61.9 ms to 77.0 ms. That codec is not the guest input format.

31-bit packing and variable-length integers do not reduce the number of KoalaBear values consumed by LeanVM. In-guest unpacking would add range and bit-extraction work. Factored product rounds save 8,400 raw bytes but require reconstructing the original cubic transcript observations; the guest's three-multiplication Newton-Horner evaluator is cheaper than reconstructing and then evaluating those observations. Final-row reconstruction saves 1,980 raw bytes but requires an additional recovery step and a nonzero-pivot case. These remain transport options rather than recommended guest changes.

The second native round also tested nonadjacent duplicate columns (zero additional bytes), compact metadata tags (44 bytes), and redundant product fields (407 bytes after packing). Nullspace and interpolation checks find no additional row omission from the same fresh/final equations. A public fixed-oracle cache would require about 272 MiB and a separate authenticated-memory design in the guest. Changes to Logup, grouping, folding, rates, queries, hash security or masking are outside the fixed-schedule comparison.

#### Binding and verification scope

The application digest is an eight-field public input. The guest hashes the 256 application bits with its embedded statement prefix. Circuit identity, fixed roots, domains, dimensions and schedules are embedded in the compiled program. Proof values are supplied by the prover; roots and claims enter the same transcript positions as in the ordinary guest.

| Challenge scope | Ordered transcript prefix retained | Dependent work | Validation |
| --- | --- | --- | --- |
| SPARK beta/gamma and product rounds | Existing circuit/application context, SPARK geometry, product claims, then each cubic message | Memory products, equality factors and leaf claims | Original proof accepted; sumcheck/opening mutations reject |
| Plain WHIR queries and folds | Existing commitment/domain, OOD answers, round PoW/checkpoint, then query draws | Structured row hashes, folds and Merkle paths | Roots and transcript order retained; fixed/read mutations reject |
| Hiding base-case queries | Existing relation transcript, fresh commitments, gamma and reveals in their existing order | Recover fresh values and authenticate carried/fresh openings | Source, mask, reveal and code-switch mutations reject |
| Query sampling internals | Same candidate draws, rejection rule, distinctness test and termination count | Sorted indices and cached bits | Small-domain regression compares positions and final transcript |

This change does not claim a new audit of the entire Spartan-WHIR or LeanVM protocol. It preserves the existing statement and challenge bindings at the modified guest helpers. The ordinary guest, optimized guest and all 17 existing production mutation cases have been executed. Additional regressions cover Merkle traversal for sparse, adjacent, complete and height-zero query sets, and preservation of query sampling output and transcript state.

#### Commands and artifacts

Run from the LeanVM repository:

```bash
RAYON_NUM_THREADS=12 cargo run --release -p spartan_whir_guest \
  --bin leanvm-full-zk-spark-poseidon1 --offline -- execute recommended
RAYON_NUM_THREADS=12 cargo run --release -p spartan_whir_guest \
  --bin leanvm-full-zk-spark-poseidon1 --offline -- validate recommended
RAYON_NUM_THREADS=12 cargo bench -p spartan_whir_guest \
  --bench spark_guest_optimization --offline
```

The Cargo configuration enables native CPU code generation. Criterion measures compact input preparation separately from LeanVM execution-proof generation, native verification and serialized-size accounting. Compilation and fixture loading are outside those intervals. The execution-proof benchmark has ten flat samples, ten seconds of warmup and a 180-second target per case. It uses the same inner fixture, outer WHIR parameters and 12 threads for both variants. Outer proof-of-work may produce different valid outer proofs.

Both ordinary and optimized direct proofs also pass the existing lift and binary-node prover. These checks use the same valid lifted proof in both ordered child slots and reject changed application claims. The optimized sample has a 449,746-byte lift proof and a 609,480-byte node proof; padded lift/node table heights remain unchanged. Run `cargo run --release -p spartan_whir_guest --bin leanvm-binary-node --offline -- prove-optimized` for this check.

The regression commands are `cargo test --release -p spartan_whir_guest --test guest_optimizations --test optimized_full_zk_spark --test full_zk_spark_poseidon1 --test binary_recursion --offline -- --test-threads=1`. Tests check both program profiles, compact input framing and source hashes, 17 production mutations under each encoding, and the focused helper cases. Regression totals are recorded in `leanvm-results.json`.

Raw measurements and Criterion samples are in the `leanvm-*.json` files. Exact commands, source hashes, candidate ancestry, Criterion samples, and regression totals are retained by `summarize_leanvm.py` in `leanvm-results.json`.

#### Validation issue resolved

The first row-length omission trial passed VM execution but failed native execution-proof verification. The 392 row lengths in the two hiding relation rounds were not materialized by their branch-local assertions. The optimized guest now stores these fixed widths explicitly before using the rows. The complete optimized execution proof passes native verification. No LeanVM prover, AIR or native verifier code was changed.

#### Tool issues

Delegated agents reached the account usage limit; the remaining implementation and validation were completed locally.
