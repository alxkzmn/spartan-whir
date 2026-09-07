# SPARK proof size with the selected 2048-byte SHA-256 schedule

#### Native transport result

The implemented full-ZK Poseidon1 quintic SPARK transport proof shrinks from a median **2,741,789 bytes to 2,245,906.5 bytes**, an **18.086% reduction** on four matched valid 2048-byte SHA-256 inputs. The first complete optimization round saves 18.070%; the second saves another **451 bytes, or 0.0201% of its starting proof**. Every shortlisted category was revisited before applying the 1% stopping condition.

Use `prove_compressed_with_rng`, `CompressedZkProofFor::to_bytes` / `from_bytes`, and `verify_compressed`. The opt-in APIs support full-ZK SPARK with both Poseidon1 and Poseidon2. The decoder reconstructs omitted values and runs all original verification checks. Schedules, polynomials, commitments, public claims and transcript operations are preserved. The ordinary Rust proof format retains its existing encoding.

The measured transport format is larger than 2 MiB. Native decoding and verification costs below belong to this transport codec.

#### Measured size by candidate

Rows are cumulative and include all framing. The baseline is the complete bincode proof. An even-sized corpus can have a half-byte median. Exact samples and setup are in [measurements.json](measurements.json).

| Encoding | Median bytes | Incremental bytes saved |
| --- | ---: | ---: |
| Bincode baseline | 2,741,789.0 | — |
| Structured initial rows | 2,567,964.0 | 173,825.0 |
| Fresh hiding rows omitted | 2,353,644.0 | 214,320.0 |
| 31-bit field packing | 2,281,026.5 | 72,617.5 |
| Compact integer metadata | 2,256,111.5 | 24,915.0 |
| Factored SPARK product rounds | 2,248,275.5 | 7,836.0 |
| Final plain WHIR rows | 2,246,357.5 | 1,918.0 |
| Derived product fields | 2,245,950.5 | 407.0 |
| Smaller metadata tags | 2,245,906.5 | 44.0 |
| Nonadjacent duplicate-column trial | 2,245,906.5 | 0.0 |

The fresh-row change removes 208,400 bytes of field payload and 5,920 bytes of row lengths. Other measured savings likewise include framing and interactions with earlier stages; the fixture payload estimates below count raw four-byte field coordinates.

#### Complete second-round coverage

| Category | Trial or exclusion test | Additional saving |
| --- | --- | ---: |
| Initial rows | Detect nonadjacent duplicate columns after zero/tail compression; verify four inputs | 0 B |
| Fresh hiding rows | Nullspace tests for a second omission; degree/interpolation analysis | 0 B from these equations |
| Field packing | Exact bit count and base-p block bound: 32 fields still need 992 bits; at least 89 fields are needed to save one bit | At most 819 B with ideal unframed range coding |
| Metadata | Implement compact small indices and one-bit tags; count remaining non-field bits | 44 B; under 4,950 B of metadata remains |
| SPARK products | Derive redundant headers and repeated leaf evaluations; test exact proof and transcript reconstruction | 407 B after packing |
| Final WHIR rows | Nonzero-pivot and nullspace tests for another omitted coordinate | 0 B from the final fold equation |

The implemented second-round combination saves 451 bytes. Even ideal range coding plus removal of every remaining metadata bit would add less than 0.26% on the measured samples. These bounds apply to these representation refinements, not every possible proof protocol.

Each of the seven carried mask groups has 88 queries and 88 random coefficients per column. Message lengths are 8, 3, 3, 269, 3, 125, 3 and widths are 80, 21, 8, 1, 3, 1, 3. At distinct nonzero query points, the randomness evaluation matrix is a nonsingular diagonal matrix times a Vandermonde matrix. All 88 queried values remain independently variable even with fixed messages, so interpolation cannot recover an omitted carried value. The source has 124 queries, 124 random coefficients, 64 message coefficients and width 8. Its fresh-row equation already removes one scalar per row; retaining fresh instead only changes which scalar is omitted. These dimensions come from the [existing fixture constants](../../../leanVM/crates/spartan_whir_guest/testdata/full_zk_spark_poseidon1/full_zk_spark_guest_constants.json) and pinned backend configuration.

#### Scope

Consider encoding and reconstruction changes that preserve the selected WHIR schedule, committed polynomials and roots, public claims, verifier equations, and the exact sequence of transcript observations and challenges. The wire format may change. Decoding must reconstruct the values expected by the existing verifier; compact bytes must not replace those values in transcript absorption.

The active shortlist consists of structured initial-row encoding, fresh-row reconstruction, equality-factor encoding, final-row reconstruction, field packing, and removal of derivable metadata. General transport compression and authenticated fixed-oracle caching remain optional deployment choices. Lookup replacements, shared WHIR arguments, joint product-tree protocols, different product-tree arities, and changed dotproduct splits are outside this analysis.

#### Fixed baseline and evidence

This analysis fixes the current selected full-ZK Poseidon1, KoalaBear quintic configuration for the optimized 2048-byte SHA-256 circuit: 605,424 constraints, 116-bit composed security, 120-bit plain SPARK WHIR components, a 122-bit hiding-WHIR relation after its additional two-bit slack, and 123-bit Merkle binding.

| Component | Variables | Folding parameters | PoW budget | Initial log inverse rate | Initial reduction factor |
| --- | ---: | --- | ---: | ---: | ---: |
| Hiding witness relation | 20 | first 8, then 3 | 7 | 1 | 7 |
| Fixed value, including audit | 25 | first 8, then 4 | 9 | 1 | 8 |
| Read group 0, eight columns | 25 | first 8, then 4 | 9 | 1 | 8 |
| Read group 1, two columns | 23 | first 8, then 4 | 9 | 1 | 8 |

All round-rate lists retain their empty, backend-derived representation. `ell_zk = 3` and `mask_log_inv_rate = 3`. The configured audit parameters remain `Constant(8)`, PoW 6, initial log inverse rate 1, reduction factor 8; the embedded audit has no separate proof. Each plain SPARK WHIR opening has query counts **259, 259, 58, 33** and folding schedule **8, 4, 4, 4**. The two read dimensions give different domain sizes despite sharing these counts.

The [selected schedule measurement](../2026-09-03-poseidon1-spark-retune/README.md) records a median of **2,741,805 bincode bytes**. Exact counts below use the separately seeded [LeanVM fixture manifest](../../../leanVM/crates/spartan_whir_guest/testdata/full_zk_spark_poseidon1/full_zk_spark_manifest.json), whose proof is **2,745,325 bincode bytes**. Query-dependent Merkle multiproof sizes vary between proofs. The fixture's setup matches the selected parameters. Its source revisions and hashes are recorded in the manifest; it was not regenerated for this analysis.

The canonical guest stream occupies 2,730,792 bytes, including the public instance and header, and is padded to 4,194,304 bytes for the guest. The canonical proof portion is 2,729,692 bytes; bincode adds 15,633 bytes relative to that encoding. These encodings have different framing. The table below partitions the canonical stream; individual field-payload savings also apply to bincode because both use four bytes per base-field coordinate.

| Canonical component | Bytes |
| --- | ---: |
| Hiding-WHIR relation | 1,170,188 |
| Fixed-value WHIR proof | 518,864 |
| Read group 0, including commitment/evaluations | 518,524 |
| Read group 1, including commitment/evaluations | 480,352 |
| Remaining SPARK data | 37,364 |
| Spartan data, instance, and header | 5,500 |
| Total | 2,730,792 |

Run the analysis from this repository:

```bash
python3 benchmark-results/2026-09-05-spark-proof-size/analyze.py \
  ../leanVM/crates/spartan_whir_guest/testdata/full_zk_spark_poseidon1 \
  --out benchmark-results/2026-09-05-spark-proof-size/counts.json
```

[analyze.py](analyze.py) verifies every manifest artifact hash and size, verifies that the layout covers the canonical stream without overlap, counts each component, inspects every query row, and derives the payload estimates in [counts.json](counts.json). It performs no proving or timing comparison. The fixture analysis is separate from the implementation measurements above; the checkout also contains preexisting uncommitted work.

#### Encoding opportunities with the existing schedule and transcript

**1. Encode the repeated and zero coordinates of initial SPARK rows: 174,048 bytes.**

Each of the three initial openings contains 259 rows of 256 base-field elements. In the fixed opening, the same 56 coordinate positions are zero in every row: omitting them saves `259 × 56 × 4 = 58,016` bytes. In each read group, coordinates 199 through 255 are equal within each row. Transmitting one of these 57 values and reconstructing the remaining 56 saves another 58,016 bytes per group. The repeated value varies across rows and need not be zero.

The structure follows from zero-address padding of the sparse tables, equality-polynomial reads of those addresses, and the prefix layout's column-wise linear encoding. The measured equalities hold in every relevant fixture row. A compact codec can reconstruct full-width rows before hashing, retaining the existing roots and transcript. The encoder should check the pattern, and any general API needs either a declared compatible layout or a fallback encoding. Sources: [table padding](../../src/spark.rs), [read construction](../../src/spark.rs), [prefix commitment](../../src/plonky3_whir_pcs.rs).

**2. Reconstruct fresh hiding-WHIR rows: 208,400 bytes.**

The base-case check relates the revealed blinded codeword, the fresh opening, and the carried opening through `Enc(blinded)(z) = fresh(z) + gamma × carried(z)`. Given the reveal and carried values, the verifier can calculate fresh values. Retain both commitments and their authentication proofs. The fresh main rows occupy 2,480 bytes; fresh mask rows occupy 205,920 bytes. Removing these rows is independent of the 174,048-byte SPARK row saving.

For the main oracle, the carried row is folded before applying this relation. For masks, the equation applies coordinate by coordinate. This is a codec opportunity: decode to the existing proof shape, or have the verifier use reconstructed values directly. Native verification already evaluates the blinded codewords. The LeanVM cost depends on whether its implementation can reuse those calculations. Source: pinned [hiding-WHIR base-case verifier](https://github.com/alxkzmn/Plonky3/blob/f64ae15da3807388b1a4e0a89a4fde8fdcdff515/whir/src/pcs/zk/base_case/verifier.rs).

**3. Pack field elements into 31 bits.**

KoalaBear elements, including quintic coordinates and Poseidon digest elements, currently occupy 32 bits. Canonical 31-bit packing saves **3.125% of the field payload to which it is applied**. Packing one continuous stream avoids padding every 155-bit quintic element to 20 bytes. The total ceiling is less than 86 KB on this fixture and becomes smaller after other fields are omitted. Preserve canonical-value validation. For recursion, byte decoding and bit extraction need measurement; transport compression alone leaves the decoded guest input unchanged.

**4. Compress product sumcheck messages using their known equality factor: 8,400 bytes.**

For each pure product round, write `g(t) = E(t) Q(t)`, where `E(t) = (1-u) + (2u-1)t` and `Q(t) = q0 + q1 t + q2 t²`. The running claim gives `S = g(0) + g(1) = q0 + u(q1+q2)`. Transmit `q1,q2`, reconstruct `q0`, then reconstruct the existing three observations `g(0),g(2),g(3)`. This can preserve the exact transcript. It requires no division, including when `u = 1/2`.

There are 210 eligible internal operation rounds and 210 memory rounds. The last 21 operation rounds also contain value dotproducts without the equality factor and retain their three elements. Thus `420 × 20 = 8,400` bytes can be omitted. Source: [equality-weighted product rounds](../../src/spark.rs) and [cubic replay](../../src/spark.rs).

**5. Reconstruct one coordinate in each final plain-WHIR query row: 1,980 bytes.**

The final polynomial is revealed before final queries. Its evaluation determines the multilinear fold of each queried row. Omit one extension coordinate and recover it using a deterministically selected nonzero folding weight. Such a weight exists because the weights sum to one. This saves `3 × 33 × 20 = 1,980` bytes across the three SPARK openings. The polynomial itself must remain available before sampling these queries. Source: pinned [plain verifier](https://github.com/alxkzmn/Plonky3/blob/f64ae15da3807388b1a4e0a89a4fde8fdcdff515/whir/src/pcs/verifier/mod.rs), final polynomial and STIR checks.

**6. Remove derivable fields and encode lengths compactly.**

The fixed root, table dimensions, column counts, ZK parameters, vector lengths, challenge copies, and repeated product roots contain values already determined by the key, schedule, or transcript. A key-aware codec can omit selected values and reconstruct them at the correct transcript position. The canonical stream contains 19,884 bytes classified as vector/option/tag framing, and bincode has an additional net 15,633 bytes relative to the canonical proof. These are useful ceilings to investigate, with overlap between categories; a complete codec is needed for an exact saving. Keep shape validation and allocation limits.

Some terminal GKR evaluations can also be reconstructed from a layer equation after selecting a nonzero coefficient, with a complete degenerate case. The saving is hundreds of bytes. Existing cubic sumchecks already omit the value at one using the running sum.

**7. General transport compression.**

On the complete unpadded canonical stream, zlib level 9 produces 2,550,042 bytes and default LZMA produces 2,549,936 bytes, about 6.6% smaller. This overlaps the structured row savings. The input includes the public instance and header, so these numbers are not compressed-bincode sizes. Decompression roundtrips the original bytes; using it only outside the guest reduces network/storage size while retaining the guest's decoded proof size and verification work.

#### Verifier preprocessing of the fixed oracle

The initial fixed-table codeword and Merkle tree are public and determined by the authenticated circuit key. A verifier that retains them can reconstruct its initial queried rows and Merkle siblings, removing **340,640 bytes** in this fixture: 265,216 row bytes plus 75,424 sibling bytes. This includes the 58,016 zero-coordinate saving above and must not be added to it.

A dense cache for this oracle is approximately **272 MiB**: `2^26` four-byte codeword elements plus roughly `2^19` 32-byte tree nodes. Construction can be amortized across many proofs. Partial caches provide intermediate tradeoffs. A small Merkle cap saves less because the existing multiproof already shares upper authentication paths.

The remaining folded fixed-table oracle depends on proof challenges and requires verification. This option reconstructs the initial opening from an authenticated cache and preserves the rest of the existing argument. Keeping only the fixed root does not reconstruct initial openings. Sources: [fixed proof schema](../../src/protocol.rs), [fixed opening protocol](../../src/protocol.rs).

For native servers, the cache is a plausible workload tradeoff. A recursive verifier must account for access to that public cache, its authentication and representation, and memory/trace cost. The current LeanVM result does not establish feasibility of this cache. Encoding compression and preprocessing have different effects on recursive work.

#### Existing reductions and fixed constraints

The implementation already has shared-union A/B/C tables, shared read factors, batched row/column products, six value dotproducts integrated into the operation argument, fixed audit data embedded in the fixed-value commitment, and quintic read groups of eight and two columns. Merkle openings already use pruned multiproofs, initial rows already use base-field values, and sampled query indices are distinct. The fixture contains no duplicate full rows within an opening.

Reducing PoW/security, changing the extension field, dropping ZK masks, altering folding factors/rates/query counts, or using a different hash profile changes the fixed comparison. Seven Poseidon digest elements would have insufficient collision security for the current 123-bit Merkle target. Merkle arity changes require a separate hash design and do not automatically reduce proof bytes. Arbitrary dense values in later extension-field rows have no general compression beyond canonical field packing and the specific verified equations above.

Combining all ten read columns by padding them to sixteen raises the commitment dimension to 26 and changes the realized schedule. Revealing original ZK masks to reconstruct their commitments would change the privacy property. The 88 mask queries are protected by 88 random coefficients per column; their carried values should not be treated as a compressible short deterministic polynomial.

#### Verification boundary

The reconstruction helpers retain all commitments and authentication proofs. They replay an isolated challenger without adding events to the active trace, reconstruct the original proof fields, and then invoke the ordinary verifiers. Fresh-row decoding repeats masked-sumcheck target arithmetic, reveal hashing and codeword evaluations; final-row decoding repeats transcript progression and a linear solve. These additional operations are included in decoding-plus-verification measurements.

Factored SPARK rounds reconstruct the cubic observations before the original sumcheck verifier samples challenges. Final-row reconstruction observes the final polynomial before deriving query indices and chooses a nonzero folding weight, including Boolean challenge cases. The custom codec validates framing and allocation bounds; original field deserialization and cryptographic verification remain required.

The native transport APIs are full-ZK SPARK only. Fixed-oracle caching is not implemented. Fixture payload counts and native transport measurements use separate encodings and seeds.

#### Validation and benchmark method

The corpus has four valid SHA-256 inputs and fixed proof RNG seeds. Corpus generation uses one Rayon thread because parallel PoW grinding can select different valid witnesses on repeated proofs. Every compressed proof matches its baseline instance and 16 post-proof extension challenges; each decoded proof verifies and produces those challenges. Serial integration tests also compare every transcript operation for both Poseidon profiles, across all options and two seeds.

Coverage includes exact fresh/final reconstruction, equality-factor edge cases, original-verifier authentication failures, malformed rows and flags, changed public inputs, canonical integer and field decoding, truncation, trailing data, allocation bounds and second-round nullspace tests. Independent static review compared reconstruction and adapter ordering with backend revision `f64ae15da3807388b1a4e0a89a4fde8fdcdff515`.

Criterion runs optimized native code with 12 Rayon threads, ten samples, three seconds of warmup and a 15-second target measurement interval per case. Proving uses flat sampling and rotates inputs with varying proof RNG seeds. Its interval includes linked witness generation, proving and encoding; setup and circuit compilation are outside it. Encoding-only measurements serialize prepared proofs. Decoding-plus-verification measurements rotate through the verified corpus. Criterion drops large outputs after timing through per-iteration batching.

The checkout has preexisting uncommitted work. HEAD is `411849a2826ad734b18c461c3c47fb45e0561166`; the report records features, flags, workload and exact setup. Toolchain: `rustc 1.96.0-nightly (d9563937f 2026-03-03)`, aarch64 macOS. The cached R1CS SHA-256 is `1f1c6beae387e938d86b5ca433abc024945f14c2763db0c29638613ebb206627`.

```bash
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' \
RAYON_NUM_THREADS=12 \
SHA256_BENCH_WORKDIR=target/sha256-optimized-cache \
SPARK_COMPRESSION_DUMP_DIR=target/spark-compression-proofs \
SPARK_COMPRESSION_REPORT=benchmark-results/2026-09-05-spark-proof-size/measurements.json \
cargo bench --features parallel,poseidon1 --bench spark_proof_compression --offline

python3 benchmark-results/2026-09-05-spark-proof-size/summarize.py \
  --out benchmark-results/2026-09-05-spark-proof-size/criterion-results.json
```

`summarize.py` retains Criterion estimates, samples and source hashes. The earlier fixture payload analysis remains reproducible with `analyze.py` and `counts.json`; it uses a separately seeded proof and the canonical LeanVM word framing.
