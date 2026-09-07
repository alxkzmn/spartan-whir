# Poseidon1 full-ZK matrix-closing comparison

#### Result

SPARK is the production matrix-closing mode for the 2,048-byte SHA-256 application. DirectSparse is faster on the client, but its verifier cannot fit LeanVM's current bytecode and extension-operation table limits.

The production R1CS has 4,850,245 raw A/B/C entries. DirectSparse performs one quintic `dot_product_ee` operation per entry when it evaluates the three matrices. The matrix evaluation alone therefore requires at least 4,850,245 extension-operation instructions and table rows. LeanVM permits at most `2^22 = 4,194,304` bytecode instructions and `2^22` extension-operation rows. The matrix scan exceeds both limits by 655,941 before the rest of the Spartan and hiding-WHIR verifier is included. A production DirectSparse guest cannot compile under the fixed LeanVM limits, so it cannot produce a root proof.

SPARK replaces the direct matrix scan with batched memory-product verification and authenticated fixed and read-table WHIR openings. Its production guest fits LeanVM and produces a root proof that passes LeanVM's native verifier. This selects SPARK for the recursive profile. Application-budget acceptance remains open because no maximum client proving latency, throughput, or memory budget has been recorded.

#### Client measurements

The measurements use Poseidon1, the optimized 2,048-byte SHA-256 R1CS, quintic extension, full ZK, 116-bit security, the selected schedules, the same 16-input corpus, release mode, and 12 effective threads.

| Metric | DirectSparse | SPARK |
| --- | ---: | ---: |
| Mean `witness_and_prove` | 76.050 ms | 1,007.0 ms |
| 95% confidence interval | 75.886–76.219 ms | 1,003.5–1,010.6 ms |
| Proof bytes, min / median / max | 1,223,236 / 1,226,372 / 1,228,740 | 2,736,717 / 2,741,517 / 2,746,349 |
| Mean native verification | 56.380 ms | 63.694 ms |
| Diagnostic process peak RSS | 935,919,616 bytes | 4,626,563,072 bytes |

SPARK client proving is 13.241 times the Poseidon1 DirectSparse mean. The fastest measured client control was Poseidon2 DirectSparse at 63.258 ms, so the selected Poseidon1 SPARK result is 15.919 times that mean. The factors are the 1.202-times Poseidon1 hash cost and the 13.241-times SPARK matrix-closing cost on the recorded workloads.

These measurements establish that SPARK can prove on the 48 GiB measurement machine and that DirectSparse cannot fit the fixed LeanVM verifier limits. They do not establish that the selected client profile fits the privacy application's budget. Before release, record the application's maximum client proving latency, peak memory, proof throughput, target device, and expected concurrency, then compare this profile with those limits.

#### Recursive measurements

The selected guest is `spartan-whir-poseidon1-quintic-full-zk-spark-leanvm-v1`. It consumes the fixed 1,048,576-word input, uses the 121-bit LeanVM outer profile at `log_inv_rate = 1`, and exposes only the eight-element digest of the 256-bit application statement.

| Metric | SPARK result |
| --- | ---: |
| Canonical / padded guest words | 682,698 / 1,048,576 |
| Guest input bytes | 4,194,304 |
| Compiled / padded instructions | 424,109 / 524,288 (`2^19`) |
| Encoded bytecode | 33,554,432 bytes |
| Execution cycles | 33,485,006 |
| Execution table | 33,485,006 rows, padded to `2^25` |
| Extension-operation table | 1,622,974 rows, padded to `2^21` |
| Poseidon1 table | 100,106 rows, padded to `2^17` |
| Memory | 36,861,485 cells, padded to `2^26` |
| Execution peak RSS | 6,345,179,136 bytes |
| Root proving | 23,312.54 ms |
| Root verification | 70.70 ms |
| Serialized root proof | 746,518 bytes |
| Complete root command peak RSS | 27,009,564,672 bytes |

The execution table has 69,426 rows of headroom below `2^25`. The production guest test enforces both the recorded 33,485,006-cycle count and the `2^25` ceiling. DirectSparse has no recursive measurements because its 4,850,245-entry matrix scan has a proven lower bound above the fixed `2^22` bytecode and extension-operation limits. The fixed profile and LeanVM implementation source hashes are recorded in `leanVM/crates/spartan_whir_guest/testdata/full_zk_spark_poseidon1/full_zk_spark_profile.json` from the workspace root.

The root proving and verification measurements come from the manual release command below. Continuous integration checks the fixed profile, source and artifact hashes, guest execution, exact cycle ceiling, and mutation failures. It does not generate the root proof because the recorded command reaches 27.0 GB peak RSS.

The inner proof uses a 116-bit Johnson-bound configuration and the outer proof uses a 121-bit Johnson-bound configuration. Their union bound is `2^-116 + 2^-121`, or about 115.956 bits before hash assumptions.

#### Commands

```bash
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' \
SHA256_BENCH_WORKDIR=target/sha256-optimized-cache \
SHA256_ZK_BENCH_PROVING_ONLY=1 \
SHA256_ZK_BENCH_SINGLE_PROVING_VARIANT=full_zk_spark \
SHA256_ZK_BENCH_SECURITY_BITS=116 \
SHA256_ZK_BENCH_EXTENSION=selected \
SHA256_ZK_BENCH_CORPUS_SIZE=16 \
SHA256_ZK_BENCH_DIAGNOSTICS=1 \
cargo bench --features parallel,poseidon1 --bench sha256_full_zk -- --noplot
```

The Criterion target uses 30 samples, a four-second warm-up, and a twelve-second requested measurement period. Because one SPARK proof takes about one second, Criterion collected one iteration per sample over an estimated 30-second measurement period.

Run and verify the selected LeanVM root proof from the LeanVM checkout:

```bash
cargo run --release -p spartan_whir_guest --bin leanvm-full-zk-spark-poseidon1 -- prove
```
