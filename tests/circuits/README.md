#### Test Circuits

`tiny_arithmetic.circom` and `non_power_of_two.circom` have fixed generated
fixtures under `../fixtures/circom/`. Regenerate them with:

```sh
tests/circuits/regenerate_fixtures.sh ../circom/target/debug/circom
```

The script runs `circom --prime koalabear --r1cs --c`, builds the generated
native C++ witness calculator, and writes refreshed `.r1cs` / `.wtns` files.
If GMP is installed outside the default compiler search path, pass normal make
overrides, for example:

```sh
CC='g++ -L/path/to/gmp/lib' CFLAGS='-std=c++11 -O3 -I. -I/path/to/gmp/include' \
  tests/circuits/regenerate_fixtures.sh ../circom/target/debug/circom
```

`sha256_128b.circom`, `sha256_256b.circom`, `sha256_512b.circom`,
`sha256_1024b.circom`, and `sha256_2048b.circom` are real fixed-size SHA-256
frontend circuits. `Sha256Bytes(N_BYTES)` takes `8 * N_BYTES` Boolean field
limbs in most-significant-bit-first byte order. The circuit constrains every
input limb with `x * (x - 1) = 0`, and the linked witness generator supplies
those limbs from byte strings.
Run the 512-byte compile, `.wtns` import, prove, and verify smoke flow with:

```sh
CIRCOM_BIN=../circom/target/debug/circom \
  cargo run --release -p spartan-whir --example sha256_512b
```

`optimized/sha256_2048b.circom` is a separate 2048-byte circuit using
single-row XOR and majority encodings, fused modular additions, and the
determined two-input XOR specialization for the zero tail of each lower sigma.
Its fixed final padding block uses a compile-time message schedule. The
corresponding components live in `koalabear-sha256-optimized/`. The default
`sha256_2048b.circom` remains available for cross-system comparisons. Compile
the optimized circuit and build its linked witness library in a separate cache
root so the Criterion benchmark can select it through `SHA256_BENCH_WORKDIR`:

```sh
tests/circuits/build_sha256_optimized_fixture.sh \
  ../circom/target/release/circom
```

Then run Criterion with:

```sh
RUSTFLAGS='-C target-cpu=native -C debuginfo=0' \
SHA256_BENCH_WORKDIR=target/sha256-optimized-cache \
cargo bench --features parallel --bench sha256_full_zk
```

When the example generates artifacts itself, it removes the cached
`sha256_512b.r1cs`, `sha256_512b.wtns`, `sha256_512b_input.json`, and
`sha256_512b_cpp/` outputs from its workdir before recompiling. If
`SHA256_512B_R1CS` and `SHA256_512B_WTNS` are set, those explicit paths are used
as-is.

The example proves and verifies the same imported SHA-256 instance twice:
direct sparse matrix evaluation first, then Spark. Its prove timer is a
pre-imported-witness smoke check, not the deployment benchmark. Spark uses a
folding factor of 2 because the 512-byte SHA circuit's packed Spark fixed/read
tables need a larger WHIR polynomial than the witness commitment.

Run the size-range benchmark with:

```sh
CIRCOM_BIN=../circom/target/debug/circom \
  SHA256_BENCH_SIZES=128,256,512,1024,2048 \
  cargo run --release -p spartan-whir --features parallel --example sha256_bench
```

The benchmark reports constraints, constraints per SHA block, wires,
`witness_and_prove_ms`, verify time, and Spark layout stats.
`witness_and_prove_ms` starts at the linked native witness generator and ends at
proof output. This `Instant` timing is diagnostic; use the Criterion benchmark
for statistical comparisons. It derives the Spark folding factor from the
packed Spark table size, so larger circuits can cross WHIR domain cliffs without
manual retuning.

Set `SHA256_BENCH_MODES=spark,spark-independent` to compare the shared Spark
WHIR schedule against independently selected witness, fixed-value,
fixed-audit, and read-table schedules. `spark-independent` is the mode to use
for larger Spark layouts whose read-table commitment crosses the KoalaBear
two-adicity bound under the shared schedule.

Set `SHA256_BENCH_PROFILE=1` to emit phase timers for the
`witness_and_prove` path. The Spark read-table profile is split into
`spark_compute_read_table_row`, which is available after `r_x`, and
`spark_compute_read_table_col`, which waits for `r_y`. The surrounding Spark
scopes bracket the read commitment, product proofs, fixed-table openings,
read-table openings, witness evaluation, and the witness WHIR opening.

If GMP is installed outside the default compiler search path, pass the same
`CC` and `CFLAGS` overrides shown above.

The `koalabear-sha256/` subtree is adapted from GPL-3.0 circomlib SHA-256 code
and should be treated as a benchmark fixture, not as owned permissively licensed
frontend code. Unreachable unsafe Circomlib entry points are intentionally not
kept in the tree.
