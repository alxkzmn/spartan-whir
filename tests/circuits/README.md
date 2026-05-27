#### Circom Test Circuits

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

`sum_of_squares.circom` is intentionally not committed as a binary fixture: it
is the 65,536-constraint witness-performance circuit used by
`scripts/bench_sum_of_squares_witness.sh`.

`sha256_128b.circom`, `sha256_256b.circom`, `sha256_512b.circom`,
`sha256_1024b.circom`, and `sha256_2048b.circom` are real fixed-size SHA-256
frontend circuits. They use the `koalabear-sha256/Sha256Bytes(N_BYTES)` wrapper
around the adapted SHA-256 bit circuit. Run the 512-byte compile, witness
generation, import, prove, and verify flow with:

```sh
CIRCOM_BIN=../circom/target/debug/circom \
  cargo run --release -p spartan-whir --features circom --example sha256_512b_circom
```

When the example generates artifacts itself, it removes the previous
`sha256_512b.r1cs`, `sha256_512b.wtns`, `sha256_512b_input.json`, and
`sha256_512b_cpp/` outputs from its workdir before recompiling. If
`SHA256_512B_R1CS` and `SHA256_512B_WTNS` are set, those explicit paths are used
as-is.

The example proves and verifies the same imported SHA-256 instance twice:
direct sparse matrix evaluation first, then Spark. Spark uses a folding factor
of 2 because the 512-byte SHA circuit's packed Spark fixed/read tables need a
larger WHIR polynomial than the witness commitment.

Run the size-range benchmark with:

```sh
CIRCOM_BIN=../circom/target/debug/circom \
  SHA256_BENCH_SIZES=128,256,512,1024,2048 \
  cargo run --release -p spartan-whir --features circom,whir-p3-backend,parallel --example sha256_circom_bench
```

The benchmark reports constraints, constraints per SHA block, wires, witness
generation time, import time, direct prove/verify time, Spark prove/verify time,
and Spark layout stats. It derives the Spark folding factor from the packed
Spark table size, so larger circuits can cross WHIR domain cliffs without
manual retuning.

Set `SHA256_BENCH_PROFILE=1` to emit phase timers for the proving path. The
Spark read-table profile is split into `spark_compute_read_table_row`, which is
available after `r_x`, and `spark_compute_read_table_col`, which waits for
`r_y`. The surrounding Spark scopes bracket the read commitment, product
proofs, fixed-table openings, read-table openings, witness evaluation, and the
witness WHIR opening.

If GMP is installed outside the default compiler search path, pass the same
`CC` and `CFLAGS` overrides shown above.

The `koalabear-sha256/` subtree is adapted from GPL-3.0 circomlib SHA-256 code
and should be treated as a benchmark fixture, not as owned permissively licensed
frontend code. Unreachable unsafe Circomlib entry points are intentionally not
kept in the tree.
