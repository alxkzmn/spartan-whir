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

`sha256_512b.circom` is a real 512-byte SHA-256 frontend circuit. It uses the
vendored Circomlib SHA-256 bit circuit plus KoalaBear-safe replacements for the
parts that originally packed 32-bit words into one field element. Run the full
compile, witness generation, import, prove, and verify flow with:

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

If GMP is installed outside the default compiler search path, pass the same
`CC` and `CFLAGS` overrides shown above.

The `circomlib-sha256/` subtree is GPL-3.0 circomlib-derived code and should be
treated as a reference/benchmark fixture, not as owned permissively licensed
frontend code.
