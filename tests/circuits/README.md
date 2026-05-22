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
CC='g++ -L/opt/homebrew/lib' CFLAGS='-std=c++11 -O3 -I. -I/opt/homebrew/include' \
  tests/circuits/regenerate_fixtures.sh ../circom/target/debug/circom
```

`sum_of_squares.circom` is intentionally not committed as a binary fixture: it
is the 65,536-constraint witness-performance circuit used by
`scripts/bench_sum_of_squares_witness.sh`.
