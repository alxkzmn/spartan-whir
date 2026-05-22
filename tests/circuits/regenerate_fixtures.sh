#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: tests/circuits/regenerate_fixtures.sh <circom-bin>" >&2
  exit 2
fi

CIRCOM_BIN="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="${TMPDIR:-/tmp}/spartan-whir-circom-fixtures"
FIXTURE_DIR="$ROOT/tests/fixtures/circom"

generate_fixture() {
  local name="$1"
  local input_json="$FIXTURE_DIR/${name}_input.json"
  local cpp_dir="$WORKDIR/${name}_cpp"

  "$CIRCOM_BIN" \
    "$ROOT/tests/circuits/${name}.circom" \
    --prime koalabear \
    --r1cs \
    --c \
    -o "$WORKDIR"

  make -C "$cpp_dir" \
    CC="${CC:-g++}" \
    CFLAGS="${CFLAGS:--std=c++11 -O3 -I.}" \
    CXXFLAGS="${CXXFLAGS:--std=c++11 -O3 -I.}"

  "$cpp_dir/$name" "$input_json" "$WORKDIR/${name}.wtns"

  cp "$WORKDIR/${name}.r1cs" "$FIXTURE_DIR/${name}.r1cs"
  cp "$WORKDIR/${name}.wtns" "$FIXTURE_DIR/${name}.wtns"
}

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR" "$FIXTURE_DIR"

generate_fixture tiny_arithmetic
generate_fixture non_power_of_two
