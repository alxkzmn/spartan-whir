#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: bench_sum_of_squares_witness.sh <circom-bin>" >&2
  exit 2
fi

CIRCOM_BIN="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${TMPDIR:-/tmp}/koalabear-sum-of-squares-bench"
CONSTRAINTS=65536
RUNS=10

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

"$CIRCOM_BIN" \
  "$REPO_ROOT/tests/circuits/sum_of_squares.circom" \
  --prime koalabear \
  --c \
  -o "$WORKDIR"

python3 - "$WORKDIR/input.json" "$CONSTRAINTS" <<'PY'
import json
import sys

path = sys.argv[1]
n = int(sys.argv[2])
with open(path, "w", encoding="utf-8") as f:
    json.dump({"xs": [str((i * 17 + 3) % 2130706433) for i in range(n)]}, f)
PY

make -C "$WORKDIR/sum_of_squares_cpp" \
  CFLAGS="${CFLAGS:--std=c++11 -O3 -I.}" \
  CXXFLAGS="${CXXFLAGS:--std=c++11 -O3 -I.}"

python3 - "$WORKDIR" "$CONSTRAINTS" "$RUNS" <<'PY'
import statistics
import subprocess
import sys
import time

workdir = sys.argv[1]
constraints = int(sys.argv[2])
runs = int(sys.argv[3])
binary = f"{workdir}/sum_of_squares_cpp/sum_of_squares"
input_json = f"{workdir}/input.json"

print("benchmark_scope=end_to_end_json_input_to_wtns")
samples = []
for i in range(runs):
    output = f"{workdir}/witness-{i}.wtns"
    start = time.perf_counter()
    subprocess.run([binary, input_json, output], check=True, stdout=subprocess.DEVNULL)
    elapsed = time.perf_counter() - start
    samples.append(elapsed * 1_000_000 / constraints)

median = statistics.median(samples)
print(f"median_us_per_constraint={median:.6f}")
if median > 0.5:
    raise SystemExit(f"performance gate failed: {median:.6f} > 0.5 us/constraint")
PY
