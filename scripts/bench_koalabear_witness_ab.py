#!/usr/bin/env python3
"""A/B benchmark KoalaBear Circom native witness generation.

This script intentionally benchmarks generated `circom --prime koalabear --c`
artifacts. It applies experimental changes to the generated `fr.hpp` inside a
temporary work directory before `make`, so failed candidates do not require
rebuilding the Circom compiler or editing tracked field templates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


MODULUS = 2_130_706_433
MONTGOMERY_R = (1 << 32) % MODULUS
MONTGOMERY_R2 = (MONTGOMERY_R * MONTGOMERY_R) % MODULUS
MONTGOMERY_NPRIME = (-pow(MODULUS, -1, 1 << 32)) % (1 << 32)
SUM_OF_SQUARES_CONSTRAINTS = 65_536
SHA_SIZES = (256, 512, 2048)


@dataclass(frozen=True)
class Candidate:
    name: str
    cflags: str
    cxxflags: str
    ldflags: str = ""
    generated_cflags: str | None = None
    patch_makefile_lto: bool = False
    overlay: str | None = None
    main_overlay: str | None = None
    generated_cpp_overlay: str | None = None
    pgo: bool = False
    persistent_process: bool = False


@dataclass
class Workload:
    name: str
    circuit: Path
    cpp_dir_name: str
    binary_name: str
    input_name: str
    expected_witnesses: int | None
    throughput_denominator: int
    write_input: Callable[[Path], None]


@dataclass
class SampleSet:
    cold_seconds: list[float] = field(default_factory=list)
    warm_seconds: list[float] = field(default_factory=list)
    wtns_hash: str = ""
    wtns_size: int = 0
    nvars: int = 0
    max_rss_bytes: int | None = None

    @property
    def median_cold(self) -> float:
        return statistics.median(self.cold_seconds)

    @property
    def p10_cold(self) -> float:
        return percentile(self.cold_seconds, 10)

    @property
    def p90_cold(self) -> float:
        return percentile(self.cold_seconds, 90)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to spartan-whir repo root.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Path to spartan-p3 workspace root.",
    )
    parser.add_argument(
        "--circom-bin",
        type=Path,
        default=None,
        help="Circom binary. Defaults to <workspace>/circom/target/release/circom.",
    )
    parser.add_argument(
        "--build-circom",
        action="store_true",
        help="Build release circom before benchmarking.",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="Temporary work directory. Defaults under TMPDIR.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=15,
        help="Retained samples after dropping the first run.",
    )
    parser.add_argument(
        "--warm-series",
        type=int,
        default=15,
        help="Diagnostic repeated-process samples after one discarded warmup.",
    )
    parser.add_argument(
        "--batch-repeats",
        type=int,
        default=1,
        help=(
            "Witnesses generated inside each timed sample. Values >1 are intended "
            "for persistent-process A/B tests."
        ),
    )
    parser.add_argument(
        "--candidates",
        default="baseline,mcpu-native,mcpu-native-lto",
        help=(
            "Comma-separated candidates. Known: baseline, mcpu-native, "
            "mcpu-native-lto, scalar-bundle, identity-reduction, "
            "json-fast-input, stream-witness-output, pgo, generated-tu-os, "
            "generated-tu-size-flags, persistent-process, montgomery-form."
        ),
    )
    parser.add_argument(
        "--workloads",
        default="sum_of_squares,sha256_256b,sha256_512b,sha256_2048b",
        help="Comma-separated workloads.",
    )
    parser.add_argument(
        "--input-mode",
        choices=("json", "binary"),
        default="json",
        help=(
            "Input format passed to the generated witness binary. "
            "binary writes little-endian uint32 KoalaBear elements and uses "
            "the generated loadBinary path."
        ),
    )
    parser.add_argument(
        "--results-json",
        type=Path,
        default=None,
        help="Optional path to write machine-readable results.",
    )
    parser.add_argument(
        "--keep-threshold",
        type=float,
        default=0.05,
        help="Required median improvement for non-baseline candidates.",
    )
    args = parser.parse_args()

    if args.samples < 1:
        raise SystemExit("--samples must be positive")
    if args.warm_series < 1:
        raise SystemExit("--warm-series must be positive")
    if args.batch_repeats < 1:
        raise SystemExit("--batch-repeats must be positive")

    repo_root = args.repo_root.resolve()
    workspace_root = args.workspace_root.resolve()
    circom_bin = (
        args.circom_bin.resolve()
        if args.circom_bin
        else workspace_root / "circom" / "target" / "release" / "circom"
    )

    if args.build_circom:
        run(
            [
                "cargo",
                "build",
                "--release",
                "--manifest-path",
                str(workspace_root / "circom" / "Cargo.toml"),
            ],
            cwd=workspace_root,
        )
    if not circom_bin.exists():
        raise SystemExit(f"circom binary not found: {circom_bin}")

    candidates = select_candidates(args.candidates)
    if any(candidate.persistent_process for candidate in candidates):
        if args.input_mode != "binary":
            raise SystemExit("persistent-process candidate requires --input-mode binary")
        if args.batch_repeats < 2:
            raise SystemExit("persistent-process candidate requires --batch-repeats >= 2")
    workloads = select_workloads(repo_root, args.workloads, args.input_mode)
    workdir = (
        args.workdir.resolve()
        if args.workdir
        else Path(tempfile.mkdtemp(prefix="koalabear-witness-ab-"))
    )
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"repo_root={repo_root}")
    print(f"workspace_root={workspace_root}")
    print(f"circom_bin={circom_bin}")
    print(f"workdir={workdir}")
    print(f"samples_retained={args.samples}")
    print(f"warm_series_retained={args.warm_series}")
    print(f"batch_repeats={args.batch_repeats}")
    print(f"input_mode={args.input_mode}")
    print("memory_policy=no new witness-side buffers; report one peak-RSS probe per candidate/workload")
    print("candidates=" + ",".join(candidate.name for candidate in candidates))
    print("workloads=" + ",".join(workload.name for workload in workloads))

    results: dict[str, dict[str, dict[str, object]]] = {}
    baseline: dict[str, SampleSet] = {}

    for candidate in candidates:
        print(f"\n== candidate {candidate.name} ==")
        candidate_results: dict[str, dict[str, object]] = {}
        for workload in workloads:
            sample_set = run_workload(
                repo_root=repo_root,
                workdir=workdir,
                circom_bin=circom_bin,
                candidate=candidate,
                workload=workload,
                retained_samples=args.samples,
                retained_warm_samples=args.warm_series,
                batch_repeats=args.batch_repeats,
            )
            if candidate.name == "baseline":
                baseline[workload.name] = sample_set
                improvement = None
                warm_improvement = None
                p_value = None
                passes_gate = True
            else:
                base = baseline.get(workload.name)
                if base is None:
                    raise SystemExit(
                        "baseline must be listed before non-baseline candidates"
                    )
                assert_same_witness(candidate.name, workload.name, base, sample_set)
                improvement = 1.0 - (sample_set.median_cold / base.median_cold)
                warm_improvement = 1.0 - (
                    statistics.median(sample_set.warm_seconds)
                    / statistics.median(base.warm_seconds)
                )
                p_value = mann_whitney_u_two_sided(
                    base.cold_seconds, sample_set.cold_seconds
                )
                memory_ok = max_rss_not_bloated(base.max_rss_bytes, sample_set.max_rss_bytes)
                passes_gate = (
                    improvement >= args.keep_threshold
                    and (
                        sample_set.p90_cold < base.median_cold
                        or (p_value is not None and p_value < 0.05)
                    )
                    and memory_ok
                )

            memory_ok_for_row = (
                None
                if candidate.name == "baseline"
                else max_rss_not_bloated(
                    baseline[workload.name].max_rss_bytes, sample_set.max_rss_bytes
                )
            )
            row = result_row(
                sample_set,
                workload,
                improvement,
                warm_improvement,
                p_value,
                passes_gate,
                memory_ok_for_row,
            )
            candidate_results[workload.name] = row
            print_result(candidate.name, workload.name, row)

        results[candidate.name] = candidate_results

    if args.results_json:
        args.results_json.parent.mkdir(parents=True, exist_ok=True)
        args.results_json.write_text(json.dumps(results, indent=2) + "\n")
        print(f"\nwrote_results={args.results_json}")

    print("\nmirror_back_check_commands:")
    print(f"  cargo build --release --manifest-path={workspace_root / 'circom/Cargo.toml'}")
    print(f"  CIRCOM_BIN={circom_bin} {Path(__file__).resolve().relative_to(repo_root)} ...")
    print(
        "  bash spartan-whir/tests/circuits/regenerate_fixtures.sh "
        "circom/target/release/circom"
    )
    print("  git diff -- spartan-whir/tests/fixtures/circom/")
    return 0


def select_candidates(raw: str) -> list[Candidate]:
    base = "-std=c++11 -O3 -I."
    native = f"{base} -mcpu=native"
    native_lto = f"{native} -flto"
    known = {
        "baseline": Candidate("baseline", base, base),
        "mcpu-native": Candidate("mcpu-native", native, native),
        "mcpu-native-lto": Candidate(
            "mcpu-native-lto",
            native_lto,
            native_lto,
            "-flto",
            patch_makefile_lto=True,
        ),
        "scalar-bundle": Candidate(
            "scalar-bundle",
            native_lto,
            native_lto,
            "-flto",
            patch_makefile_lto=True,
            overlay="scalar-bundle",
        ),
        "identity-reduction": Candidate(
            "identity-reduction",
            native_lto,
            native_lto,
            "-flto",
            patch_makefile_lto=True,
            overlay="identity-reduction",
        ),
        "json-fast-input": Candidate(
            "json-fast-input",
            base,
            base,
            main_overlay="json-fast-input",
        ),
        "stream-witness-output": Candidate(
            "stream-witness-output",
            base,
            base,
            main_overlay="stream-witness-output",
        ),
        "pgo": Candidate(
            "pgo",
            base,
            base,
            pgo=True,
        ),
        "generated-tu-os": Candidate(
            "generated-tu-os",
            base,
            base,
            generated_cflags="-std=c++11 -Os -I.",
        ),
        "generated-tu-size-flags": Candidate(
            "generated-tu-size-flags",
            base,
            base,
            generated_cflags=(
                "-std=c++11 -Os -I. -fno-exceptions -fno-rtti "
                "-fmerge-all-constants"
            ),
        ),
        "persistent-process": Candidate(
            "persistent-process",
            base,
            base,
            main_overlay="persistent-process",
            persistent_process=True,
        ),
        "montgomery-form": Candidate(
            "montgomery-form",
            base,
            base,
            overlay="montgomery-form",
            main_overlay="montgomery-io",
            generated_cpp_overlay="montgomery-literals",
        ),
    }
    selected = []
    for name in split_csv(raw):
        try:
            selected.append(known[name])
        except KeyError as err:
            raise SystemExit(f"unknown candidate: {name}") from err
    if not selected or selected[0].name != "baseline":
        raise SystemExit("candidate list must start with baseline")
    return selected


def select_workloads(repo_root: Path, raw: str, input_mode: str) -> list[Workload]:
    known: dict[str, Workload] = {
        "sum_of_squares": Workload(
            name="sum_of_squares",
            circuit=repo_root / "tests" / "circuits" / "sum_of_squares.circom",
            cpp_dir_name="sum_of_squares_cpp",
            binary_name="sum_of_squares",
            input_name=f"sum_of_squares_input.{input_mode_extension(input_mode)}",
            expected_witnesses=None,
            throughput_denominator=SUM_OF_SQUARES_CONSTRAINTS,
            write_input=select_input_writer(
                input_mode, write_sum_of_squares_json_input, write_sum_of_squares_binary_input
            ),
        )
    }
    for size in SHA_SIZES:
        known[f"sha256_{size}b"] = Workload(
            name=f"sha256_{size}b",
            circuit=repo_root / "tests" / "circuits" / f"sha256_{size}b.circom",
            cpp_dir_name=f"sha256_{size}b_cpp",
            binary_name=f"sha256_{size}b",
            input_name=f"sha256_{size}b_input.{input_mode_extension(input_mode)}",
            expected_witnesses=None,
            throughput_denominator=size,
            write_input=select_input_writer(
                input_mode,
                lambda path, n=size: write_sha256_json_input(path, n),
                lambda path, n=size: write_sha256_binary_input(path, n),
            ),
        )

    selected = []
    for name in split_csv(raw):
        try:
            selected.append(known[name])
        except KeyError as err:
            raise SystemExit(f"unknown workload: {name}") from err
    return selected


def split_csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def run_workload(
    repo_root: Path,
    workdir: Path,
    circom_bin: Path,
    candidate: Candidate,
    workload: Workload,
    retained_samples: int,
    retained_warm_samples: int,
    batch_repeats: int,
) -> SampleSet:
    candidate_workdir = workdir / candidate.name / workload.name
    if candidate_workdir.exists():
        shutil.rmtree(candidate_workdir)
    candidate_workdir.mkdir(parents=True)

    run(
        [
            str(circom_bin),
            str(workload.circuit),
            "--prime",
            "koalabear",
            "--r1cs",
            "--c",
            "-o",
            str(candidate_workdir),
        ],
        cwd=repo_root,
    )
    input_path = candidate_workdir / workload.input_name
    workload.write_input(input_path)

    cpp_dir = candidate_workdir / workload.cpp_dir_name
    if candidate.overlay:
        overlay_header(cpp_dir / "fr.hpp", candidate.overlay)
    if candidate.main_overlay:
        overlay_main(cpp_dir / "main.cpp", candidate.main_overlay)
    if candidate.generated_cpp_overlay:
        overlay_generated_cpp(
            cpp_dir / f"{workload.binary_name}.cpp",
            candidate.generated_cpp_overlay,
        )
    if candidate.patch_makefile_lto or candidate.pgo:
        patch_makefile_for_ldflags(cpp_dir / "Makefile")
    if candidate.generated_cflags:
        patch_makefile_for_generated_cflags(cpp_dir / "Makefile", workload.binary_name)

    env = os.environ.copy()
    env.setdefault("CPATH", "")
    env.setdefault("LIBRARY_PATH", "")
    add_env_path_if_exists(env, "CPATH", Path("/opt/homebrew/include"), "gmp.h")
    add_env_path_if_exists(env, "CPATH", Path("/usr/local/include"), "gmp.h")
    add_env_path_if_exists(env, "LIBRARY_PATH", Path("/opt/homebrew/lib"), "libgmp.dylib")
    add_env_path_if_exists(env, "LIBRARY_PATH", Path("/usr/local/lib"), "libgmp.dylib")

    binary = cpp_dir / workload.binary_name
    if candidate.pgo:
        build_pgo_candidate(
            repo_root=repo_root,
            candidate_workdir=candidate_workdir,
            cpp_dir=cpp_dir,
            binary=binary,
            input_path=input_path,
            candidate=candidate,
            env=env,
        )
    else:
        make_cmd = make_command(
            cpp_dir,
            candidate.cflags,
            candidate.cxxflags,
            candidate.ldflags,
            candidate.generated_cflags,
        )
        run(make_cmd, cwd=repo_root, env=env)

    samples = SampleSet()

    cold_outputs = []
    for i in range(retained_samples + 1):
        outputs = batch_output_paths(candidate_workdir, "cold", i, batch_repeats)
        elapsed = timed_witness_run(
            binary=binary,
            input_path=input_path,
            outputs=outputs,
            cwd=cpp_dir,
            candidate=candidate,
        )
        if i == 0:
            continue
        samples.cold_seconds.append(elapsed)
        cold_outputs.extend(outputs)

    warm_outputs = []
    for i in range(retained_warm_samples + 1):
        outputs = batch_output_paths(candidate_workdir, "warm", i, batch_repeats)
        elapsed = timed_witness_run(
            binary=binary,
            input_path=input_path,
            outputs=outputs,
            cwd=cpp_dir,
            candidate=candidate,
        )
        if i == 0:
            continue
        samples.warm_seconds.append(elapsed)
        warm_outputs.extend(outputs)

    memory_outputs = batch_output_paths(candidate_workdir, "memory-probe", 0, batch_repeats)
    samples.max_rss_bytes = probe_witness_max_rss_bytes(
        binary=binary,
        input_path=input_path,
        outputs=memory_outputs,
        cwd=cpp_dir,
        candidate=candidate,
    )

    reference_output = cold_outputs[-1]
    meta = parse_wtns(reference_output)
    samples.wtns_hash = sha256_file(reference_output)
    samples.wtns_size = reference_output.stat().st_size
    samples.nvars = meta["nvars"]
    assert_wtns_layout(reference_output, meta)
    outputs_to_check = cold_outputs[:-1] + warm_outputs
    outputs_to_check.extend(output for output in memory_outputs if output.exists())
    for output in outputs_to_check:
        other_meta = parse_wtns(output)
        assert_wtns_layout(output, other_meta)
        if sha256_file(output) != samples.wtns_hash:
            raise SystemExit(
                f"non-deterministic witness output for {candidate.name}/{workload.name}: "
                f"{output}"
            )
    return samples


def input_mode_extension(input_mode: str) -> str:
    if input_mode == "json":
        return "json"
    if input_mode == "binary":
        return "bin"
    raise SystemExit(f"unknown input mode: {input_mode}")


def select_input_writer(
    input_mode: str, json_writer: Callable[[Path], None], binary_writer: Callable[[Path], None]
) -> Callable[[Path], None]:
    if input_mode == "json":
        return json_writer
    if input_mode == "binary":
        return binary_writer
    raise SystemExit(f"unknown input mode: {input_mode}")


def write_sum_of_squares_json_input(path: Path) -> None:
    values = [str((i * 17 + 3) % MODULUS) for i in range(SUM_OF_SQUARES_CONSTRAINTS)]
    path.write_text(json.dumps({"xs": values}) + "\n")


def write_sum_of_squares_binary_input(path: Path) -> None:
    values = [(i * 17 + 3) % MODULUS for i in range(SUM_OF_SQUARES_CONSTRAINTS)]
    write_u32_binary(path, values)


def write_sha256_json_input(path: Path, size: int) -> None:
    bits = sha256_input_bits(size)
    path.write_text(json.dumps({"in": bits}, separators=(",", ":")) + "\n")


def write_sha256_binary_input(path: Path, size: int) -> None:
    write_u32_binary(path, sha256_input_bits(size))


def sha256_input_bits(size: int) -> list[int]:
    message = bytes(((i & 0xFF) * 17 + 3) & 0xFF for i in range(size))
    return [(byte >> bit) & 1 for byte in message for bit in range(7, -1, -1)]


def write_u32_binary(path: Path, values: list[int]) -> None:
    with path.open("wb") as f:
        for value in values:
            if not 0 <= value < MODULUS:
                raise SystemExit(f"binary input value outside KoalaBear field: {value}")
            f.write(struct.pack("<I", value))


def montgomery_literal(value: int) -> str:
    return f"{(value % MODULUS) * MONTGOMERY_R % MODULUS}u"


def overlay_header(path: Path, overlay: str) -> None:
    original = path.read_text()
    if overlay == "scalar-bundle":
        patched = apply_scalar_bundle(original)
    elif overlay == "identity-reduction":
        patched = apply_identity_reduction(apply_scalar_bundle(original))
    elif overlay == "montgomery-form":
        patched = apply_montgomery_header(original)
    else:
        raise SystemExit(f"unknown overlay: {overlay}")
    path.write_text(patched)


def overlay_main(path: Path, overlay: str) -> None:
    original = path.read_text()
    if overlay == "json-fast-input":
        patched = apply_json_fast_input(original)
    elif overlay == "stream-witness-output":
        patched = apply_stream_witness_output(original)
    elif overlay == "persistent-process":
        patched = apply_persistent_process(original)
    elif overlay == "montgomery-io":
        patched = apply_montgomery_io(original)
    else:
        raise SystemExit(f"unknown main overlay: {overlay}")
    path.write_text(patched)


def overlay_generated_cpp(path: Path, overlay: str) -> None:
    original = path.read_text()
    if overlay == "montgomery-literals":
        patched = apply_montgomery_generated_literals(original)
    else:
        raise SystemExit(f"unknown generated cpp overlay: {overlay}")
    path.write_text(patched)


def apply_montgomery_header(text: str) -> str:
    replacement = f"""#ifndef __FR_H
#define __FR_H

#include <gmp.h>
#include <stdlib.h>
#include <sstream>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#define Fr_N64 1
#define Fr_N8 4
#define Fr_prime {MODULUS}u
#define Fr_prime_str "{MODULUS}"
#define Fr_half {MODULUS // 2}u
#define Fr_montgomery_r {MONTGOMERY_R}u
#define Fr_montgomery_r2 {MONTGOMERY_R2}u
#define Fr_montgomery_nprime {MONTGOMERY_NPRIME}u

typedef uint32_t FrElement;

inline FrElement Fr_reduce64(uint64_t x) {{
  const uint64_t q = (((__uint128_t)x * 8657571868ull) >> 64);
  uint64_t r = x - q * (uint64_t)Fr_prime;
  if (r >= (uint64_t)Fr_prime) r -= (uint64_t)Fr_prime;
  return (FrElement)r;
}}

inline FrElement Fr_montgomeryReduce(uint64_t x) {{
  uint32_t m = (uint32_t)x * (uint32_t)Fr_montgomery_nprime;
  uint64_t u = (x + (uint64_t)m * (uint64_t)Fr_prime) >> 32;
  if (u >= (uint64_t)Fr_prime) u -= (uint64_t)Fr_prime;
  return (FrElement)u;
}}

inline FrElement Fr_toMontgomeryCanonical(FrElement a) {{
  return Fr_montgomeryReduce((uint64_t)a * (uint64_t)Fr_montgomery_r2);
}}

inline FrElement Fr_fromMontgomery(FrElement a) {{
  return Fr_montgomeryReduce((uint64_t)a);
}}

inline FrElement Fr_bool(bool a) {{
  return a ? (FrElement)Fr_montgomery_r : 0u;
}}

inline FrElement Fr_one() {{
  return Fr_montgomery_r;
}}

#define Fr_copy(r, a) r = a

inline void Fr_copyn(FrElement r[], const FrElement a[], int n){{
  for (int i = 0; i < n; i++) {{
    r[i] = a[i];
  }}
}}

inline int Fr_toInt(const FrElement & a) {{
  FrElement n = Fr_fromMontgomery(a);
  if (n > Fr_half) return -((int)(Fr_prime - n));
  return (int)n;
}}

inline FrElement Fr_str2element(const char *s, uint base) {{
  mpz_t q;
  mpz_init_set_ui(q, Fr_prime);
  mpz_t mr;
  mpz_init_set_str(mr, s, base);
  mpz_fdiv_r(mr, mr, q);
  FrElement v = Fr_toMontgomeryCanonical((FrElement)mpz_get_ui(mr));
  mpz_clear(mr);
  mpz_clear(q);
  return v;
}}

inline char *Fr_element2str(const FrElement & a) {{
  std::stringstream ss;
  ss << Fr_fromMontgomery(a);
  std::string str = ss.str();
  char * cstr = new char [str.length()+1];
  strcpy (cstr, str.c_str());
  return cstr;
}}

inline FrElement Fr_add (const FrElement & a, const FrElement & b) {{
  uint32_t r = a + b;
  return r >= Fr_prime ? r - Fr_prime : r;
}}

inline FrElement Fr_sub (const FrElement & a, const FrElement & b) {{
  return (b <= a)? a - b : Fr_prime - (b - a);
}}

inline FrElement Fr_mul(const FrElement & a, const FrElement & b) {{
  return Fr_montgomeryReduce((uint64_t)a * (uint64_t)b);
}}

inline FrElement Fr_inv(const FrElement & a) {{
  mpz_t ma;
  mpz_init_set_ui(ma, Fr_fromMontgomery(a));
  mpz_t mr;
  mpz_init(mr);
  mpz_t mpz_prime;
  mpz_init_set_ui(mpz_prime, Fr_prime);
  mpz_invert(mr, ma, mpz_prime);
  FrElement ra = Fr_toMontgomeryCanonical((FrElement)mpz_get_ui(mr));
  mpz_clear(ma);
  mpz_clear(mr);
  mpz_clear(mpz_prime);
  return ra;
}}

inline FrElement Fr_div(const FrElement & a, const FrElement & b) {{
  FrElement ib = Fr_inv(b);
  return Fr_mul(a, ib);
}}

inline FrElement Fr_idiv(const FrElement & a, const FrElement & b) {{
  return Fr_toMontgomeryCanonical(Fr_fromMontgomery(a) / Fr_fromMontgomery(b));
}}

inline FrElement Fr_mod(const FrElement & a, const FrElement & b) {{
  return Fr_toMontgomeryCanonical(Fr_fromMontgomery(a) % Fr_fromMontgomery(b));
}}

inline FrElement Fr_pow(const FrElement & a, const FrElement & b) {{
  FrElement p = Fr_one();
  FrElement ao = a;
  FrElement bo = Fr_fromMontgomery(b);
  while (bo > 0) {{
    if ((bo & 1u) == 0)  {{
      ao = Fr_mul(ao, ao);
      bo = bo >> 1;
    }} else {{
      p = Fr_mul(p, ao);
      bo = bo - 1;
    }}
  }}
  return p;
}}

FrElement Fr_shr(const FrElement & a, const FrElement & b);

inline FrElement Fr_shl(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (bn > Fr_half) return Fr_shr(a, Fr_toMontgomeryCanonical(Fr_prime - bn));
  if (bn >= 32) return 0u;
  return Fr_toMontgomeryCanonical(Fr_reduce64((uint64_t)an << bn));
}}

inline FrElement Fr_shr(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (bn > Fr_half) return Fr_shl(a, Fr_toMontgomeryCanonical(Fr_prime - bn));
  if (bn >= 32) return 0u;
  return Fr_toMontgomeryCanonical(an >> bn);
}}

inline FrElement Fr_leq(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (an <= Fr_half) {{
    if (bn <= Fr_half) return Fr_bool(an <= bn);
    else return 0u;
  }} else {{
    if (bn <= Fr_half) return Fr_montgomery_r;
    else return Fr_bool(an <= bn);
  }}
}}

inline FrElement Fr_geq(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (an <= Fr_half) {{
    if (bn <= Fr_half) return Fr_bool(an >= bn);
    else return Fr_montgomery_r;
  }} else {{
    if (bn <= Fr_half) return 0u;
    else return Fr_bool(an >= bn);
  }}
}}

inline FrElement Fr_lt(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (an <= Fr_half) {{
    if (bn <= Fr_half) return Fr_bool(an < bn);
    else return 0u;
  }} else {{
    if (bn <= Fr_half) return Fr_montgomery_r;
    else return Fr_bool(an < bn);
  }}
}}

inline FrElement Fr_gt(const FrElement & a, const FrElement & b) {{
  FrElement an = Fr_fromMontgomery(a);
  FrElement bn = Fr_fromMontgomery(b);
  if (an <= Fr_half) {{
    if (bn <= Fr_half) return Fr_bool(an > bn);
    else return Fr_montgomery_r;
  }} else {{
    if (bn <= Fr_half) return 0u;
    else return Fr_bool(an > bn);
  }}
}}

inline FrElement Fr_eq(const FrElement & a, const FrElement & b) {{
  return Fr_bool(a == b);
}}

inline FrElement Fr_eq(const FrElement a[], const FrElement b[], int n) {{
  for (int i = 0; i < n; i++) {{
    if (a[i] != b[i]) return 0u;
  }}
  return Fr_montgomery_r;
}}

inline FrElement Fr_neq(const FrElement & a, const FrElement & b) {{
  return Fr_bool(a != b);
}}

inline FrElement Fr_lor(const FrElement & a, const FrElement & b) {{
  return (a == 0u) && (b == 0u) ? 0u : (FrElement)Fr_montgomery_r;
}}

inline FrElement Fr_land(const FrElement & a, const FrElement & b) {{
  return (a == 0u) || (b == 0u) ? 0u : (FrElement)Fr_montgomery_r;
}}

inline FrElement Fr_bor(const FrElement & a, const FrElement & b) {{
  return Fr_toMontgomeryCanonical(Fr_reduce64((uint64_t)(Fr_fromMontgomery(a) | Fr_fromMontgomery(b))));
}}

inline FrElement Fr_band(const FrElement & a, const FrElement & b) {{
  return Fr_toMontgomeryCanonical(Fr_fromMontgomery(a) & Fr_fromMontgomery(b));
}}

inline FrElement Fr_bxor(const FrElement & a, const FrElement & b) {{
  return Fr_toMontgomeryCanonical(Fr_reduce64((uint64_t)(Fr_fromMontgomery(a) ^ Fr_fromMontgomery(b))));
}}

inline FrElement Fr_neg(const FrElement & a) {{
  if (a == 0u) return a;
  return Fr_prime - a;
}}

inline FrElement Fr_lnot(const FrElement & a) {{
  return a == 0u ? (FrElement)Fr_montgomery_r : 0u;
}}

inline int Fr_isTrue(const FrElement & a) {{
  return a == 0u ? 0 : 1;
}}

inline FrElement Fr_bnot(const FrElement & a) {{
  return Fr_toMontgomeryCanonical(Fr_reduce64((uint64_t)(~Fr_fromMontgomery(a))));
}}

#endif // __FR_H
"""
    if "Fr_montgomeryReduce" not in replacement:
        raise SystemExit("failed to build montgomery header")
    return replacement


def apply_montgomery_io(text: str) -> str:
    text = text.replace(
        "  FrElement v = (FrElement)mpz_get_ui(mr);\n"
        "  mpz_clear(mr);\n"
        "  return v;\n",
        "  FrElement v = Fr_toMontgomeryCanonical((FrElement)mpz_get_ui(mr));\n"
        "  mpz_clear(mr);\n"
        "  return v;\n",
        1,
    )
    old_binary = """    uint dsize = get_main_input_signal_no()*sizeof(FrElement);
    memcpy((void *)(ctx->signalValues+get_main_input_signal_start()), (void *)bdata, dsize);
}
"""
    new_binary = """    FrElement *values = (FrElement *)bdata;
    uint n = get_main_input_signal_no();
    uint start = get_main_input_signal_start();
    for (uint i = 0; i < n; i++) {
        ctx->signalValues[start + i] = Fr_toMontgomeryCanonical(values[i]);
    }
    munmap(bdata, sb.st_size);
}
"""
    text = text.replace(old_binary, new_binary, 1)
    text = text.replace(
        "        ctx->getWitness(i, v[i]);\n",
        "        ctx->getWitness(i, v[i]);\n"
        "        v[i] = Fr_fromMontgomery(v[i]);\n",
        1,
    )
    if "Fr_toMontgomeryCanonical((FrElement)mpz_get_ui(mr))" not in text:
        raise SystemExit("failed to patch montgomery JSON input")
    if "Fr_toMontgomeryCanonical(values[i])" not in text:
        raise SystemExit("failed to patch montgomery binary input")
    if "v[i] = Fr_fromMontgomery(v[i]);" not in text:
        raise SystemExit("failed to patch montgomery witness output")
    return text


def apply_montgomery_generated_literals(text: str) -> str:
    text = re.sub(
        r"((?:lvar|signalValues|ctx->signalValues)\[[^\n;]*\]\s*=\s*)(\d+)u;",
        lambda match: match.group(1) + montgomery_literal(int(match.group(2))) + ";",
        text,
    )
    return rewrite_fr_call_literals(text)


def rewrite_fr_call_literals(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("Fr_", i):
            name_end = i + 3
            while name_end < len(text) and (
                text[name_end].isalnum() or text[name_end] == "_"
            ):
                name_end += 1
            if name_end < len(text) and text[name_end] == "(":
                call_end = find_matching_paren(text, name_end)
                if call_end is not None:
                    out.append(text[i:name_end + 1])
                    out.append(rewrite_field_numeric_literals(text[name_end + 1:call_end]))
                    out.append(")")
                    i = call_end + 1
                    continue
        out.append(text[i])
        i += 1
    return "".join(out)


def find_matching_paren(text: str, open_index: int) -> int | None:
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def rewrite_field_numeric_literals(args: str) -> str:
    out: list[str] = []
    i = 0
    square_depth = 0
    while i < len(args):
        ch = args[i]
        if ch == "[":
            square_depth += 1
            out.append(ch)
            i += 1
            continue
        if ch == "]":
            square_depth = max(0, square_depth - 1)
            out.append(ch)
            i += 1
            continue
        if square_depth == 0 and ch.isdigit():
            j = i + 1
            while j < len(args) and args[j].isdigit():
                j += 1
            if j < len(args) and args[j] == "u":
                out.append(montgomery_literal(int(args[i:j])))
                i = j + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def apply_json_fast_input(text: str) -> str:
    if "tryStr2ElementFast" in text:
        return text

    marker = "\nFrElement str2element(const char *s, uint base) {\n"
    fast_helper = """
bool tryStr2ElementFast(const char *s, uint base, FrElement *out) {
  if (!(base == 2 || base == 8 || base == 10 || base == 16)) return false;
  uint64_t acc = 0;
  bool saw_digit = false;
  for (const char *p = s; *p != '\\0'; p++) {
    unsigned int digit;
    if ('0' <= *p && *p <= '9') {
      digit = (unsigned int)(*p - '0');
    } else if ('a' <= *p && *p <= 'f') {
      digit = (unsigned int)(*p - 'a' + 10);
    } else if ('A' <= *p && *p <= 'F') {
      digit = (unsigned int)(*p - 'A' + 10);
    } else {
      return false;
    }
    if (digit >= base) return false;
    acc = (acc * base + digit) % (uint64_t)Fr_prime;
    saw_digit = true;
  }
  if (!saw_digit) return false;
  *out = (FrElement)acc;
  return true;
}
"""
    text = text.replace(marker, "\n" + fast_helper + marker.lstrip(), 1)
    text = text.replace(
        "FrElement str2element(const char *s, uint base) {\n",
        "FrElement str2element(const char *s, uint base) {\n"
        "  FrElement fast;\n"
        "  if (tryStr2ElementFast(s, base, &fast)) return fast;\n\n",
        1,
    )
    if "tryStr2ElementFast" not in text:
        raise SystemExit("failed to apply json-fast-input overlay")
    return text


def apply_stream_witness_output(text: str) -> str:
    if "witnessChunkSize" in text:
        return text
    old = """    FrElement *v = new FrElement[Nwtns];
    for (int i=0;i<Nwtns;i++) {
        ctx->getWitness(i, v[i]);
    }
    fwrite(v, 4, Nwtns, write_ptr);
"""
    new = """    const uint witnessChunkSize = 4096;
    FrElement v[witnessChunkSize];
    for (uint offset = 0; offset < Nwtns; offset += witnessChunkSize) {
        uint remaining = Nwtns - offset;
        uint n = remaining < witnessChunkSize ? remaining : witnessChunkSize;
        for (uint i = 0; i < n; i++) {
            ctx->getWitness(offset + i, v[i]);
        }
        fwrite(v, 4, n, write_ptr);
    }
"""
    patched = text.replace(old, new, 1)
    if patched == text:
        raise SystemExit("failed to apply stream-witness-output overlay")
    return patched


def apply_persistent_process(text: str) -> str:
    if "--repeat" in text and "persistent witness loop" in text:
        return text
    old = """  if (argc!=3) {
        std::cout << "Usage: " << cl << " <input.json> <output.wtns>\\n";
  } else {
"""
    new = """  if (argc == 5 && std::string(argv[1]) == "--repeat") {
    // persistent witness loop: binary inputs only, one circuit load, one context
    uint repeat = (uint)std::stoul(argv[2]);
    std::string datfile = cl + ".dat";
    std::string inputfile(argv[3]);
    std::string outputprefix(argv[4]);
    if (inputfile.substr(inputfile.find_last_of(".") + 1) == "json") {
      std::cerr << "--repeat only supports binary inputs\\n";
      assert(false);
    }
    Circom_Circuit *circuit = loadCircuit(datfile);
    Circom_CalcWit *ctx = new Circom_CalcWit(circuit);
    for (uint i = 0; i < repeat; i++) {
      loadBinary(ctx, inputfile);
      ctx->runCircuit();
      writeBinWitness(ctx, outputprefix + "-" + std::to_string(i) + ".wtns");
    }
  } else if (argc!=3) {
        std::cout << "Usage: " << cl << " <input.json> <output.wtns>\\n";
        std::cout << "   or: " << cl << " --repeat <n> <input.bin> <output-prefix>\\n";
  } else {
"""
    patched = text.replace(old, new, 1)
    if patched == text:
        raise SystemExit("failed to apply persistent-process overlay")
    return patched


def apply_scalar_bundle(text: str) -> str:
    if "KOALABEAR_ALWAYS_INLINE" not in text:
        text = text.replace(
            "typedef uint32_t FrElement;\n",
            """typedef uint32_t FrElement;

#if defined(__clang__) || defined(__GNUC__)
#define KOALABEAR_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define KOALABEAR_ALWAYS_INLINE inline
#endif
""",
        )

    text = text.replace("const FrElement & a", "FrElement a")
    text = text.replace("const FrElement & b", "FrElement b")

    text = text.replace(
        "inline void Fr_copyn(FrElement r[], const FrElement a[], int n)",
        "inline void Fr_copyn(FrElement *__restrict__ r, const FrElement *__restrict__ a, int n)",
    )
    text = text.replace(
        "inline FrElement Fr_eq(const FrElement a[], const FrElement b[], int n)",
        "inline FrElement Fr_eq(const FrElement *__restrict__ a, const FrElement *__restrict__ b, int n)",
    )

    for signature in [
        "inline FrElement Fr_reduce64",
        "inline FrElement Fr_add",
        "inline FrElement Fr_sub",
        "inline FrElement Fr_mul",
        "inline FrElement Fr_band",
        "inline FrElement Fr_neg",
        "inline int Fr_isTrue",
    ]:
        text = text.replace(signature, signature.replace("inline", "KOALABEAR_ALWAYS_INLINE"))
    text = text.replace(
        "inline FrElement Fr_eq(FrElement a, FrElement b)",
        "KOALABEAR_ALWAYS_INLINE FrElement Fr_eq(FrElement a, FrElement b)",
    )

    old_sub = """KOALABEAR_ALWAYS_INLINE FrElement Fr_sub (FrElement a, FrElement b) {
  return (b <= a)? a - b : Fr_prime - (b - a);
}"""
    new_sub = """KOALABEAR_ALWAYS_INLINE FrElement Fr_sub (FrElement a, FrElement b) {
  uint32_t r = a - b;
  return r + (Fr_prime & (0u - (uint32_t)(a < b)));
}"""
    text = text.replace(old_sub, new_sub)
    return text


def apply_identity_reduction(text: str) -> str:
    start = text.index("KOALABEAR_ALWAYS_INLINE FrElement Fr_reduce64(uint64_t x) {")
    end = text.index("\n}\n\n#define Fr_copy", start) + 3
    replacement = """KOALABEAR_ALWAYS_INLINE FrElement Fr_reduce64(uint64_t x) {
  // Candidate reduction for p = 2^31 - 2^24 + 1.
  // Since 2^31 == 2^24 - 1 (mod p), one fold
  //   x = lo + hi * (2^24 - 1), with lo = x mod 2^31,
  // preserves x mod p. For any uint64 input, the conservative recurrence
  // y_{i+1} <= (2^31 - 1) + floor(y_i / 2^31) * (2^24 - 1)
  // starting at y_0 = 2^64 - 1 is below 2p after K = 5 folds. One final
  // conditional subtract therefore canonicalizes the result.
  const uint64_t mask31 = (1ull << 31) - 1ull;
  const uint64_t fold = (1ull << 24) - 1ull;
  x = (x & mask31) + (x >> 31) * fold;
  x = (x & mask31) + (x >> 31) * fold;
  x = (x & mask31) + (x >> 31) * fold;
  x = (x & mask31) + (x >> 31) * fold;
  x = (x & mask31) + (x >> 31) * fold;
  if (x >= (uint64_t)Fr_prime) x -= (uint64_t)Fr_prime;
  return (FrElement)x;
}
"""
    return text[:start] + replacement + text[end:]


def patch_makefile_for_ldflags(path: Path) -> None:
    text = path.read_text()
    if "$(LDFLAGS)" in text:
        return
    patched = text.replace(" -lgmp ", " $(LDFLAGS) -lgmp ")
    if patched == text:
        patched = text.replace(" -lgmp", " $(LDFLAGS) -lgmp")
    if patched == text:
        raise SystemExit(f"failed to patch LDFLAGS into {path}")
    path.write_text(patched)


def patch_makefile_for_generated_cflags(path: Path, binary_name: str) -> None:
    text = path.read_text()
    if "$(GEN_CFLAGS)" in text:
        return
    rule = (
        "GEN_CFLAGS ?= $(CFLAGS)\n\n"
        f"{binary_name}.o: {binary_name}.cpp $(DEPS_HPP)\n"
        "\t$(CC) -c $< $(GEN_CFLAGS)\n\n"
    )
    all_match = re.search(r"^all: .*\n\n", text, re.MULTILINE)
    if all_match is None:
        raise SystemExit(f"failed to patch generated-TU flags into {path}")
    idx = all_match.end()
    path.write_text(text[:idx] + rule + text[idx:])


def make_command(
    cpp_dir: Path,
    cflags: str,
    cxxflags: str,
    ldflags: str = "",
    generated_cflags: str | None = None,
) -> list[str]:
    cmd = [
        "make",
        "-C",
        str(cpp_dir),
        "CC=clang++",
        f"CFLAGS={cflags}",
        f"CXXFLAGS={cxxflags}",
    ]
    if ldflags:
        cmd.append(f"LDFLAGS={ldflags}")
    if generated_cflags:
        cmd.append(f"GEN_CFLAGS={generated_cflags}")
    return cmd


def build_pgo_candidate(
    repo_root: Path,
    candidate_workdir: Path,
    cpp_dir: Path,
    binary: Path,
    input_path: Path,
    candidate: Candidate,
    env: dict[str, str],
) -> None:
    profraw = candidate_workdir / "training.profraw"
    profdata = candidate_workdir / "training.profdata"
    training_output = candidate_workdir / "training.wtns"

    generate_flag = "-fprofile-instr-generate"
    use_flag = f"-fprofile-instr-use={profdata}"

    run(
        make_command(
            cpp_dir,
            f"{candidate.cflags} {generate_flag}",
            f"{candidate.cxxflags} {generate_flag}",
            generate_flag,
        ),
        cwd=repo_root,
        env=env,
    )
    training_env = env.copy()
    training_env["LLVM_PROFILE_FILE"] = str(profraw)
    run([str(binary), str(input_path), str(training_output)], cwd=cpp_dir, env=training_env)
    if not profraw.exists():
        raise SystemExit(f"PGO training profile was not written: {profraw}")

    llvm_profdata = find_llvm_profdata(repo_root)
    run([llvm_profdata, "merge", "-output", str(profdata), str(profraw)], cwd=repo_root)
    if not profdata.exists():
        raise SystemExit(f"PGO merged profile was not written: {profdata}")

    remove_build_outputs(cpp_dir, binary)
    run(
        make_command(
            cpp_dir,
            f"{candidate.cflags} {use_flag} -Wno-profile-instr-unprofiled",
            f"{candidate.cxxflags} {use_flag} -Wno-profile-instr-unprofiled",
            "",
        ),
        cwd=repo_root,
        env=env,
    )


def find_llvm_profdata(cwd: Path) -> str:
    direct = shutil.which("llvm-profdata")
    if direct:
        return direct
    result = subprocess.run(
        ["xcrun", "--find", "llvm-profdata"],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit("llvm-profdata not found; cannot run PGO candidate")
    return result.stdout.strip()


def remove_build_outputs(cpp_dir: Path, binary: Path) -> None:
    for obj in cpp_dir.glob("*.o"):
        obj.unlink()
    if binary.exists():
        binary.unlink()


def parse_wtns(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) < 4 + 4 + 4:
        raise SystemExit(f"wtns too short: {path}")
    offset = 0
    magic = data[offset : offset + 4]
    offset += 4
    if magic != b"wtns":
        raise SystemExit(f"bad wtns magic: {path}")
    version, nsections = struct.unpack_from("<II", data, offset)
    offset += 8
    if version != 2 or nsections != 2:
        raise SystemExit(f"unexpected wtns header in {path}: v={version} sections={nsections}")

    section1, length1 = struct.unpack_from("<IQ", data, offset)
    offset += 12
    if section1 != 1 or length1 != 12:
        raise SystemExit(f"unexpected section 1 in {path}")
    n8 = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if n8 != 4:
        raise SystemExit(f"expected KoalaBear n8=4 in {path}, got {n8}")
    modulus = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if modulus != MODULUS:
        raise SystemExit(f"unexpected modulus in {path}: {modulus}")
    nvars = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    section2, length2 = struct.unpack_from("<IQ", data, offset)
    offset += 12
    if section2 != 2:
        raise SystemExit(f"unexpected section 2 in {path}")
    if length2 != nvars * n8:
        raise SystemExit(f"bad witness section length in {path}: {length2} != {nvars * n8}")
    if len(data) != offset + length2:
        raise SystemExit(f"bad wtns size in {path}: {len(data)} != {offset + length2}")
    return {"n8": n8, "nvars": nvars, "payload_offset": offset, "payload_len": length2}


def assert_wtns_layout(path: Path, meta: dict[str, int]) -> None:
    expected_size = meta["payload_offset"] + meta["nvars"] * meta["n8"]
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise SystemExit(f"bad wtns size for {path}: {actual_size} != {expected_size}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def assert_same_witness(
    candidate_name: str, workload_name: str, baseline: SampleSet, candidate: SampleSet
) -> None:
    if baseline.wtns_hash != candidate.wtns_hash:
        raise SystemExit(
            f"wtns hash mismatch for {candidate_name}/{workload_name}: "
            f"{candidate.wtns_hash} != {baseline.wtns_hash}"
        )
    if baseline.wtns_size != candidate.wtns_size:
        raise SystemExit(
            f"wtns size mismatch for {candidate_name}/{workload_name}: "
            f"{candidate.wtns_size} != {baseline.wtns_size}"
        )
    if baseline.nvars != candidate.nvars:
        raise SystemExit(
            f"wtns nvars mismatch for {candidate_name}/{workload_name}: "
            f"{candidate.nvars} != {baseline.nvars}"
        )


def max_rss_not_bloated(baseline: int | None, candidate: int | None) -> bool:
    if baseline is None or candidate is None:
        return True
    allowed = max(baseline + 1024 * 1024, int(baseline * 1.02))
    return candidate <= allowed


def result_row(
    samples: SampleSet,
    workload: Workload,
    improvement: float | None,
    warm_improvement: float | None,
    p_value: float | None,
    passes_gate: bool,
    memory_ok: bool | None,
) -> dict[str, object]:
    return {
        "median_cold_s": samples.median_cold,
        "p10_cold_s": samples.p10_cold,
        "p90_cold_s": samples.p90_cold,
        "median_warm_s": statistics.median(samples.warm_seconds),
        "median_cold_per_unit_us": samples.median_cold
        * 1_000_000.0
        / workload.throughput_denominator,
        "improvement": improvement,
        "warm_improvement": warm_improvement,
        "mann_whitney_p": p_value,
        "passes_gate": passes_gate,
        "wtns_size": samples.wtns_size,
        "wtns_nvars": samples.nvars,
        "wtns_sha256": samples.wtns_hash,
        "max_rss_bytes": samples.max_rss_bytes,
        "memory_ok": memory_ok,
    }


def print_result(candidate: str, workload: str, row: dict[str, object]) -> None:
    improvement = row["improvement"]
    improvement_text = (
        "baseline" if improvement is None else f"{float(improvement) * 100.0:.2f}%"
    )
    warm_improvement = row["warm_improvement"]
    warm_improvement_text = (
        "baseline"
        if warm_improvement is None
        else f"{float(warm_improvement) * 100.0:.2f}%"
    )
    p_value = row["mann_whitney_p"]
    p_text = "n/a" if p_value is None else f"{float(p_value):.4g}"
    rss = row["max_rss_bytes"]
    rss_text = "n/a" if rss is None else str(rss)
    print(
        "result "
        f"candidate={candidate} workload={workload} "
        f"median_cold_s={float(row['median_cold_s']):.6f} "
        f"p10_s={float(row['p10_cold_s']):.6f} "
        f"p90_s={float(row['p90_cold_s']):.6f} "
        f"median_unit_us={float(row['median_cold_per_unit_us']):.6f} "
        f"improvement={improvement_text} "
        f"warm_improvement={warm_improvement_text} p={p_text} "
        f"passes_gate={row['passes_gate']} "
        f"memory_ok={row['memory_ok']} "
        f"max_rss_bytes={rss_text} "
        f"wtns_size={row['wtns_size']} "
        f"wtns_sha256={str(row['wtns_sha256'])[:16]}"
    )


def percentile(values: list[float], pct: float) -> float:
    if not values:
        raise ValueError("empty percentile input")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct / 100.0
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return ordered[lo]
    frac = rank - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def mann_whitney_u_two_sided(a: list[float], b: list[float]) -> float | None:
    if not a or not b:
        return None
    combined = [(x, 0) for x in a] + [(x, 1) for x in b]
    combined.sort(key=lambda item: item[0])
    ranks = [0.0] * len(combined)
    tie_correction = 0.0
    i = 0
    while i < len(combined):
        j = i + 1
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        tie_size = j - i
        tie_correction += tie_size**3 - tie_size
        i = j

    rank_a = sum(rank for rank, item in zip(ranks, combined) if item[1] == 0)
    n1 = len(a)
    n2 = len(b)
    u1 = rank_a - n1 * (n1 + 1) / 2.0
    mean = n1 * n2 / 2.0
    n = n1 + n2
    var = n1 * n2 / 12.0 * ((n + 1) - tie_correction / (n * (n - 1)))
    if var <= 0:
        return None
    z = (abs(u1 - mean) - 0.5) / math.sqrt(var)
    # Two-sided normal approximation.
    return math.erfc(z / math.sqrt(2.0))


def timed_run(cmd: list[str], cwd: Path) -> float:
    start = time.perf_counter()
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(cmd)}")
    return time.perf_counter() - start


def batch_output_paths(workdir: Path, prefix: str, sample_idx: int, repeats: int) -> list[Path]:
    if repeats == 1:
        return [workdir / f"{prefix}-{sample_idx}.wtns"]
    return [workdir / f"{prefix}-{sample_idx}-{i}.wtns" for i in range(repeats)]


def timed_witness_run(
    binary: Path,
    input_path: Path,
    outputs: list[Path],
    cwd: Path,
    candidate: Candidate,
) -> float:
    if candidate.persistent_process:
        prefix = common_output_prefix(outputs)
        return timed_run(
            [str(binary), "--repeat", str(len(outputs)), str(input_path), str(prefix)],
            cwd=cwd,
        )

    start = time.perf_counter()
    for output in outputs:
        result = subprocess.run(
            [str(binary), str(input_path), str(output)],
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise SystemExit(
                f"command failed ({result.returncode}): {binary} {input_path} {output}"
            )
    return time.perf_counter() - start


def common_output_prefix(outputs: list[Path]) -> Path:
    if len(outputs) == 1:
        path = outputs[0]
        if path.suffix == ".wtns":
            return path.with_suffix("")
        return path
    first = outputs[0]
    suffix = "-0.wtns"
    first_s = str(first)
    if not first_s.endswith(suffix):
        raise SystemExit(f"unexpected persistent output path: {first}")
    return Path(first_s[: -len(suffix)])


def probe_witness_max_rss_bytes(
    binary: Path,
    input_path: Path,
    outputs: list[Path],
    cwd: Path,
    candidate: Candidate,
) -> int | None:
    if candidate.persistent_process:
        prefix = common_output_prefix(outputs)
        cmd = [str(binary), "--repeat", str(len(outputs)), str(input_path), str(prefix)]
    elif len(outputs) == 1:
        cmd = [str(binary), str(input_path), str(outputs[0])]
    else:
        # The peak of repeated process launches is represented by one launch.
        cmd = [str(binary), str(input_path), str(outputs[0])]
    return probe_max_rss_bytes(cmd, cwd)


def probe_max_rss_bytes(cmd: list[str], cwd: Path) -> int | None:
    time_bin = Path("/usr/bin/time")
    if not time_bin.exists():
        return probe_max_rss_with_python(cmd, cwd)
    time_cmd = [str(time_bin), "-l"] + cmd
    result = subprocess.run(
        time_cmd,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        python_probe = probe_max_rss_with_python(cmd, cwd)
        if python_probe is not None:
            return python_probe
        # GNU time does not support `-l`; retry with `-v` and parse kbytes.
        time_cmd = [str(time_bin), "-v"] + cmd
        result = subprocess.run(
            time_cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return None
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", result.stderr)
        return int(match.group(1)) * 1024 if match else None

    match = re.search(r"^\s*(\d+)\s+maximum resident set size", result.stderr, re.MULTILINE)
    return int(match.group(1)) if match else None


def probe_max_rss_with_python(cmd: list[str], cwd: Path) -> int | None:
    code = r"""
import resource
import subprocess
import sys

result = subprocess.run(sys.argv[1:])
usage = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != "darwin":
    usage *= 1024
print(usage)
raise SystemExit(result.returncode)
"""
    result = subprocess.run(
        [sys.executable, "-c", code] + cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        return None


def run(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    stdout=None,
    stderr=None,
) -> None:
    printable = " ".join(cmd)
    print(f"+ {printable}", flush=True)
    result = subprocess.run(cmd, cwd=cwd, env=env, stdout=stdout, stderr=stderr)
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {printable}")


def add_env_path_if_exists(env: dict[str, str], var: str, directory: Path, marker: str) -> None:
    if not (directory / marker).exists():
        return
    existing = [p for p in env.get(var, "").split(os.pathsep) if p]
    directory_s = str(directory)
    if directory_s not in existing:
        existing.append(directory_s)
    env[var] = os.pathsep.join(existing)


if __name__ == "__main__":
    raise SystemExit(main())
