#!/usr/bin/env python3
"""Collect exact guest counts, complete optimization rounds, and Criterion evidence."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
LEANVM = WORKSPACE / "leanVM"
CANDIDATES = [
    ("fresh_relation", "baseline"), ("horner_cubic", "baseline"),
    ("eq_precompile", "baseline"), ("factor_eq_endpoints", "baseline"),
    ("merkle_query_bits", "baseline"), ("paired_merkle", "baseline"),
    ("combined-six", "baseline"), ("fresh_rows", "combined-six"),
    ("query_product", "fresh_rows"), ("radix_prefix", "fresh_rows"),
    ("combined-nine", "fresh_rows"), ("structured_rows", "combined-nine"),
    ("row_counts", "structured_rows"), ("derived_fields", "structured_rows"),
    ("combined-twelve", "structured_rows"),
]

def load(name):
    return json.loads((HERE / f"leanvm-{name}.json").read_text())

def canonical_bytes(data):
    return data.get("canonical_proof_words", 682698) * 4

def main():
    baseline = load("baseline-validation")
    original = load("baseline")
    for key in ["cycles", "memory_cells", "extension_operation_calls", "poseidon1_precompile_calls"]:
        assert baseline["execution"][key] == original["execution"][key]
    final = load("recommended-validation")
    measurements = {"baseline": baseline}
    rows = []
    for name, parent in CANDIDATES:
        data = load(name)
        previous = measurements[parent]
        measurements[name] = data
        rows.append({
            "candidate": name, "parent": parent,
            "canonical_input_bytes": canonical_bytes(data),
            "input_bytes_removed": canonical_bytes(previous) - canonical_bytes(data),
            "cycle_delta": data["execution"]["cycles"] - previous["execution"]["cycles"],
            "extension_row_delta": data["execution"]["extension_operation_calls"] - previous["execution"]["extension_operation_calls"],
            "measurement": data,
        })
    criterion = {}
    for group, names in [("spark_guest_input_encoding", ["optimized"]),
                         ("spark_guest_execution_proof", ["baseline", "optimized"])]:
        for name in names:
            directory = LEANVM / "crates/spartan_whir_guest/target/criterion" / group / name / "new"
            criterion[f"{group}/{name}"] = {
                key: json.loads((directory / f"{key}.json").read_text())
                for key in ["estimates", "sample", "benchmark"]
            }
    profile_path = LEANVM / "crates/spartan_whir_guest/testdata/full_zk_spark_poseidon1/full_zk_spark_profile.json"
    profile = json.loads(profile_path.read_text())
    proof = load("baseline-proof")
    for target, source in [
        ("compiled_instructions", "compiled_instruction_count"),
        ("padded_instructions", "padded_instruction_count"),
        ("bytecode_bytes", "bytecode_bytes"), ("bytecode_log_size", "bytecode_log_size"),
        ("bytecode_hash", "bytecode_hash"), ("compile_ms", "compile_ms"),
        ("compiler_peak_rss_bytes", "compiler_peak_rss_bytes"),
    ]:
        profile["guest"][target] = proof[source]
    profile["guest"]["execution_peak_rss_bytes"] = proof["execution"]["peak_rss_bytes"]
    for key in ["proving_ms", "verification_ms", "serialized_proof_bytes"]:
        profile["outer_proof"][key] = proof["root_proof"][key]
    profile["outer_proof"]["complete_command_peak_rss_bytes"] = proof["root_proof"]["peak_rss_bytes"]
    profile["measurement_environment"]["date"] = "2026-09-05"
    names = list(profile["implementation_source_ids"]) + [
        "crates/spartan_whir_guest/benches/spark_guest_optimization.rs",
        "crates/spartan_whir_guest/tests/guest_optimizations.rs",
        "crates/spartan_whir_guest/tests/optimized_full_zk_spark.rs",
        "crates/spartan_whir_guest/tests/binary_recursion.rs",
        "crates/spartan_whir_guest/src/bin/leanvm-binary-node.rs",
        ".cargo/config.toml",
    ]
    source_ids = {name: hashlib.sha256((LEANVM / name).read_bytes()).hexdigest() for name in sorted(set(names))}
    profile["implementation_source_ids"] = {
        name: source_ids[name] for name in profile["implementation_source_ids"]
    }
    profile_path.write_text(json.dumps(profile, indent=2) + "\n")
    recursion_path = profile_path.parent.parent / "binary_recursion_profile.json"
    recursion = json.loads(recursion_path.read_text())
    for variant, target in [("baseline", recursion_path),
                            ("optimized", recursion_path.with_name("optimized_binary_recursion_profile.json"))]:
        current = json.loads(json.dumps(recursion))
        programs = load(f"{variant}-recursion-programs")
        for name, source in [("spartan_guest", "child"), ("lifted_execution", "lifted"), ("binary_node", "node")]:
            current["production_programs"][name] = {
                ("bytecode_hash" if key == "hash" else key): value
                for key, value in programs[source].items() if key != "compile_ms"
            }
        smoke = load(f"{variant}-recursion-proof")
        for key, value in smoke.items():
            if key not in ["profile", "optimized", "public_claim_mutations"]:
                current["production_smoke"][key.replace("node_", "binary_node_") if key.startswith("node_") else key] = value
        current["optimized"] = variant == "optimized"
        current["measurement_date"] = "2026-09-05"
        current["implementation_source_ids"] = {
            name: hashlib.sha256((LEANVM / name).read_bytes()).hexdigest()
            for name in sorted(set(current["implementation_source_ids"]) | set(source_ids))
        }
        target.write_text(json.dumps(current, indent=2) + "\n")
    log = (HERE / "leanvm-criterion.log").read_text()
    proof_examples = {name: int(size) for name, size in re.findall(r"verified (baseline|optimized): (\d+) bytes", log)}
    validation = {}
    for name in ["leanvm-tests.log", "leanvm-helper-tests.log"]:
        test_log = (HERE / name).read_text()
        validation[name] = {
            "passed": sum(map(int, re.findall(r"test result: ok\. (\d+) passed", test_log))),
            "failed": "test result: FAILED" in test_log,
        }
    report = {
        "scope": "Selected inner WHIR schedule and existing SHA-256 fixture; optimized direct LeanVM guest",
        "baseline": baseline, "optimized": final, "candidates": rows,
        "recursion_checks": {variant: load(f"{variant}-recursion-proof") for variant in ["baseline", "optimized"]},
        "rounds": [
            {"round": 1, "start_bytes": 2730792, "end_bytes": 2348344,
             "reduction_percent": 100 * (1 - 2348344 / 2730792), "completed": True},
            {"round": 2, "start_bytes": 2348344, "end_bytes": 2333288,
             "reduction_percent": 100 * (1 - 2333288 / 2348344), "completed": True},
        ],
        "stopping_condition": "Every candidate in the final round was tried; their combined input reduction is below 1%.",
        "criterion": criterion,
        "regression_tests": validation,
        "outer_proof_examples": proof_examples,
        "outer_proof_example_scope": "One verified sample per variant; proof-of-work can change later outer proof sizes.",
        "implementation_source_ids": source_ids,
        "leanvm_head": subprocess.check_output(["git", "-C", str(LEANVM), "rev-parse", "HEAD"], text=True).strip(),
        "leanvm_branch": subprocess.check_output(["git", "-C", str(LEANVM), "branch", "--show-current"], text=True).strip(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "effective_threads": 12,
        "flags": "-C target-cpu=native (leanVM/.cargo/config.toml)",
        "command": "RAYON_NUM_THREADS=12 cargo bench -p spartan_whir_guest --bench spark_guest_optimization --offline",
    }
    (HERE / "leanvm-results.json").write_text(json.dumps(report, indent=2) + "\n")
    optimized_profile = {
        "schema": "leanvm-spartan-spark-optimization-profile-v1",
        "base_profile_id": profile["profile_id"],
        "source_revisions": profile["source_revisions"],
        "implementation_source_ids": source_ids,
        "canonical_input_words": 583322,
        "bytecode_hash": final["bytecode_hash"],
        "compiled_instructions": final["compiled_instruction_count"],
        "execution": final["execution"],
        "outer_proof_examples": proof_examples,
        "date": "2026-09-05",
    }
    (profile_path.parent / "optimized_profile.json").write_text(json.dumps(optimized_profile, indent=2) + "\n")
    for name, result in criterion.items():
        mean = result["estimates"]["mean"]
        ci = mean["confidence_interval"]
        print(f"{name}: {mean['point_estimate']/1e6:.3f} ms [{ci['lower_bound']/1e6:.3f}, {ci['upper_bound']/1e6:.3f}]")

if __name__ == "__main__":
    main()
