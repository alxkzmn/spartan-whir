#!/usr/bin/env python3
"""Retain Criterion estimates and samples for the SPARK codec comparison."""

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--criterion", type=Path, default=Path("target/criterion"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for path in sorted(args.criterion.glob("spark_proof_compression_*/*/new/benchmark.json")):
        metadata = json.loads(path.read_text())
        estimates = json.loads(path.with_name("estimates.json").read_text())
        samples = json.loads(path.with_name("sample.json").read_text())
        results.append({"benchmark": metadata, "estimates_ns": estimates, "samples": samples})
    if not results:
        raise SystemExit("No SPARK proof compression Criterion results found")
    source_paths = sorted({*Path("src").rglob("*.rs"), *Path("benches").rglob("*.rs"), Path("Cargo.toml"), Path("Cargo.lock")})
    source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    output = {"criterion": results, "source_sha256": source_hashes}
    args.out.write_text(json.dumps(output, indent=2) + "\n")
    for result in results:
        mean = result["estimates_ns"]["mean"]
        interval = mean["confidence_interval"]
        print(f'{result["benchmark"]["full_id"]}: {mean["point_estimate"]/1e6:.3f} ms '
              f'[{interval["lower_bound"]/1e6:.3f}, {interval["upper_bound"]/1e6:.3f}]')


if __name__ == "__main__":
    main()
