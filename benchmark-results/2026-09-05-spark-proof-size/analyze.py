#!/usr/bin/env python3
"""Count the existing fixed-schedule SPARK fixture; does not generate proofs."""

import argparse
import collections
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.fixture / "full_zk_spark_manifest.json").read_text())
    for artifact in manifest["artifacts"].values():
        data = (args.fixture / artifact["file"]).read_bytes()
        assert len(data) == artifact["bytes"]
        assert hashlib.sha256(data).hexdigest() == artifact["sha256"]
    layout = json.loads((args.fixture / "full_zk_spark_guest_layout.json").read_text())
    entries = layout["entries"]
    raw = (args.fixture / "full_zk_spark_guest_input.words").read_bytes()
    raw = raw[: layout["total_words"] * 4]
    cursor = 0
    for entry in sorted((v for v in entries.values() if v["words"]), key=lambda x: x["offset"]):
        assert entry["offset"] == cursor
        cursor += entry["words"]
    assert cursor == layout["total_words"]

    def group(key):
        if key.startswith("proof.spark.fixed.value_proof"):
            return "spark_fixed_whir"
        match = re.match(r"proof.spark.read.groups\[(\d+)\]", key)
        if match:
            return "spark_read_" + match[1]
        if key.startswith("proof.spark"):
            return "spark_other"
        if key.startswith("proof.pcs"):
            return "hiding_whir"
        return "other_and_instance"

    def category(key):
        if key.endswith(".siblings"):
            return "merkle_siblings"
        if re.search(r"\.rows\[\d+\]\.values$", key):
            return "query_rows"
        if key.endswith(".roots"):
            return "commitments"
        if any(key.endswith(s) for s in [".count", "_count", ".present", ".tag"]):
            return "framing"
        return "other"

    stats = collections.defaultdict(collections.Counter)
    openings = collections.defaultdict(list)
    for key, entry in entries.items():
        stats[group(key)][category(key)] += entry["words"] * 4
        if category(key) == "query_rows":
            start = entry["offset"] * 4
            row = raw[start : start + entry["words"] * 4]
            openings[key.rsplit(".rows[", 1)[0]].append(row)

    opening_stats = {}
    for key, rows in sorted(openings.items()):
        values = [struct.unpack("<" + "I" * (len(row) // 4), row) for row in rows]
        zero_columns = [i for i in range(len(values[0])) if all(row[i] == 0 for row in values)]
        tail_start = len(values[0]) - 1
        while tail_start > 0 and all(row[tail_start - 1] == row[-1] for row in values):
            tail_start -= 1
        opening_stats[key] = {
            "rows": len(rows),
            "row_words": len(values[0]),
            "row_bytes": sum(map(len, rows)),
            "duplicate_row_bytes": (len(rows) - len(set(rows))) * len(rows[0]),
            "zero_columns": zero_columns,
            "repeated_tail_start": tail_start,
            "repeated_tail_saving_bytes": len(rows) * (len(values[0]) - tail_start - 1) * 4,
        }

    fixed = "proof.spark.fixed.value_proof.rounds[0].openings"
    reads = [f"proof.spark.read.groups[{i}].proof.rounds[0].openings" for i in range(2)]
    fresh_bytes = sum(v["row_bytes"] for k, v in opening_stats.items()
                      if k.startswith("proof.pcs.base_case.") and
                      (".fresh." in k or k.endswith(".fresh") or "fresh_main_openings" in k))
    fixed_zero_bytes = len(opening_stats[fixed]["zero_columns"]) * opening_stats[fixed]["rows"] * 4
    read_repeat_bytes = sum(opening_stats[k]["repeated_tail_saving_bytes"] for k in reads)
    fixed_initial_bytes = opening_stats[fixed]["row_bytes"] + entries[fixed + ".siblings"]["words"] * 4
    shape = manifest["proof_shape"]["spark"]
    ops_rounds = sum(shape["operations_product"]["rounds_per_layer"])
    mem_rounds = sum(shape["memory_product"]["rounds_per_layer"])
    ops_leaf_rounds = shape["operations_product"]["rounds_per_layer"][-1]
    ef_bytes = manifest["extension_degree"] * 4
    final_rows = sum(v["rows"] for k, v in opening_stats.items() if k.endswith(".final_openings"))
    zlib_bytes = zlib.compress(raw, 9)
    lzma_bytes = lzma.compress(raw)
    assert zlib.decompress(zlib_bytes) == raw
    assert lzma.decompress(lzma_bytes) == raw
    result = {
        "schema": "spark-proof-size-analysis-v1",
        "method": "Read existing canonical word fixture; verify artifact hashes and complete nonoverlapping layout. Savings count payload only and do not validate a new codec.",
        "manifest_sha256": hashlib.sha256((args.fixture / "full_zk_spark_manifest.json").read_bytes()).hexdigest(),
        "bincode_proof_bytes": manifest["bincode_proof_bytes"],
        "canonical_stream_bytes_including_instance": len(raw),
        "padded_guest_bytes": manifest["guest_bytes"],
        "setup": manifest["setup"],
        "table_metadata": manifest["spark_table_metadata"],
        "groups": {k: {"total": sum(v.values()), **v} for k, v in stats.items()},
        "openings": opening_stats,
        "payload_savings": {
            "reconstruct_fresh_hiding_rows": fresh_bytes,
            "fixed_initial_zero_columns": fixed_zero_bytes,
            "read_initial_repeated_tails": read_repeat_bytes,
            "fresh_rows_plus_fixed_zeros_plus_read_tails": fresh_bytes + fixed_zero_bytes + read_repeat_bytes,
            "cache_fixed_initial_rows_and_merkle_siblings": fixed_initial_bytes,
            "final_row_one_coordinate": final_rows * ef_bytes,
            "factor_product_rounds": (ops_rounds - ops_leaf_rounds + mem_rounds) * ef_bytes,
        },
        "transport_compression_canonical_stream": {
            "zlib_level_9": len(zlib_bytes),
            "lzma_default": len(lzma_bytes),
        },
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
