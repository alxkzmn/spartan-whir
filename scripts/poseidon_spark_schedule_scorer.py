#!/usr/bin/env python3
"""Compose and calibrate full-ZK SPARK WHIR schedule candidates."""

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness-report", required=True)
    parser.add_argument("--fixed-value-report", required=True)
    parser.add_argument("--fixed-audit-report", required=True)
    parser.add_argument("--read-report", required=True)
    parser.add_argument("--out-report", required=True)
    parser.add_argument("--security-bits", type=int, required=True)
    parser.add_argument("--merkle-security-bits", type=int, required=True)
    parser.add_argument("--ell-zk", type=int, required=True)
    parser.add_argument("--mask-log-inv-rate", type=int, required=True)
    parser.add_argument("--top-per-component", type=int, default=8)
    parser.add_argument("--max-report-rows", type=int, default=100)
    parser.add_argument("--measurement-rows", type=int, default=10)
    parser.add_argument("--measurements")
    parser.add_argument("--reference-witness-label")
    parser.add_argument("--reference-fixed-value-label")
    parser.add_argument("--reference-fixed-audit-label")
    parser.add_argument("--reference-read-label")
    args = parser.parse_args()

    reports = {
        "witness": read_json(args.witness_report),
        "fixed_value": read_json(args.fixed_value_report),
        "fixed_audit": read_json(args.fixed_audit_report),
        "read": read_json(args.read_report),
    }
    report = compose_report(
        reports,
        args.security_bits,
        args.merkle_security_bits,
        args.ell_zk,
        args.mask_log_inv_rate,
        args.top_per_component,
        args.max_report_rows,
        args.measurement_rows,
        read_json(args.measurements) if args.measurements else None,
        {
            "witness": args.reference_witness_label,
            "fixed_value": args.reference_fixed_value_label,
            "fixed_audit": args.reference_fixed_audit_label,
            "read": args.reference_read_label,
        },
    )
    write_json(args.out_report, report)
    selected = report.get("selected_measured") or report["selected"]
    print(
        "selected "
        f"label={selected['label']} "
        f"projected_seconds={selected['projected_seconds']:.9g} "
        f"proof_size_bytes_estimate={selected['proof_size_bytes_estimate']}"
    )


def compose_report(
    reports: dict[str, dict[str, Any]],
    security_bits: int,
    merkle_security_bits: int,
    ell_zk: int,
    mask_log_inv_rate: int,
    top_per_component: int,
    max_report_rows: int,
    measurement_rows: int,
    measurements: dict[str, Any] | None,
    reference_labels: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    if min(top_per_component, max_report_rows, measurement_rows) <= 0:
        raise SystemExit("row limits must be positive")
    provenance = require_matching_provenance(reports)
    require_report_mode(reports["witness"], "full-zk", "witness")
    for component in ("fixed_value", "fixed_audit", "read"):
        require_report_mode(reports[component], "no-zk", component)

    ranked = {
        component: component_rows(report, component, top_per_component)
        for component, report in reports.items()
    }
    rows = []
    for witness, fixed_value, fixed_audit, read in itertools.product(
        ranked["witness"],
        ranked["fixed_value"],
        ranked["fixed_audit"],
        ranked["read"],
    ):
        rows.append(
            composed_row(
                witness,
                fixed_value,
                fixed_audit,
                read,
                security_bits,
                merkle_security_bits,
                ell_zk,
                mask_log_inv_rate,
            )
        )
    rows.sort(key=ranking_key)
    rows = deduplicate_rows(rows)
    if not rows:
        raise SystemExit("no valid octic schedule combinations")

    shortlist = stratified_shortlist(
        ranked,
        rows,
        security_bits,
        merkle_security_bits,
        ell_zk,
        mask_log_inv_rate,
        measurement_rows,
        reports,
        reference_labels or {},
    )
    rows = rows[:max_report_rows]
    for row in shortlist:
        if all(existing["label"] != row["label"] for existing in rows):
            rows.append(row)

    calibration = calibrate(rows, measurements)
    if calibration is not None:
        apply_calibration(rows, calibration)
        rows.sort(key=ranking_key)

    selected_measured = select_measured(rows, measurements)
    return {
        "schema_version": 1,
        "provenance": provenance,
        "matrix_closing": "Spark",
        "proof_mode": "full-zk",
        "security_bits": security_bits,
        "merkle_security_bits": merkle_security_bits,
        "ell_zk": ell_zk,
        "mask_log_inv_rate": mask_log_inv_rate,
        "component_num_variables": {
            component: report.get("num_variables") for component, report in reports.items()
        },
        "model": {
            "formula": "witness + fixed openings + 2 * read commit/open",
            "fixed_value_excludes_setup_commitment": True,
            "fixed_audit_excludes_setup_commitment": True,
            "calibration": calibration,
        },
        "selected": rows[0],
        "selected_measured": selected_measured,
        "measurement_shortlist": shortlist,
        "scores": rows,
    }


def stratified_shortlist(
    ranked: dict[str, list[dict[str, Any]]],
    rows: list[dict[str, Any]],
    security_bits: int,
    merkle_security_bits: int,
    ell_zk: int,
    mask_log_inv_rate: int,
    limit: int,
    reports: dict[str, dict[str, Any]],
    reference_labels: dict[str, str | None],
) -> list[dict[str, Any]]:
    selected = rows[: min(2, len(rows))]
    best = {component: candidates[0] for component, candidates in ranked.items()}
    for component in ("witness", "fixed_value", "fixed_audit", "read"):
        for alternative in ranked[component][1:3]:
            choice = dict(best)
            choice[component] = alternative
            selected.append(
                composed_row(
                    choice["witness"],
                    choice["fixed_value"],
                    choice["fixed_audit"],
                    choice["read"],
                    security_bits,
                    merkle_security_bits,
                    ell_zk,
                    mask_log_inv_rate,
                )
            )
    if any(reference_labels.values()):
        if not all(reference_labels.values()):
            raise SystemExit("all four reference labels are required together")
        reference = {
            component: find_report_row(reports[component], str(label), component)
            for component, label in reference_labels.items()
        }
        selected.append(
            composed_row(
                reference["witness"],
                reference["fixed_value"],
                reference["fixed_audit"],
                reference["read"],
                security_bits,
                merkle_security_bits,
                ell_zk,
                mask_log_inv_rate,
            )
        )
    selected = deduplicate_rows(selected)
    return selected[:limit]


def find_report_row(
    report: dict[str, Any], label: str, component: str
) -> dict[str, Any]:
    for row in report.get("scores", []):
        if row.get("label") == label and row.get("extension") == "octic":
            return row
    raise SystemExit(f"{component} reference label not found: {label}")


def component_rows(
    report: dict[str, Any], component: str, limit: int
) -> list[dict[str, Any]]:
    rows = [
        row
        for row in report.get("scores", [])
        if row.get("valid", True)
        and row.get("extension") == "octic"
        and row.get("whir_params") is not None
    ]
    rows.sort(key=lambda row: (component_score(row, component), proof_size(row), row["label"]))
    if not rows:
        raise SystemExit(f"{component} report has no valid octic rows")
    return rows[:limit]


def component_score(row: dict[str, Any], component: str) -> float:
    costs = row.get("cost_breakdown") or {}
    if component == "witness":
        names = ("dft", "merkle", "merkle_path", "row_opening", "sumcheck", "pow")
        multiplier = 1.0
    elif component in ("fixed_value", "fixed_audit"):
        names = ("merkle_path", "row_opening", "sumcheck", "pow")
        multiplier = 1.0
    elif component == "read":
        names = ("dft", "merkle", "merkle_path", "row_opening", "sumcheck", "pow")
        multiplier = 2.0
    else:
        raise AssertionError(component)
    return multiplier * sum(float(costs.get(name) or 0.0) for name in names)


def composed_row(
    witness: dict[str, Any],
    fixed_value: dict[str, Any],
    fixed_audit: dict[str, Any],
    read: dict[str, Any],
    security_bits: int,
    merkle_security_bits: int,
    ell_zk: int,
    mask_log_inv_rate: int,
) -> dict[str, Any]:
    components = {
        "witness": witness,
        "fixed_value": fixed_value,
        "fixed_audit": fixed_audit,
        "read": read,
    }
    scores = {
        component: component_score(row, component) for component, row in components.items()
    }
    projected = sum(scores.values())
    size = (
        proof_size(witness)
        + proof_size(fixed_value)
        + proof_size(fixed_audit)
        + 2 * proof_size(read)
    )
    labels = {component: str(row["label"]) for component, row in components.items()}
    label = "spark_" + "__".join(
        f"{short}={labels[component]}"
        for component, short in (
            ("witness", "w"),
            ("fixed_value", "fv"),
            ("fixed_audit", "fa"),
            ("read", "r"),
        )
    )
    return {
        "label": label,
        "extension": "octic",
        "valid": True,
        "proof_mode": "full-zk",
        "matrix_closing": "Spark",
        "projected_schedule_seconds": projected,
        "projected_seconds": projected,
        "proof_size_bytes_estimate": size,
        "component_labels": labels,
        "component_scores": scores,
        "setup_config": {
            "matrix_closing": "Spark",
            "security": {
                "security_level_bits": security_bits,
                "merkle_security_bits": merkle_security_bits,
                "soundness_assumption": "JohnsonBound",
            },
            "whir_params": witness["whir_params"],
            "spark_whir_params": {
                "fixed_value": fixed_value["whir_params"],
                "fixed_audit": fixed_audit["whir_params"],
                "read": read["whir_params"],
            },
            "ell_zk": ell_zk,
            "mask_log_inv_rate": mask_log_inv_rate,
        },
    }


def deduplicate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = json.dumps(row["setup_config"], sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def calibrate(
    rows: list[dict[str, Any]], measurements: dict[str, Any] | None
) -> dict[str, Any] | None:
    if measurements is None:
        return None
    measured = measurement_map(measurements)
    pairs = [
        (float(row["projected_schedule_seconds"]), measured[row["label"]])
        for row in rows
        if row["label"] in measured
    ]
    if len(pairs) < 3:
        raise SystemExit("SPARK calibration requires at least three measured rows")
    calibration_pairs = [pair for index, pair in enumerate(pairs) if index % 3 != 2]
    validation_pairs = [pair for index, pair in enumerate(pairs) if index % 3 == 2]
    if not validation_pairs:
        validation_pairs = [calibration_pairs.pop()]
    scale = 1.0
    intercept = sum(y - x for x, y in calibration_pairs) / len(calibration_pairs)
    errors = [relative_error(intercept + scale * x, y) for x, y in validation_pairs]
    return {
        "method": "unit-scale offset fit with every third measured row held out",
        "intercept_seconds": intercept,
        "scale": scale,
        "calibration_rows": len(calibration_pairs),
        "validation_rows": len(validation_pairs),
        "validation_max_relative_error": max(errors),
        "validation_within_ten_percent": max(errors) <= 0.10,
    }


def fit_affine(pairs: list[tuple[float, float]]) -> tuple[float, float]:
    x_mean = sum(x for x, _ in pairs) / len(pairs)
    y_mean = sum(y for _, y in pairs) / len(pairs)
    variance = sum((x - x_mean) ** 2 for x, _ in pairs)
    if variance == 0.0:
        return y_mean - x_mean, 1.0
    scale = sum((x - x_mean) * (y - y_mean) for x, y in pairs) / variance
    return y_mean - scale * x_mean, scale


def apply_calibration(rows: list[dict[str, Any]], calibration: dict[str, Any]) -> None:
    intercept = float(calibration["intercept_seconds"])
    scale = float(calibration["scale"])
    for row in rows:
        row["projected_seconds"] = intercept + scale * float(row["projected_schedule_seconds"])


def select_measured(
    rows: list[dict[str, Any]], measurements: dict[str, Any] | None
) -> dict[str, Any] | None:
    if measurements is None:
        return None
    measured_rows = {
        row["label"]: row
        for row in measurements.get("rows", [])
        if row.get("measured_seconds") is not None
    }
    candidates = [row for row in rows if row["label"] in measured_rows]
    if not candidates:
        return None
    fastest = min(candidates, key=lambda row: float(measured_rows[row["label"]]["measured_seconds"]))
    fastest_measurement = measured_rows[fastest["label"]]
    tied = [
        row
        for row in candidates
        if intervals_overlap(
            median_interval(measured_rows[row["label"]]),
            median_interval(fastest_measurement),
        )
    ]
    selected = min(tied, key=lambda row: (measured_size(measured_rows[row["label"]]), row["label"]))
    out = dict(selected)
    out.update(
        {
            "measured_seconds": measured_rows[selected["label"]]["measured_seconds"],
            "heldout_median_ci_seconds": measured_rows[selected["label"]].get(
                "heldout_median_ci_seconds"
            ),
            "heldout_proof_size_median_bytes": measured_size(
                measured_rows[selected["label"]]
            ),
        }
    )
    return out


def measurement_map(measurements: dict[str, Any]) -> dict[str, float]:
    return {
        str(row["label"]): float(row["measured_seconds"])
        for row in measurements.get("rows", [])
        if row.get("measured_seconds") is not None
    }


def median_interval(row: dict[str, Any]) -> tuple[float, float]:
    value = float(row["measured_seconds"])
    interval = row.get("heldout_median_ci_seconds")
    if not isinstance(interval, list) or len(interval) != 2:
        return value, value
    return float(interval[0]), float(interval[1])


def intervals_overlap(left: tuple[float, float], right: tuple[float, float]) -> bool:
    return max(left[0], right[0]) <= min(left[1], right[1])


def measured_size(row: dict[str, Any]) -> int:
    return int(row.get("heldout_proof_size_median_bytes") or proof_size(row))


def proof_size(row: dict[str, Any]) -> int:
    return int(row.get("proof_size_bytes_estimate") or 0)


def ranking_key(row: dict[str, Any]) -> tuple[float, int, str]:
    return float(row["projected_seconds"]), proof_size(row), str(row["label"])


def relative_error(projected: float, measured: float) -> float:
    return abs(projected - measured) / measured if measured > 0.0 else float("inf")


def require_report_mode(report: dict[str, Any], mode: str, name: str) -> None:
    if report.get("proof_mode") != mode:
        raise SystemExit(f"{name} report must use proof_mode={mode}")


def require_matching_provenance(reports: dict[str, dict[str, Any]]) -> Any:
    values = [report.get("provenance") for report in reports.values()]
    first = values[0]
    if any(value != first for value in values[1:]):
        raise SystemExit("component reports have different provenance")
    return first


def read_json(path: str) -> dict[str, Any]:
    with Path(path).open() as file:
        return json.load(file)


def write_json(path: str, value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w") as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write("\n")


if __name__ == "__main__":
    main()
