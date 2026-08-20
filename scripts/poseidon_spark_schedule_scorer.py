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
    parser.add_argument(
        "--proof-mode",
        choices=("no-zk", "full-zk"),
        default="full-zk",
    )
    parser.add_argument("--security-bits", type=int, required=True)
    parser.add_argument("--merkle-security-bits", type=int, required=True)
    parser.add_argument("--ell-zk", type=int)
    parser.add_argument("--mask-log-inv-rate", type=int)
    parser.add_argument("--top-per-component", type=int, default=8)
    parser.add_argument("--max-report-rows", type=int, default=100)
    parser.add_argument("--measurement-rows", type=int, default=10)
    parser.add_argument("--max-fixed-value-log-domain", type=int, required=True)
    parser.add_argument("--max-fixed-audit-log-domain", type=int, required=True)
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
    if args.proof_mode == "full-zk" and (
        args.ell_zk is None or args.mask_log_inv_rate is None
    ):
        raise SystemExit("full-zk composition requires --ell-zk and --mask-log-inv-rate")
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
            "fixed_value": args.max_fixed_value_log_domain,
            "fixed_audit": args.max_fixed_audit_log_domain,
        },
        {
            "witness": args.reference_witness_label,
            "fixed_value": args.reference_fixed_value_label,
            "fixed_audit": args.reference_fixed_audit_label,
            "read": args.reference_read_label,
        },
        proof_mode=args.proof_mode,
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
    ell_zk: int | None,
    mask_log_inv_rate: int | None,
    top_per_component: int,
    max_report_rows: int,
    measurement_rows: int,
    measurements: dict[str, Any] | None,
    fixed_setup_log_domain_caps: dict[str, int],
    reference_labels: dict[str, str | None] | None = None,
    proof_mode: str = "full-zk",
) -> dict[str, Any]:
    if min(top_per_component, max_report_rows, measurement_rows) <= 0:
        raise SystemExit("row limits must be positive")
    provenance = require_matching_provenance(reports)
    if proof_mode not in ("no-zk", "full-zk"):
        raise SystemExit(f"unsupported SPARK proof mode: {proof_mode}")
    require_report_mode(reports["witness"], proof_mode, "witness")
    for component in ("fixed_value", "fixed_audit", "read"):
        require_report_mode(reports[component], "no-zk", component)
    component_security_bits, component_merkle_security_bits = require_security_targets(
        reports, security_bits, merkle_security_bits
    )

    ranked = {
        component: component_rows(
            report,
            component,
            top_per_component,
            fixed_setup_log_domain_caps.get(component),
        )
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
                proof_mode,
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
        proof_mode,
    )
    rows = rows[:max_report_rows]
    for row in shortlist:
        if all(existing["label"] != row["label"] for existing in rows):
            rows.append(row)
    rows.sort(key=ranking_key)

    calibration = calibrate(rows, measurements, reference_labels or {})
    if calibration is not None:
        apply_calibration(rows, calibration)
        rows.sort(key=ranking_key)

    selected_measured = select_measured(rows, measurements)
    return {
        "schema_version": 2,
        "provenance": provenance,
        "matrix_closing": "Spark",
        "proof_mode": proof_mode,
        "security_bits": security_bits,
        "merkle_security_bits": merkle_security_bits,
        "component_security_bits": component_security_bits,
        "component_merkle_security_bits": component_merkle_security_bits,
        "ell_zk": ell_zk,
        "mask_log_inv_rate": mask_log_inv_rate,
        "component_num_variables": {
            component: report.get("num_variables") for component, report in reports.items()
        },
        "model": {
            "formula": "witness + fixed post-setup commitments/openings + combined read commit/open",
            "fixed_value_excludes_setup_commitment": True,
            "fixed_audit_excludes_setup_commitment": True,
            "fixed_setup_log_domain_caps": fixed_setup_log_domain_caps,
            "calibration": calibration,
        },
        "selected": rows[0],
        "selected_measured": selected_measured,
        "measurement_shortlist": shortlist,
        "scores": rows,
    }


def require_security_targets(
    reports: dict[str, dict[str, Any]],
    security_bits: int,
    merkle_security_bits: int,
) -> tuple[int, int]:
    component_targets = set()
    for component, report in reports.items():
        report_security = report.get("target_security_bits")
        report_merkle = report.get("target_merkle_security_bits")
        if (report_security, report_merkle) != (security_bits, merkle_security_bits):
            raise SystemExit(
                f"{component} report targets end-to-end security "
                f"{report_security}/{report_merkle}, expected "
                f"{security_bits}/{merkle_security_bits}"
            )
        component_security = report.get("component_security_override_bits")
        component_merkle = report.get("component_merkle_security_override_bits")
        if not isinstance(component_security, int) or not isinstance(component_merkle, int):
            raise SystemExit(f"{component} report is missing explicit component security targets")
        component_targets.add((component_security, component_merkle))
    if len(component_targets) != 1:
        raise SystemExit("SPARK component reports use different component security targets")
    return component_targets.pop()


def stratified_shortlist(
    ranked: dict[str, list[dict[str, Any]]],
    rows: list[dict[str, Any]],
    security_bits: int,
    merkle_security_bits: int,
    ell_zk: int | None,
    mask_log_inv_rate: int | None,
    limit: int,
    reports: dict[str, dict[str, Any]],
    reference_labels: dict[str, str | None],
    proof_mode: str,
) -> list[dict[str, Any]]:
    best = {component: candidates[0] for component, candidates in ranked.items()}
    selected = rows[: min(2, len(rows))]
    if any(reference_labels.values()):
        if not all(reference_labels.values()):
            raise SystemExit("all four reference labels are required together")
        reference = {
            component: find_report_row(reports[component], str(label), component)
            for component, label in reference_labels.items()
        }
        selected = [rows[0], composed_row(
            reference["witness"],
            reference["fixed_value"],
            reference["fixed_audit"],
            reference["read"],
            security_bits,
            merkle_security_bits,
            ell_zk,
            mask_log_inv_rate,
            proof_mode,
        )]
        for component in ("witness", "fixed_value", "fixed_audit", "read"):
            alternatives = [
                candidate
                for candidate in ranked[component]
                if candidate["label"] != reference_labels[component]
            ][:2]
            for alternative in alternatives:
                choice = dict(reference)
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
                        proof_mode,
                    )
                )
    else:
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
                        proof_mode,
                    )
                )
    selected = deduplicate_rows(selected)
    return selected[:limit]


def find_report_row(
    report: dict[str, Any], label: str, component: str
) -> dict[str, Any]:
    for row in report.get("scores", []):
        if row.get("label") == label and row.get("extension") == "octic":
            return {**row, "_component_num_variables": report.get("num_variables")}
    raise SystemExit(f"{component} reference label not found: {label}")


def component_rows(
    report: dict[str, Any],
    component: str,
    limit: int,
    max_setup_log_domain: int | None,
) -> list[dict[str, Any]]:
    rows = [
        {**row, "_component_num_variables": report.get("num_variables")}
        for row in report.get("scores", [])
        if row.get("valid", True)
        and row.get("extension") == "octic"
        and row.get("whir_params") is not None
        and within_setup_domain_cap(report, row, max_setup_log_domain)
    ]
    rows.sort(key=lambda row: (component_score(row, component), proof_size(row), row["label"]))
    if not rows:
        raise SystemExit(f"{component} report has no valid octic rows")
    return rows[:limit]


def within_setup_domain_cap(
    report: dict[str, Any], row: dict[str, Any], max_setup_log_domain: int | None
) -> bool:
    if max_setup_log_domain is None:
        return True
    num_variables = report.get("num_variables")
    starting_log_inv_rate = (row.get("whir_params") or {}).get("starting_log_inv_rate")
    if not isinstance(num_variables, int) or not isinstance(starting_log_inv_rate, int):
        return False
    return num_variables + starting_log_inv_rate <= max_setup_log_domain


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
        multiplier = 1.0
    else:
        raise AssertionError(component)
    score = multiplier * sum(float(costs.get(name) or 0.0) for name in names)
    if component in ("fixed_value", "fixed_audit"):
        score += post_setup_commitment_cost(row)
    return score


def post_setup_commitment_cost(row: dict[str, Any]) -> float:
    num_variables = row.get("_component_num_variables")
    params = row.get("whir_params") or {}
    starting_log_inv_rate = params.get("starting_log_inv_rate")
    if not isinstance(num_variables, int) or not isinstance(starting_log_inv_rate, int):
        return 0.0
    initial_work = 1 << (num_variables + starting_log_inv_rate)
    costs = row.get("cost_breakdown") or {}
    total = 0.0
    for cost_name, work_name in (("dft", "dft_work"), ("merkle", "merkle_work")):
        work = int(row.get(work_name) or 0)
        if work <= 0:
            continue
        post_setup_work = max(0, work - initial_work)
        total += float(costs.get(cost_name) or 0.0) * post_setup_work / work
    return total


def composed_row(
    witness: dict[str, Any],
    fixed_value: dict[str, Any],
    fixed_audit: dict[str, Any],
    read: dict[str, Any],
    security_bits: int,
    merkle_security_bits: int,
    ell_zk: int | None,
    mask_log_inv_rate: int | None,
    proof_mode: str,
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
        + proof_size(read)
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
    setup_config = {
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
    }
    if proof_mode == "full-zk":
        if ell_zk is None or mask_log_inv_rate is None:
            raise SystemExit("full-zk composition requires ZK mask parameters")
        setup_config["ell_zk"] = ell_zk
        setup_config["mask_log_inv_rate"] = mask_log_inv_rate
    return {
        "label": label,
        "extension": "octic",
        "valid": True,
        "proof_mode": proof_mode,
        "matrix_closing": "Spark",
        "projected_schedule_seconds": projected,
        "projected_seconds": projected,
        "proof_size_bytes_estimate": size,
        "component_labels": labels,
        "component_scores": scores,
        "setup_config": setup_config,
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
    rows: list[dict[str, Any]],
    measurements: dict[str, Any] | None,
    reference_labels: dict[str, str | None] | None = None,
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
    if reference_labels and all(reference_labels.values()):
        component_calibration = calibrate_components(rows, measured, reference_labels)
        if component_calibration is not None:
            return component_calibration
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


def calibrate_components(
    rows: list[dict[str, Any]],
    measured: dict[str, float],
    reference_labels: dict[str, str | None],
) -> dict[str, Any] | None:
    components = ("witness", "fixed_value", "fixed_audit", "read")
    reference = next(
        (
            row
            for row in rows
            if row["label"] in measured
            and all(row["component_labels"][name] == reference_labels[name] for name in components)
        ),
        None,
    )
    if reference is None:
        return None

    reference_time = measured[reference["label"]]
    scales = {}
    fallback_components = []
    calibration_labels = {reference["label"]}
    for component in components:
        slopes = []
        for row in rows:
            if row["label"] not in measured:
                continue
            if any(
                row["component_labels"][name] != reference_labels[name]
                for name in components
                if name != component
            ):
                continue
            delta_score = float(row["component_scores"][component]) - float(
                reference["component_scores"][component]
            )
            if delta_score == 0.0:
                continue
            slopes.append((measured[row["label"]] - reference_time) / delta_score)
            calibration_labels.add(row["label"])
        if not slopes:
            return None
        slopes.sort()
        fitted_scale = slopes[len(slopes) // 2]
        if fitted_scale <= 0.0:
            fitted_scale = 1.0
            fallback_components.append(component)
        scales[component] = fitted_scale

    intercept = reference_time - sum(
        scales[component] * float(reference["component_scores"][component])
        for component in components
    )
    validation_rows = [
        row
        for row in rows
        if row["label"] in measured and row["label"] not in calibration_labels
    ]
    errors = [
        relative_error(
            intercept
            + sum(
                scales[component] * float(row["component_scores"][component])
                for component in components
            ),
            measured[row["label"]],
        )
        for row in validation_rows
    ]
    return {
        "method": "per-component slopes from configured-reference perturbations",
        "intercept_seconds": intercept,
        "component_scales": scales,
        "unit_scale_fallback_components": fallback_components,
        "calibration_rows": len(calibration_labels),
        "validation_rows": len(validation_rows),
        "validation_max_relative_error": max(errors) if errors else None,
        "validation_within_ten_percent": bool(errors) and max(errors) <= 0.10,
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
    component_scales = calibration.get("component_scales")
    if component_scales is not None:
        for row in rows:
            row["projected_seconds"] = intercept + sum(
                float(component_scales[component]) * float(row["component_scores"][component])
                for component in ("witness", "fixed_value", "fixed_audit", "read")
            )
        return
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
        if measurement_is_tied(measured_rows[row["label"]], fastest_measurement)
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


def measurement_is_tied(row: dict[str, Any], fastest: dict[str, Any]) -> bool:
    paired = row.get("heldout_paired_relative_median_ci")
    if isinstance(paired, list) and len(paired) == 2:
        relative = row.get("heldout_relative_median_difference")
        if relative is None:
            fastest_seconds = float(fastest["measured_seconds"])
            relative = (
                (float(row["measured_seconds"]) - fastest_seconds) / fastest_seconds
                if fastest_seconds > 0.0
                else float("inf")
            )
        relative = float(relative)
        return relative <= 0.01 or float(paired[0]) <= 0.0 <= float(paired[1])
    return intervals_overlap(median_interval(row), median_interval(fastest))


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
