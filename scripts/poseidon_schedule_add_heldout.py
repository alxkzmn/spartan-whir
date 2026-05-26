#!/usr/bin/env python3
"""Append measured full-proof heldout rows to a schedule calibration JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_VALIDATION_TOLERANCE = 0.20
COMPONENTS = (
    ("spartan", "constraint_work"),
    ("dft", "dft_work"),
    ("merkle", "merkle_work"),
    ("merkle_path", "merkle_path_work"),
    ("row_opening", "row_work"),
    ("sumcheck", "sumcheck_work"),
    ("pow", "pow_work_units"),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calibration", required=True, help="Input calibration JSON")
    parser.add_argument("--heldout", required=True, help="Heldout JSON from poseidon-schedule-heldout")
    parser.add_argument("--out", required=True, help="Output calibration JSON")
    parser.add_argument("--replace", action="store_true", help="Replace existing heldout rows")
    parser.add_argument(
        "--recalibrate",
        action="store_true",
        help="Fit component coefficient scale factors from heldout rows",
    )
    parser.add_argument(
        "--prior-weight",
        type=float,
        default=0.01,
        help="Ridge prior weight keeping scale factors near the component microbench coefficients",
    )
    args = parser.parse_args()

    calibration = read_json(Path(args.calibration))
    heldout = read_json(Path(args.heldout))
    rows = heldout.get("rows")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("heldout JSON must contain a non-empty rows array")
    for row in rows:
        if "measured_seconds" not in row:
            raise SystemExit(f"heldout row {row.get('label')} is missing measured_seconds")

    validation = calibration.setdefault("validation", {})
    validation.setdefault("max_relative_error", DEFAULT_VALIDATION_TOLERANCE)
    validation["note"] = "Heldout rows are real direct-sparse Poseidon proof timings."
    validation["heldout"] = rows if args.replace else [*(validation.get("heldout") or []), *rows]
    if args.recalibrate:
        recalibrate(calibration, validation["heldout"], args.prior_weight)

    write_json(Path(args.out), calibration)
    print(f"heldout_rows={len(validation['heldout'])} out={args.out}")


def recalibrate(calibration: dict[str, Any], rows: list[dict[str, Any]], prior_weight: float) -> None:
    if prior_weight < 0:
        raise SystemExit("--prior-weight must be non-negative")
    coefficients = calibration.get("coefficients")
    if not isinstance(coefficients, dict):
        raise SystemExit("calibration JSON must contain coefficients")
    base: dict[str, float] = {}
    for name, _metric in COMPONENTS:
        source = coefficients.get(name, 0.0)
        if name == "sumcheck" and isinstance(source, dict):
            extensions = {
                str(row.get("extension"))
                for row in usable_candidate_rows(rows)
                if row.get("extension") is not None
            }
            for extension in sorted(extensions):
                if extension not in source:
                    raise SystemExit(f"calibration missing sumcheck coefficient for {extension}")
                base[sumcheck_key(extension)] = float(source[extension])
        else:
            base[name] = float(source)
    fixed = float(coefficients.get("fixed_overhead", 0.0))
    fixed_prior = fixed
    usable = [
        row
        for row in rows
        if float(row.get("measured_seconds") or 0.0) > 0
        and all(metric in row for _name, metric in COMPONENTS)
    ]
    if not usable:
        raise SystemExit("no heldout rows have measured_seconds and component metrics")

    if base["spartan"] == 0.0:
        residuals = []
        for row in usable:
            constraint_work = float(row.get("constraint_work") or 0.0)
            if constraint_work <= 0.0:
                continue
            projected_without_spartan = fixed + sum(
                contribution(base, row, key)
                for key in base
                if key != "spartan"
            )
            residual = float(row["measured_seconds"]) - projected_without_spartan
            if residual > 0.0:
                residuals.append(residual / constraint_work)
        if residuals:
            base["spartan"] = sum(residuals) / len(residuals)

    scales = {key: 1.0 for key in base}
    contributions = [
        {
            key: contribution(base, row, key)
            for key in base
        }
        for row in usable
    ]
    measured = [float(row["measured_seconds"]) for row in usable]
    for _ in range(200):
        # Keep the fixed-cost prior anchored to the input calibration. Component
        # scales are multiplicative and are anchored to 1.0 below.
        denom = len(usable) + prior_weight
        numer = prior_weight * fixed_prior
        for row_contribs, y in zip(contributions, measured):
            rest = sum(
                row_contribs[other] * scales[other] for other in base
            )
            numer += y - rest
        fixed = max(0.0, numer / denom) if denom > 0.0 else fixed
        for name in base:
            denom = prior_weight
            numer = prior_weight
            for row_contribs, y in zip(contributions, measured):
                c = row_contribs[name]
                if c == 0.0:
                    continue
                rest = fixed + sum(
                    row_contribs[other] * scales[other]
                    for other in base
                    if other != name
                )
                denom += c * c
                numer += c * (y - rest)
            scales[name] = max(0.0, numer / denom) if denom > 0.0 else 1.0

    old = dict(coefficients)
    coefficients["fixed_overhead"] = fixed
    for name in base:
        value = base[name] * scales[name]
        if name.startswith("sumcheck:"):
            coefficients.setdefault("sumcheck", {})
            coefficients["sumcheck"][name.split(":", 1)[1]] = value
        else:
            coefficients[name] = value
    calibration["recalibration"] = {
        "method": "heldout_ridge_scale_fit",
        "prior_weight": prior_weight,
        "heldout_rows": len(usable),
        "scale_factors": scales,
        "previous_coefficients": old,
    }


def usable_candidate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if float(row.get("measured_seconds") or 0.0) > 0
        and all(metric in row for _name, metric in COMPONENTS)
    ]


def sumcheck_key(extension: str) -> str:
    return f"sumcheck:{extension}"


def contribution(base: dict[str, float], row: dict[str, Any], key: str) -> float:
    if key.startswith("sumcheck:"):
        extension = key.split(":", 1)[1]
        if row.get("extension") != extension:
            return 0.0
        return base[key] * float(row.get("sumcheck_work") or 0.0)
    metric = dict(COMPONENTS)[key]
    return base[key] * float(row.get(metric) or 0.0)


def read_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
