#!/usr/bin/env python3
"""Rank Poseidon Plonky3-WHIR direct-sparse schedules.

The Rust candidate dumper derives WHIR security/query/PoW values from the
backend. This script only scores already-derived candidates.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_MAX_POW_BITS = 22
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
    parser.add_argument("--candidates", help="Candidate JSON from poseidon-schedule-candidates")
    parser.add_argument("--num-variables", type=int, help="Generate candidates for this size")
    parser.add_argument("--field", default="koalabear", help="Field profile: koalabear or babybear")
    parser.add_argument("--calibration", required=True, help="Component calibration JSON")
    parser.add_argument("--out-report", required=True, help="Ranked report JSON path")
    parser.add_argument("--out-config", required=True, help="Selected PoseidonSetupConfig JSON path")
    parser.add_argument("--max-pow-bits", type=int, default=DEFAULT_MAX_POW_BITS)
    parser.add_argument("--constraint-work", type=int, help="Circuit constraint count for full-prover scoring")
    parser.add_argument("--case-label", help="Optional case label copied into report rows")
    parser.add_argument("--cargo", default="cargo", help="Cargo binary used when --num-variables is set")
    args = parser.parse_args()

    if bool(args.candidates) == bool(args.num_variables):
        raise SystemExit("pass exactly one of --candidates or --num-variables")

    candidates = (
        read_json(Path(args.candidates))
        if args.candidates
        else generate_candidates(args.cargo, args.num_variables, args.max_pow_bits, args.field)
    )
    apply_case_metrics(candidates, args.constraint_work, args.case_label)
    calibration = read_json(Path(args.calibration))
    report = score_dump(candidates, calibration, args.max_pow_bits)

    write_json(Path(args.out_report), report)
    selected = report.get("selected")
    if selected is None:
        raise SystemExit("no valid schedule found")
    write_json(Path(args.out_config), selected["setup_config"])

    trust = "trusted" if report["model_validation"]["trusted"] else "untrusted"
    print(
        "selected "
        f"label={selected['label']} "
        f"extension={selected['extension']} "
        f"projected_seconds={selected['projected_seconds']:.9g} "
        f"security_bits={selected['security_bits_achieved']:.3f} "
        f"max_pow_bits={selected['max_derived_pow_bits']} "
        f"model={trust}"
    )


def score_dump(
    dump: dict[str, Any], calibration: dict[str, Any], max_pow_bits: int
) -> dict[str, Any]:
    coeffs = normalized_coefficients(calibration)
    validation = validate_model(calibration, coeffs)
    scored = []
    for candidate in dump.get("candidates", []):
        row = dict(candidate)
        rejection_reasons = list(filter(None, [candidate.get("rejection_reason")]))
        if not candidate.get("valid"):
            rejection_reasons.append("candidate marked invalid by backend")
        derived_pow = candidate.get("max_derived_pow_bits")
        if derived_pow is None:
            rejection_reasons.append("missing derived PoW")
        elif int(derived_pow) > max_pow_bits:
            rejection_reasons.append(f"derived PoW {derived_pow} exceeds max {max_pow_bits}")
        if candidate.get("setup_config") is None:
            rejection_reasons.append("missing setup config")
        projected = projected_seconds(candidate, coeffs)
        row["projected_seconds"] = projected
        row["cost_breakdown"] = cost_breakdown(candidate, coeffs)
        row["accepted_for_ranking"] = not rejection_reasons
        row["rejection_reasons"] = rejection_reasons
        scored.append(row)

    accepted = [row for row in scored if row["accepted_for_ranking"]]
    accepted.sort(
        key=lambda row: (
            float(row["projected_seconds"]),
            proof_size_key(row),
            str(row.get("label") or ""),
        )
    )
    selected = accepted[0] if accepted else None

    return {
        "schema_version": 1,
        "source_schema_version": dump.get("schema_version"),
        "num_variables": dump.get("num_variables"),
        "target_security_bits": dump.get("target_security_bits"),
        "max_pow_bits": max_pow_bits,
        "model_validation": validation,
        "coefficients": coeffs,
        "selected": selected,
        "scores": sorted(
            scored,
            key=lambda row: (
                not row["accepted_for_ranking"],
                float(row["projected_seconds"]),
                str(row.get("label") or ""),
            ),
        ),
    }


def normalized_coefficients(calibration: dict[str, Any]) -> dict[str, Any]:
    source = calibration.get("coefficients")
    if not isinstance(source, dict):
        raise SystemExit("calibration JSON must contain a coefficients object")
    coeffs: dict[str, Any] = {"fixed_overhead": float(source.get("fixed_overhead", 0.0))}
    for name, _metric in COMPONENTS:
        if name == "spartan" and name not in source:
            coeffs[name] = 0.0
            continue
        if name == "merkle_path" and name not in source:
            coeffs[name] = 0.0
            continue
        if name not in source:
            raise SystemExit(f"calibration missing coefficient {name}")
        if name == "sumcheck" and isinstance(source[name], dict):
            coeffs[name] = {key: float(value) for key, value in source[name].items()}
        else:
            coeffs[name] = float(source[name])
    return coeffs


def projected_seconds(candidate: dict[str, Any], coeffs: dict[str, Any]) -> float:
    total = float(coeffs["fixed_overhead"])
    for name, metric in COMPONENTS:
        total += component_seconds(candidate, coeffs, name, metric)
    return total


def cost_breakdown(candidate: dict[str, Any], coeffs: dict[str, Any]) -> dict[str, float]:
    out = {"fixed_overhead": float(coeffs["fixed_overhead"])}
    for name, metric in COMPONENTS:
        out[name] = component_seconds(candidate, coeffs, name, metric)
    return out


def component_seconds(
    candidate: dict[str, Any], coeffs: dict[str, Any], name: str, metric: str
) -> float:
    work = float(candidate.get(metric) or 0.0)
    if work == 0.0:
        return 0.0
    return coefficient_for(candidate, coeffs, name) * work


def coefficient_for(candidate: dict[str, Any], coeffs: dict[str, Any], name: str) -> float:
    coeff = coeffs[name]
    if isinstance(coeff, dict):
        extension = candidate.get("extension")
        if extension not in coeff:
            raise SystemExit(f"missing {name} coefficient for extension {extension}")
        return float(coeff[extension])
    return float(coeff)


def proof_size_key(row: dict[str, Any]) -> int:
    # `proof_size_score` is kept only for candidate JSONs emitted before
    # `proof_size_bytes_estimate` became the canonical tie-breaker.
    return int(row.get("proof_size_bytes_estimate") or row.get("proof_size_score") or 0)


def validate_model(calibration: dict[str, Any], coeffs: dict[str, Any]) -> dict[str, Any]:
    validation = calibration.get("validation") or {}
    tolerance = float(validation.get("max_relative_error", DEFAULT_VALIDATION_TOLERANCE))
    heldout = validation.get("heldout") or []
    rows = []
    trusted = bool(heldout)
    for row in heldout:
        measured = float(row.get("measured_seconds") or 0.0)
        projected = projected_seconds(row, coeffs)
        rel_error = abs(projected - measured) / measured if measured > 0 else float("inf")
        ok = rel_error <= tolerance
        trusted = trusted and ok
        rows.append(
            {
                "label": row.get("label"),
                "measured_seconds": measured,
                "projected_seconds": projected,
                "relative_error": rel_error,
                "ok": ok,
            }
        )
    return {
        "trusted": trusted,
        "max_relative_error": tolerance,
        "heldout": rows,
    }


def generate_candidates(
    cargo: str, num_variables: int, max_pow_bits: int, field: str
) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    cmd = [
        cargo,
        "run",
        "-q",
        "--manifest-path",
        str(repo / "Cargo.toml"),
        "--bin",
        "poseidon-schedule-candidates",
        "--",
        "--num-variables",
        str(num_variables),
        "--field",
        field,
        "--max-pow-bits",
        str(max_pow_bits),
    ]
    output = subprocess.check_output(cmd, text=True)
    return json.loads(output)


def apply_case_metrics(
    dump: dict[str, Any], constraint_work: int | None, case_label: str | None
) -> None:
    if constraint_work is not None:
        dump["constraint_work"] = constraint_work
    if case_label is not None:
        dump["case_label"] = case_label
    for candidate in dump.get("candidates", []):
        if constraint_work is not None:
            candidate["constraint_work"] = constraint_work
        if case_label is not None:
            candidate["case_label"] = case_label


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
