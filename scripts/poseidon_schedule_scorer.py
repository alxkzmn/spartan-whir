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
DEFAULT_SECURITY_BITS = 123
DEFAULT_ZK_ELL_SWEEP = [3, 4, 8, 16]
DEFAULT_ZK_MASK_LOG_INV_RATE_SWEEP = [1, 2, 3, 4, 5]
DEFAULT_VALIDATION_TOLERANCE = 0.20
DEFAULT_SHORTLIST_MARGIN_RATIO = 0.01

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
    parser.add_argument("--security-bits", type=int, default=DEFAULT_SECURITY_BITS)
    parser.add_argument("--merkle-security-bits", type=int)
    parser.add_argument("--constraint-work", type=int, help="Circuit constraint count for full-prover scoring")
    parser.add_argument("--case-label", help="Optional case label copied into report rows")
    parser.add_argument("--cargo", default="cargo", help="Cargo binary used when --num-variables is set")
    parser.add_argument(
        "--features",
        default="parallel",
        help="Cargo features used to build generated candidates; default: parallel",
    )
    parser.add_argument(
        "--proof-mode",
        choices=("no-zk", "full-zk"),
        default="no-zk",
        help="Proof mode used for candidate validation and cost estimates",
    )
    parser.add_argument(
        "--zk-ell-values",
        help=(
            "Comma-separated ell_zk values to sweep in full-zk mode; "
            f"default: {','.join(map(str, DEFAULT_ZK_ELL_SWEEP))}"
        ),
    )
    parser.add_argument(
        "--zk-mask-log-inv-rate-values",
        help=(
            "Comma-separated mask_log_inv_rate values to sweep in full-zk mode; "
            f"default: {','.join(map(str, DEFAULT_ZK_MASK_LOG_INV_RATE_SWEEP))}"
        ),
    )
    parser.add_argument(
        "--max-report-rows",
        type=int,
        help="Limit stored score rows after ranking; selection still uses all rows",
    )
    parser.add_argument(
        "--measurement-shortlist-margin-seconds",
        type=float,
        help="Include accepted rows within this many projected seconds of the model best",
    )
    parser.add_argument(
        "--measurement-shortlist-margin-ratio",
        type=float,
        help=(
            "Include accepted rows within this fraction of the model best projected time; "
            f"default derives from heldout residuals or falls back to {DEFAULT_SHORTLIST_MARGIN_RATIO:g}"
        ),
    )
    parser.add_argument(
        "--measurements",
        help="Heldout JSON from poseidon-schedule-heldout; adds selected_measured while keeping selected model-based",
    )
    args = parser.parse_args()

    if bool(args.candidates) == bool(args.num_variables):
        raise SystemExit("pass exactly one of --candidates or --num-variables")

    candidates = (
        read_json(Path(args.candidates))
        if args.candidates
        else generate_candidates(
            args.cargo,
            args.num_variables,
            args.max_pow_bits,
            args.field,
            args.proof_mode,
            args.constraint_work,
            parse_int_list(args.zk_ell_values),
            parse_int_list(args.zk_mask_log_inv_rate_values),
            args.features,
            args.security_bits,
            args.merkle_security_bits,
        )
    )
    apply_case_metrics(candidates, args.constraint_work, args.case_label)
    calibration = read_json(Path(args.calibration))
    measurements = read_json(Path(args.measurements)) if args.measurements else None
    report = score_dump(
        candidates,
        calibration,
        args.max_pow_bits,
        args.max_report_rows,
        args.measurement_shortlist_margin_seconds,
        args.measurement_shortlist_margin_ratio,
        measurements,
    )

    write_json(Path(args.out_report), report)
    selected = report.get("selected")
    if selected is None:
        raise SystemExit("no valid schedule found")
    write_json(Path(args.out_config), selected["setup_config"])

    trust = "trusted" if report["model_validation"]["trusted"] else "untrusted"
    message = (
        "selected "
        f"label={selected['label']} "
        f"extension={selected['extension']} "
        f"projected_seconds={selected['projected_seconds']:.9g} "
        f"security_bits={selected['security_bits_achieved']:.3f} "
        f"max_pow_bits={selected['max_derived_pow_bits']} "
        f"model={trust}"
    )
    if report.get("selected_measured") is not None:
        measured = report["selected_measured"]
        message += (
            " measured_selected="
            f"{measured['label']} measured_seconds={measured['measured_seconds']:.9g}"
        )
    print(message)


def score_dump(
    dump: dict[str, Any],
    calibration: dict[str, Any],
    max_pow_bits: int,
    max_report_rows: int | None = None,
    measurement_shortlist_margin_seconds: float | None = None,
    measurement_shortlist_margin_ratio: float | None = None,
    measurements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    require_matching_code_provenance(dump, calibration, "candidate dump", "calibration")
    if measurements is not None:
        require_matching_code_provenance(
            dump, measurements, "candidate dump", "heldout measurements"
        )
    coeffs = normalized_coefficients(calibration)
    validation = validate_model(calibration, coeffs)
    proof_mode = dump.get("proof_mode")
    if proof_mode not in ("no-zk", "full-zk"):
        raise SystemExit("candidate dump must declare proof_mode as no-zk or full-zk")
    if measurements is not None and measurements.get("proof_mode") != proof_mode:
        raise SystemExit("heldout measurements must use the scorer report's proof_mode")
    use_zk_metrics = proof_mode == "full-zk"
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
        projected = projected_seconds(candidate, coeffs, use_zk_metrics)
        row["projected_seconds"] = projected
        row["cost_breakdown"] = cost_breakdown(candidate, coeffs, use_zk_metrics)
        row["accepted_for_ranking"] = not rejection_reasons
        row["rejection_reasons"] = rejection_reasons
        scored.append(row)

    accepted = [row for row in scored if row["accepted_for_ranking"]]
    accepted.sort(
        key=lambda row: (
            float(row["projected_seconds"]),
            proof_size_key(row),
            pow_tie_break_key(row),
            str(row.get("label") or ""),
        )
    )
    selected = accepted[0] if accepted else None
    measurement_shortlist, shortlist_meta = build_measurement_shortlist(
        accepted,
        validation,
        measurement_shortlist_margin_seconds,
        measurement_shortlist_margin_ratio,
    )
    selected_measured, measurement_summary = measured_selection(measurements)

    sorted_scores = sorted(
        scored,
        key=lambda row: (
            not row["accepted_for_ranking"],
            float(row["projected_seconds"]),
            proof_size_key(row),
            pow_tie_break_key(row),
            str(row.get("label") or ""),
        ),
    )
    if max_report_rows is not None:
        sorted_scores = sorted_scores[:max_report_rows]

    return {
        "schema_version": 1,
        "provenance": dump.get("provenance"),
        "source_provenance": {
            "candidates": dump.get("provenance"),
            "calibration": calibration.get("provenance"),
            "measurements": measurements.get("provenance") if measurements else None,
        },
        "source_schema_version": dump.get("schema_version"),
        "num_variables": dump.get("num_variables"),
        "target_security_bits": dump.get("target_security_bits"),
        "max_pow_bits": max_pow_bits,
        "proof_mode": proof_mode,
        "model_validation": validation,
        "coefficients": coeffs,
        "selected": selected,
        "selected_measured": selected_measured,
        "measurement_summary": measurement_summary,
        "measurement_shortlist": measurement_shortlist,
        "measurement_shortlist_meta": shortlist_meta,
        "scores": sorted_scores,
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


def projected_seconds(
    candidate: dict[str, Any], coeffs: dict[str, Any], use_zk_metrics: bool = False
) -> float:
    total = float(coeffs["fixed_overhead"])
    for name, metric in COMPONENTS:
        total += component_seconds(candidate, coeffs, name, metric, use_zk_metrics)
    return total


def cost_breakdown(
    candidate: dict[str, Any], coeffs: dict[str, Any], use_zk_metrics: bool = False
) -> dict[str, float]:
    out = {"fixed_overhead": float(coeffs["fixed_overhead"])}
    for name, metric in COMPONENTS:
        out[name] = component_seconds(candidate, coeffs, name, metric, use_zk_metrics)
    return out


def component_seconds(
    candidate: dict[str, Any],
    coeffs: dict[str, Any],
    name: str,
    metric: str,
    use_zk_metrics: bool = False,
) -> float:
    metric_name = zk_metric_name(metric) if use_zk_metrics else metric
    work = float(candidate.get(metric_name) or candidate.get(metric) or 0.0)
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


def zk_metric_name(metric: str) -> str:
    return {
        "dft_work": "zk_dft_work",
        "merkle_work": "zk_merkle_work",
        "merkle_path_work": "zk_merkle_path_work",
        "row_work": "zk_row_work",
        "sumcheck_work": "zk_sumcheck_work",
    }.get(metric, metric)


def proof_size_key(row: dict[str, Any]) -> int:
    # `proof_size_score` is kept only for candidate JSONs emitted before
    # `proof_size_bytes_estimate` became the canonical tie-breaker.
    return int(
        row.get("heldout_proof_size_median_bytes")
        or row.get("proof_size_bytes_estimate")
        or row.get("proof_size_score")
        or 0
    )


def pow_tie_break_key(row: dict[str, Any]) -> tuple[int, int]:
    return (
        int(row.get("max_derived_pow_bits") or 0),
        int(row.get("pow_work_units") or 0),
    )


def build_measurement_shortlist(
    accepted: list[dict[str, Any]],
    validation: dict[str, Any],
    margin_seconds: float | None,
    margin_ratio: float | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not accepted:
        return [], {
            "margin_seconds": 0.0,
            "margin_source": "empty",
            "pre_dedup_count": 0,
            "dedup_count": 0,
        }
    if margin_seconds is not None and margin_seconds < 0:
        raise SystemExit("--measurement-shortlist-margin-seconds must be non-negative")
    if margin_ratio is not None and margin_ratio < 0:
        raise SystemExit("--measurement-shortlist-margin-ratio must be non-negative")

    best = float(accepted[0]["projected_seconds"])
    if margin_seconds is not None:
        margin = margin_seconds
        source = "cli_seconds"
    elif margin_ratio is not None:
        margin = best * margin_ratio
        source = "cli_ratio"
    else:
        diagnostic = validation.get("ordering_diagnostic") or {}
        derived = diagnostic.get("model_resolution_seconds")
        if derived is not None and float(derived) > 0.0:
            margin = float(derived)
            source = "heldout_residuals"
        else:
            margin = best * DEFAULT_SHORTLIST_MARGIN_RATIO
            source = "default_ratio"

    cutoff = best + margin
    candidates = [
        row
        for row in accepted
        if float(row["projected_seconds"]) <= cutoff
    ]
    deduped = dedup_measurement_shortlist(candidates)
    return deduped, {
        "best_projected_seconds": best,
        "cutoff_projected_seconds": cutoff,
        "margin_seconds": margin,
        "margin_source": source,
        "pre_dedup_count": len(candidates),
        "dedup_count": len(deduped),
        "deduplication": "collapse ell_zk variants by schedule and mask_log_inv_rate",
    }


def dedup_measurement_shortlist(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = measurement_shortlist_key(row)
        old = selected.get(key)
        if old is None or shortlist_preferred(row) < shortlist_preferred(old):
            selected[key] = row
    return sorted(
        selected.values(),
        key=lambda row: (
            float(row["projected_seconds"]),
            proof_size_key(row),
            pow_tie_break_key(row),
            int(row.get("zk_ell") or 0),
            str(row.get("label") or ""),
        ),
    )


def shortlist_preferred(row: dict[str, Any]) -> tuple[int, tuple[int, int], int, float, str]:
    return (
        proof_size_key(row),
        pow_tie_break_key(row),
        int(row.get("zk_ell") or 0),
        float(row.get("projected_seconds") or 0.0),
        str(row.get("label") or ""),
    )


def measurement_shortlist_key(row: dict[str, Any]) -> str:
    setup = json.loads(json.dumps(row.get("setup_config") or {}, sort_keys=True))
    setup.pop("ell_zk", None)
    key = {
        "label": row.get("label"),
        "extension": row.get("extension"),
        "zk_mask_log_inv_rate": row.get("zk_mask_log_inv_rate"),
        "setup_without_ell_zk": setup,
    }
    return json.dumps(key, sort_keys=True)


def measured_selection(
    measurements: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if measurements is None:
        return None, None
    rows = [
        row
        for row in measurements.get("rows", [])
        if float(row.get("measured_seconds") or 0.0) > 0.0
    ]
    if not rows:
        return None, {
            "source_measurements": measurements.get("source_report"),
            "measured_rows": 0,
        }
    ranked = sorted(
        rows,
        key=lambda row: (
            float(row["measured_seconds"]),
            proof_size_key(row),
            pow_tie_break_key(row),
            str(row.get("label") or ""),
        ),
    )
    ties = measured_ties_with_fastest(ranked)
    tied_rows = [row for row in ranked if not demonstrably_slower_than_fastest(row)]
    selected_source = min(
        tied_rows,
        key=lambda row: (
            proof_size_key(row),
            pow_tie_break_key(row),
            str(row.get("label") or ""),
        ),
    )
    selected = dict(selected_source)
    selected["measured_rank"] = ranked.index(selected_source) + 1
    return selected, {
        "source_measurements": measurements.get("source_report"),
        "measured_rows": len(rows),
        "selection": "one_percent_paired_then_proof_size",
        "demonstrable_speed_threshold_relative": 0.01,
        "tied_with_best_count": len(ties),
        "tied_with_best": ties,
    }


def measured_ties_with_fastest(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    tied = []
    for rank, row in enumerate(rows, 1):
        if demonstrably_slower_than_fastest(row):
            continue
        tied.append(
            {
                "measured_rank": rank,
                "label": row.get("label"),
                "zk_ell": row.get("zk_ell"),
                "zk_mask_log_inv_rate": row.get("zk_mask_log_inv_rate"),
                "measured_seconds": row.get("measured_seconds"),
                "heldout_median_ci_seconds": row.get("heldout_median_ci_seconds"),
                "heldout_relative_median_difference": row.get(
                    "heldout_relative_median_difference"
                ),
                "heldout_paired_relative_median_ci": row.get(
                    "heldout_paired_relative_median_ci"
                ),
                "heldout_proof_size_median_bytes": row.get(
                    "heldout_proof_size_median_bytes"
                ),
            }
        )
    return tied


def demonstrably_slower_than_fastest(row: dict[str, Any]) -> bool:
    relative = float(row.get("heldout_relative_median_difference") or 0.0)
    raw_ci = row.get("heldout_paired_relative_median_ci")
    if not isinstance(raw_ci, list) or len(raw_ci) != 2:
        return False
    return relative > 0.01 and float(raw_ci[0]) > 0.0


def median_ci(row: dict[str, Any]) -> tuple[float, float] | None:
    raw = row.get("heldout_median_ci_seconds")
    if not isinstance(raw, list) or len(raw) != 2:
        return None
    return float(raw[0]), float(raw[1])


def intervals_overlap(left: tuple[float, float], right: tuple[float, float]) -> bool:
    return max(left[0], right[0]) <= min(left[1], right[1])


def validate_model(calibration: dict[str, Any], coeffs: dict[str, Any]) -> dict[str, Any]:
    validation = calibration.get("validation") or {}
    tolerance = float(validation.get("max_relative_error", DEFAULT_VALIDATION_TOLERANCE))
    heldout = validation.get("heldout") or []
    rows = []
    trusted = bool(heldout)
    for row in heldout:
        measured = float(row.get("measured_seconds") or 0.0)
        projected = projected_seconds(row, coeffs, row_uses_zk_metrics(row))
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
    ordering = ordering_diagnostic(rows)
    return {
        "trusted": trusted,
        "max_relative_error": tolerance,
        "heldout": rows,
        "ordering_diagnostic": ordering,
    }


def ordering_diagnostic(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [
        row
        for row in rows
        if float(row.get("measured_seconds") or 0.0) > 0.0
        and float(row.get("projected_seconds") or 0.0) > 0.0
    ]
    if len(usable) < 2:
        resolution = (
            abs(float(usable[0]["projected_seconds"]) - float(usable[0]["measured_seconds"]))
            if usable
            else None
        )
        measured = float(usable[0]["measured_seconds"]) if usable else None
        return {
            "comparable_pairs": 0,
            "model_resolution_seconds": resolution,
            "model_resolution_relative": (resolution / measured if resolution and measured else None),
        }

    projected_order = {
        id(row): rank
        for rank, row in enumerate(
            sorted(usable, key=lambda row: float(row["projected_seconds"])),
            1,
        )
    }
    measured_order = {
        id(row): rank
        for rank, row in enumerate(
            sorted(usable, key=lambda row: float(row["measured_seconds"])),
            1,
        )
    }
    concordant = 0
    discordant = 0
    for left_index in range(len(usable)):
        for right_index in range(left_index + 1, len(usable)):
            left = usable[left_index]
            right = usable[right_index]
            projected_delta = projected_order[id(left)] - projected_order[id(right)]
            measured_delta = measured_order[id(left)] - measured_order[id(right)]
            product = projected_delta * measured_delta
            if product > 0:
                concordant += 1
            elif product < 0:
                discordant += 1
    comparable = concordant + discordant
    tau = (concordant - discordant) / comparable if comparable else None
    residuals = [
        abs(float(row["projected_seconds"]) - float(row["measured_seconds"]))
        for row in usable
    ]
    measured_values = sorted(float(row["measured_seconds"]) for row in usable)
    median_measured = measured_values[len(measured_values) // 2]
    resolution = max(residuals)
    return {
        "comparable_pairs": comparable,
        "kendall_tau": tau,
        "concordant_pairs": concordant,
        "discordant_pairs": discordant,
        "projected_span_seconds": max(float(row["projected_seconds"]) for row in usable)
        - min(float(row["projected_seconds"]) for row in usable),
        "measured_span_seconds": max(float(row["measured_seconds"]) for row in usable)
        - min(float(row["measured_seconds"]) for row in usable),
        "model_resolution_seconds": resolution,
        "model_resolution_relative": resolution / median_measured if median_measured > 0 else None,
    }


def row_uses_zk_metrics(row: dict[str, Any]) -> bool:
    return row.get("proof_mode") == "full-zk"


def generate_candidates(
    cargo: str,
    num_variables: int,
    max_pow_bits: int,
    field: str,
    proof_mode: str,
    constraint_work: int | None,
    zk_ell_values: list[int] | None,
    zk_mask_log_inv_rate_values: list[int] | None,
    features: str = "parallel",
    security_bits: int = DEFAULT_SECURITY_BITS,
    merkle_security_bits: int | None = None,
) -> dict[str, Any]:
    num_outer_rounds = (
        max(0, constraint_work - 1).bit_length()
        if constraint_work is not None
        else num_variables
    )
    if proof_mode == "no-zk":
        return generate_candidate_dump(
            cargo,
            num_variables,
            max_pow_bits,
            field,
            proof_mode,
            num_outer_rounds,
            None,
            None,
            features,
            security_bits,
            merkle_security_bits,
        )
    ell_values = zk_ell_values or DEFAULT_ZK_ELL_SWEEP
    mask_rate_values = zk_mask_log_inv_rate_values or DEFAULT_ZK_MASK_LOG_INV_RATE_SWEEP
    dumps = []
    for zk_ell in ell_values:
        for zk_mask_log_inv_rate in mask_rate_values:
            dumps.append(
                generate_candidate_dump(
                    cargo,
                    num_variables,
                    max_pow_bits,
                    field,
                    proof_mode,
                    num_outer_rounds,
                    zk_ell,
                    zk_mask_log_inv_rate,
                    features,
                    security_bits,
                    merkle_security_bits,
                )
            )
    merged = dict(dumps[0])
    merged["candidates"] = []
    merged["zk_ell_sweep"] = [value for value in ell_values if value is not None]
    merged["zk_mask_log_inv_rate_sweep"] = [
        value for value in mask_rate_values if value is not None
    ]
    for dump in dumps:
        require_matching_code_provenance(
            merged, dump, "first candidate dump", "candidate dump"
        )
        for candidate in dump.get("candidates", []):
            row = dict(candidate)
            row["zk_ell"] = dump.get("zk_ell")
            row["zk_mask_log_inv_rate"] = dump.get("zk_mask_log_inv_rate")
            merged["candidates"].append(row)
    return merged


def generate_candidate_dump(
    cargo: str,
    num_variables: int,
    max_pow_bits: int,
    field: str,
    proof_mode: str,
    num_outer_rounds: int,
    zk_ell: int | None,
    zk_mask_log_inv_rate: int | None,
    features: str,
    security_bits: int,
    merkle_security_bits: int | None,
) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[1]
    cmd = [
        cargo,
        "run",
        "-q",
        "--release",
        "--manifest-path",
        str(repo / "Cargo.toml"),
        "--features",
        features,
        "--bin",
        "poseidon-schedule-candidates",
        "--",
        "--num-variables",
        str(num_variables),
        "--field",
        field,
        "--max-pow-bits",
        str(max_pow_bits),
        "--security-bits",
        str(security_bits),
        "--merkle-security-bits",
        str(merkle_security_bits if merkle_security_bits is not None else security_bits),
        "--proof-mode",
        proof_mode,
        "--num-outer-rounds",
        str(num_outer_rounds),
    ]
    if zk_ell is not None:
        cmd.extend(["--zk-ell", str(zk_ell)])
    if zk_mask_log_inv_rate is not None:
        cmd.extend(["--zk-mask-log-inv-rate", str(zk_mask_log_inv_rate)])
    output = subprocess.check_output(cmd, text=True)
    return json.loads(output)


def parse_int_list(raw: str | None) -> list[int] | None:
    if raw is None:
        return None
    values = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise SystemExit("integer list must not be empty")
    return values


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


def require_matching_code_provenance(
    left: dict[str, Any],
    right: dict[str, Any],
    left_name: str,
    right_name: str,
) -> None:
    left_provenance = left.get("provenance")
    right_provenance = right.get("provenance")
    if left_provenance is None and right_provenance is None:
        return
    if left_provenance is None or right_provenance is None:
        raise SystemExit(
            f"cannot combine {left_name} and {right_name}: one artifact is missing provenance"
        )
    if left_provenance != right_provenance:
        raise SystemExit(
            f"cannot combine {left_name} and {right_name}: provenance differs"
        )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
