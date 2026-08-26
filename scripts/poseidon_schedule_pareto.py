#!/usr/bin/env python3
"""Build proving-time/proof-size Pareto reports for Poseidon ZK schedules."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

NEIGHBORS = 4
DISTANCE_EPSILON = 1.0e-9
EXTRAPOLATION_PERCENTILE = 0.95

FEATURE_NAMES = [
    "log_projected_seconds",
    "log_proof_size_bytes",
    "pow_bits",
    "log_pow_work_units",
    "folding_first",
    "folding_rest",
    "starting_log_inv_rate",
    "rs_domain_initial_reduction_factor",
    "round_count",
    "final_queries",
    "final_sumcheck_rounds",
    "zk_ell",
    "zk_mask_log_inv_rate",
    "log_zk_mask_queries",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, help="Schedule scorer report JSON")
    parser.add_argument(
        "--measurements",
        action="append",
        default=[],
        help="Heldout JSON from poseidon-schedule-heldout; may be passed more than once",
    )
    parser.add_argument("--out", required=True, help="Output Pareto report JSON")
    parser.add_argument(
        "--out-svg",
        help="Optional interactive SVG frontier plot with click-to-select details",
    )
    parser.add_argument(
        "--include-points",
        action="store_true",
        help="Include every accepted point in the output JSON; off by default because full sweeps are large",
    )
    args = parser.parse_args()

    report = read_json(Path(args.report))
    measurements = [read_json(Path(path)) for path in args.measurements]
    pareto = build_pareto_report(report, measurements, include_points=args.include_points)
    write_json(Path(args.out), pareto)
    if args.out_svg:
        write_svg_plot(Path(args.out_svg), pareto)
    print(
        "pareto "
        f"points={pareto['summary']['point_count']} "
        f"measured={pareto['summary']['measured_point_count']} "
        f"estimated_frontier={len(pareto['estimated_frontier'])} "
        f"measured_frontier={len(pareto['measured_frontier'])} "
        f"out={args.out}"
        + (f" svg={args.out_svg}" if args.out_svg else "")
    )


def build_pareto_report(
    report: dict[str, Any],
    measurements: list[dict[str, Any]],
    include_points: bool = True,
) -> dict[str, Any]:
    if report.get("proof_mode") != "full-zk":
        raise SystemExit("Pareto search requires a full-zk scorer report")
    for measurement in measurements:
        if measurement.get("proof_mode") != "full-zk":
            raise SystemExit("Pareto measurements must declare proof_mode=full-zk")
    measured = collect_measurements(measurements)
    rows = [
        row
        for row in report.get("scores", [])
        if row.get("accepted_for_ranking")
        and row.get("valid", True)
        and row.get("setup_config") is not None
        and proof_size(row) is not None
        and float(row.get("projected_seconds") or 0.0) > 0.0
    ]
    training_rows = []
    for row in rows:
        entry = measured.get(row_identity(row))
        if entry is None:
            continue
        projected = float(row["projected_seconds"])
        if projected <= 0.0 or entry["measured_seconds"] <= 0.0:
            continue
        training_rows.append(
            {
                "identity": row_identity(row),
                "label": row.get("label"),
                "features": feature_vector(row),
                "projected_seconds": projected,
                "measured_seconds": entry["measured_seconds"],
                "target_log_ratio": math.log(entry["measured_seconds"] / projected),
            }
        )
    model = interpolation_model(training_rows)
    points = [pareto_point(row, measured.get(row_identity(row)), model) for row in rows]
    estimated_frontier = pareto_frontier(points, "estimated_proving_seconds")
    measured_points = [
        point for point in points if point.get("measured_proving_seconds") is not None
    ]
    measured_frontier = pareto_frontier(
        measured_points,
        "measured_proving_seconds",
    )
    estimated_ids = {point["identity"] for point in estimated_frontier}
    measured_ids = {point["identity"] for point in measured_frontier}
    for point in points:
        point["on_estimated_frontier"] = point["identity"] in estimated_ids
        point["on_measured_frontier"] = point["identity"] in measured_ids
    out = {
        "schema_version": 1,
        "source_report": report.get("source_report"),
        "source_num_variables": report.get("num_variables"),
        "proof_mode": "full-zk",
        "target_security_bits": report.get("target_security_bits"),
        "axes": {
            "x": "proof_size_bytes",
            "y": "estimated_proving_seconds",
            "measured_y": "measured_proving_seconds",
            "direction": "lower_is_better_for_both",
        },
        "interpolation": interpolation_report(model),
        "summary": {
            "point_count": len(points),
            "measured_point_count": sum(
                1 for point in points if point.get("measured_proving_seconds") is not None
            ),
            "estimated_frontier_count": len(estimated_frontier),
            "measured_frontier_count": len(measured_frontier),
            "unmeasured_estimated_frontier_count": sum(
                1
                for point in estimated_frontier
                if point.get("proving_time_estimate_kind") != "measured"
            ),
        },
        "estimated_frontier": estimated_frontier,
        "measured_frontier": measured_frontier,
        "measured_points": sorted(
            measured_points,
            key=lambda point: (
                float(point.get("measured_proving_seconds") or float("inf")),
                int(point["proof_size_bytes"]),
                point.get("label") or "",
            ),
        ),
        "measurement_candidates": [
            point
            for point in estimated_frontier
            if point.get("proving_time_estimate_kind") != "measured"
        ],
    }
    if include_points:
        out["points"] = points
    return out


def pareto_point(
    row: dict[str, Any],
    measured: dict[str, Any] | None,
    model: dict[str, Any] | None,
) -> dict[str, Any]:
    projected = float(row["projected_seconds"])
    estimate = estimate_time(row, measured, model)
    out = {
        "identity": row_identity(row),
        "label": row.get("label"),
        "proof_mode": row.get("proof_mode"),
        "extension": row.get("extension"),
        "proof_size_bytes": proof_size(row),
        "estimated_proving_seconds": estimate["seconds"],
        "proving_time_estimate_kind": estimate["kind"],
        "projected_seconds": projected,
        "measured_proving_seconds": measured.get("measured_seconds") if measured else None,
        "measured_sources": measured.get("sources") if measured else [],
        "heldout_sample_count": measured.get("sample_count") if measured else 0,
        "heldout_median_ci_seconds": measured.get("median_ci_seconds") if measured else None,
        "nearest_measured_identity": estimate.get("nearest_identity"),
        "nearest_measured_label": estimate.get("nearest_label"),
        "nearest_measured_distance": estimate.get("nearest_distance"),
        "interpolation_extrapolation": estimate.get("extrapolation"),
        "zk_ell": row.get("zk_ell"),
        "zk_mask_log_inv_rate": row.get("zk_mask_log_inv_rate"),
        "zk_mask_queries": row.get("zk_mask_queries"),
        "max_derived_pow_bits": row.get("max_derived_pow_bits"),
        "pow_work_units": row.get("pow_work_units"),
        "setup_config": row.get("setup_config"),
        "whir_params": row.get("whir_params"),
        "rounds": row.get("rounds"),
    }
    return out


def estimate_time(
    row: dict[str, Any],
    measured: dict[str, Any] | None,
    model: dict[str, Any] | None,
) -> dict[str, Any]:
    if measured is not None:
        return {
            "seconds": measured["measured_seconds"],
            "kind": "measured",
            "nearest_identity": row_identity(row),
            "nearest_label": row.get("label"),
            "nearest_distance": 0.0,
            "extrapolation": False,
        }
    projected = float(row["projected_seconds"])
    if model is None:
        return {
            "seconds": projected,
            "kind": "projected_no_measurements",
            "nearest_identity": None,
            "nearest_label": None,
            "nearest_distance": None,
            "extrapolation": None,
        }
    prediction = interpolated_log_ratio_prediction(feature_vector(row), model)
    return {
        "seconds": projected * math.exp(prediction["log_ratio"]),
        "kind": "interpolated_log_ratio",
        "nearest_identity": prediction["nearest_identity"],
        "nearest_label": prediction["nearest_label"],
        "nearest_distance": prediction["nearest_distance"],
        "extrapolation": prediction["extrapolation"],
    }


def collect_measurements(measurements: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for dump in measurements:
        source = dump.get("source_report") or "<measurement>"
        for row in dump.get("rows", []):
            seconds = float(row.get("measured_seconds") or 0.0)
            if seconds <= 0.0:
                continue
            identity = row_identity(row)
            samples = [
                float(value)
                for value in row.get("heldout_samples_seconds", [])
                if float(value) > 0.0
            ]
            if not samples:
                samples = [seconds]
            entry = grouped.setdefault(
                identity,
                {
                    "samples": [],
                    "sources": [],
                    "rows": [],
                },
            )
            entry["samples"].extend(samples)
            entry["sources"].append(source)
            entry["rows"].append(row)

    out = {}
    for identity, entry in grouped.items():
        samples = sorted(entry["samples"])
        out[identity] = {
            "measured_seconds": median(samples),
            "mean_seconds": sum(samples) / len(samples),
            "sample_count": len(samples),
            "median_ci_seconds": merged_ci(entry["rows"], samples),
            "sources": sorted(set(entry["sources"])),
        }
    return out


def merged_ci(rows: list[dict[str, Any]], samples: list[float]) -> list[float]:
    intervals = [
        row.get("heldout_median_ci_seconds")
        for row in rows
        if isinstance(row.get("heldout_median_ci_seconds"), list)
        and len(row["heldout_median_ci_seconds"]) == 2
    ]
    if intervals:
        return [
            min(float(interval[0]) for interval in intervals),
            max(float(interval[1]) for interval in intervals),
        ]
    return [samples[0], samples[-1]]


def interpolation_model(training_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not training_rows:
        return None
    scales = feature_scales(training_rows)
    nearest_distances = training_nearest_neighbor_distances(training_rows, scales)
    model = {
        "training_rows": training_rows,
        "feature_scales": scales,
        "training_nearest_neighbor_distances": nearest_distances,
        "extrapolation_threshold_z": percentile(
            nearest_distances, EXTRAPOLATION_PERCENTILE
        ),
    }
    model["leave_one_out"] = leave_one_out_rows(model)
    errors = [
        abs(row["relative_error"])
        for row in model["leave_one_out"]
        if row.get("relative_error") is not None
    ]
    model["max_relative_error"] = max(errors) if errors else None
    model["mean_relative_error"] = sum(errors) / len(errors) if errors else None
    return model


def interpolated_log_ratio_prediction(
    features: list[float], model: dict[str, Any]
) -> dict[str, Any]:
    distances = [
        (normalized_feature_distance(features, row["features"], model["feature_scales"]), row)
        for row in model["training_rows"]
    ]
    distances.sort(key=lambda item: item[0])
    nearest_distance, nearest_row = distances[0]
    exact = [
        float(row["target_log_ratio"])
        for distance, row in distances
        if distance <= DISTANCE_EPSILON
    ]
    if exact:
        log_ratio = sum(exact) / len(exact)
    else:
        weighted_sum = 0.0
        weight_total = 0.0
        for distance, row in distances[:NEIGHBORS]:
            weight = 1.0 / (distance * distance + DISTANCE_EPSILON)
            weighted_sum += weight * float(row["target_log_ratio"])
            weight_total += weight
        log_ratio = weighted_sum / weight_total
    threshold = model.get("extrapolation_threshold_z")
    extrapolation = (
        nearest_distance > float(threshold) if threshold is not None else False
    )
    return {
        "log_ratio": log_ratio,
        "nearest_distance": nearest_distance,
        "nearest_identity": nearest_row["identity"],
        "nearest_label": nearest_row["label"],
        "extrapolation": extrapolation,
    }


def leave_one_out_rows(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in model["training_rows"]:
        training_subset = [
            other
            for other in model["training_rows"]
            if other["identity"] != row["identity"]
        ]
        subset_model = interpolation_model_without_diagnostics(training_subset)
        if subset_model is None:
            predicted = None
        else:
            prediction = interpolated_log_ratio_prediction(row["features"], subset_model)
            predicted = row["projected_seconds"] * math.exp(prediction["log_ratio"])
        relative_error = (
            (predicted - row["measured_seconds"]) / row["measured_seconds"]
            if predicted is not None and row["measured_seconds"] > 0.0
            else None
        )
        rows.append(
            {
                "identity": row["identity"],
                "label": row["label"],
                "measured_seconds": row["measured_seconds"],
                "predicted_seconds": predicted,
                "relative_error": relative_error,
            }
        )
    return rows


def interpolation_model_without_diagnostics(
    training_rows: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if not training_rows:
        return None
    scales = feature_scales(training_rows)
    nearest_distances = training_nearest_neighbor_distances(training_rows, scales)
    return {
        "training_rows": training_rows,
        "feature_scales": scales,
        "training_nearest_neighbor_distances": nearest_distances,
        "extrapolation_threshold_z": percentile(
            nearest_distances, EXTRAPOLATION_PERCENTILE
        ),
    }


def interpolation_report(model: dict[str, Any] | None) -> dict[str, Any]:
    if model is None:
        return {
            "mode": "projected_no_measurements",
            "measured_sample_count": 0,
        }
    return {
        "mode": "measured_else_interpolated_log_ratio",
        "features": FEATURE_NAMES,
        "neighbors": NEIGHBORS,
        "distance_epsilon": DISTANCE_EPSILON,
        "extrapolation_threshold_z": model.get("extrapolation_threshold_z"),
        "extrapolation_threshold_percentile": EXTRAPOLATION_PERCENTILE,
        "measured_sample_count": len(model["training_rows"]),
        "training_nearest_neighbor_distance_summary": distance_summary(
            model["training_nearest_neighbor_distances"]
        ),
        "feature_scales": model["feature_scales"],
        "leave_one_out": model["leave_one_out"],
        "max_relative_error": model["max_relative_error"],
        "mean_relative_error": model["mean_relative_error"],
    }


def pareto_frontier(points: list[dict[str, Any]], time_key: str) -> list[dict[str, Any]]:
    frontier = []
    best_time: float | None = None
    for point in sorted(
        points,
        key=lambda row: (
            int(row["proof_size_bytes"]),
            float(row[time_key]),
            row.get("label") or "",
        ),
    ):
        time = float(point[time_key])
        if best_time is None or time < best_time:
            frontier.append(point)
            best_time = time
    return frontier


PLOT_MEASURED = "#0072B2"
PLOT_INTERPOLATED = "#8A8A8A"
PLOT_EXTRAPOLATED = "#E69F00"
PLOT_FRONTIER = "#666666"
PLOT_MEASURED_FRONTIER = "#0072B2"


def write_svg_plot(path: Path, pareto: dict[str, Any]) -> None:
    points = dedupe_points(
        list(pareto.get("estimated_frontier", []))
        + list(pareto.get("measured_frontier", []))
        + list(pareto.get("measured_points", []))
    )
    plot_width, plot_height = 900, 620
    detail_top = plot_height + 20
    width, height = plot_width, detail_top + 112
    margin = 70
    if not points:
        path.write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="620" />\n'
        )
        return

    xs = [float(point["proof_size_bytes"]) for point in points]
    ys = [max(float(point["estimated_proving_seconds"]), 1e-12) for point in points]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    if min_x == max_x:
        max_x += 1.0
    if min_y == max_y:
        max_y *= 1.05
    log_min_y = math.log10(min_y)
    log_max_y = math.log10(max_y)
    if log_min_y == log_max_y:
        log_max_y += 1.0

    def sx(value: float) -> float:
        return margin + (value - min_x) / (max_x - min_x) * (plot_width - 2 * margin)

    def sy(value: float) -> float:
        log_value = math.log10(max(value, 1e-12))
        return (
            plot_height
            - margin
            - (log_value - log_min_y)
            / (log_max_y - log_min_y)
            * (plot_height - 2 * margin)
        )

    x_axis_y = plot_height - margin
    y_axis_x = margin
    estimated_frontier = list(pareto.get("estimated_frontier", []))
    measured_frontier = list(pareto.get("measured_frontier", []))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        plot_click_script(),
        '<rect width="100%" height="100%" fill="white"/>',
        f'<line x1="{margin}" y1="{x_axis_y}" x2="{plot_width-margin}" y2="{x_axis_y}" stroke="#333"/>',
        f'<line x1="{y_axis_x}" y1="{margin}" x2="{y_axis_x}" y2="{x_axis_y}" stroke="#333"/>',
        f'<text x="{plot_width / 2}" y="{plot_height - 20}" text-anchor="middle" font-size="14">ZK proof size estimate, bytes (lower is better)</text>',
        f'<text x="18" y="{plot_height / 2}" transform="rotate(-90 18 {plot_height / 2})" text-anchor="middle" font-size="14">proving time, log scale (lower is better)</text>',
    ]
    parts.extend(axis_ticks_linear(min_x, max_x, sx, x_axis_y))
    parts.extend(axis_ticks_log_seconds(min_y, max_y, sy, y_axis_x))
    if len(estimated_frontier) > 1:
        parts.append(
            frontier_polyline(
                estimated_frontier,
                sx,
                sy,
                PLOT_FRONTIER,
                "3 3",
                0.8,
            )
        )
    if len(measured_frontier) > 1:
        parts.append(
            frontier_polyline(
                measured_frontier,
                sx,
                sy,
                PLOT_MEASURED_FRONTIER,
                "",
                0.95,
            )
        )

    for index, point in enumerate(points):
        x = sx(float(point["proof_size_bytes"]))
        y = sy(float(point["estimated_proving_seconds"]))
        color = marker_color(point)
        stroke = "#333"
        stroke_width = "2" if point.get("on_measured_frontier") else "1"
        title = (
            f"{point.get('label')}; proof_size_bytes={point.get('proof_size_bytes')}; "
            f"estimated_ms={float(point.get('estimated_proving_seconds') or 0.0) * 1000.0:.3f}; "
            f"kind={point.get('proving_time_estimate_kind')}"
        )
        detail_text = point_detail_text(point)
        onclick = (
            f"selectPoint({index}, {escape_xml(json.dumps(detail_text))}); "
            "event.stopPropagation();"
        )
        if point.get("proving_time_estimate_kind") == "measured":
            marker = (
                f'<circle id="point-marker-{index}" data-stroke-width="{stroke_width}" '
                f'cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}" '
                f'stroke="{stroke}" stroke-width="{stroke_width}"/>'
            )
        else:
            marker = (
                f'<path id="point-marker-{index}" data-stroke-width="{stroke_width}" '
                f'd="M {x:.1f} {y - 5:.1f} L {x + 5:.1f} {y:.1f} '
                f'L {x:.1f} {y + 5:.1f} L {x - 5:.1f} {y:.1f} Z" '
                f'fill="{color}" stroke="{stroke}" stroke-width="{stroke_width}"/>'
            )
        parts.append(
            f'<g onclick="{onclick}" style="cursor:pointer">{marker}'
            f"<title>{escape_xml(title)}</title></g>"
        )
    parts.extend(plot_legend(width))
    parts.extend(plot_selected_detail_box(detail_top))
    parts.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n")


def dedupe_points(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for point in points:
        identity = point.get("identity") or json.dumps(point, sort_keys=True)
        if identity in seen:
            continue
        seen.add(identity)
        out.append(point)
    return out


def frontier_polyline(
    frontier: list[dict[str, Any]],
    sx: Any,
    sy: Any,
    stroke: str,
    dasharray: str,
    opacity: float,
) -> str:
    coords = " ".join(
        f"{sx(float(point['proof_size_bytes'])):.1f},"
        f"{sy(float(point['estimated_proving_seconds'])):.1f}"
        for point in frontier
    )
    dash = f' stroke-dasharray="{dasharray}"' if dasharray else ""
    return (
        f'<polyline points="{coords}" fill="none" stroke="{stroke}" '
        f'stroke-width="1.5" opacity="{opacity}"{dash}/>'
    )


def axis_ticks_linear(
    min_value: float, max_value: float, scale: Any, axis_y: float
) -> list[str]:
    parts = []
    for value in regular_ticks(min_value, max_value, 5):
        pos = scale(value)
        label = format_bytes_tick(value)
        parts.extend(
            [
                f'<line x1="{pos:.1f}" y1="{axis_y}" x2="{pos:.1f}" y2="{axis_y + 5}" stroke="#333"/>',
                f'<text x="{pos:.1f}" y="{axis_y + 20}" text-anchor="middle" font-size="11" fill="#333">{label}</text>',
            ]
        )
    return parts


def axis_ticks_log_seconds(
    min_value: float, max_value: float, scale: Any, axis_x: float
) -> list[str]:
    parts = []
    tick_values = log_tick_values(min_value, max_value)
    for value in tick_values:
        pos = scale(value)
        parts.extend(
            [
                f'<line x1="{axis_x - 5}" y1="{pos:.1f}" x2="{axis_x}" y2="{pos:.1f}" stroke="#333"/>',
                f'<text x="{axis_x - 9}" y="{pos + 4:.1f}" text-anchor="end" font-size="11" fill="#333">{format_seconds_tick(value)}</text>',
            ]
        )
    return parts


def regular_ticks(min_value: float, max_value: float, count: int) -> list[float]:
    if count <= 1:
        return [min_value]
    step = (max_value - min_value) / (count - 1)
    return [min_value + step * index for index in range(count)]


def log_tick_values(min_value: float, max_value: float) -> list[float]:
    candidates = []
    start_exp = math.floor(math.log10(min_value))
    end_exp = math.ceil(math.log10(max_value))
    for exponent in range(start_exp, end_exp + 1):
        for mantissa in (1, 2, 5):
            value = mantissa * (10.0**exponent)
            if min_value <= value <= max_value:
                candidates.append(value)
    if min_value not in candidates:
        candidates.insert(0, min_value)
    if max_value not in candidates:
        candidates.append(max_value)
    return candidates


def format_bytes_tick(value: float) -> str:
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.0f}k"
    return f"{value:.0f}"


def format_seconds_tick(value: float) -> str:
    if value < 1.0:
        return f"{value * 1000.0:.0f}ms"
    return f"{value:.1f}s"


def marker_color(point: dict[str, Any]) -> str:
    if point.get("proving_time_estimate_kind") == "measured":
        return PLOT_MEASURED
    if point.get("interpolation_extrapolation"):
        return PLOT_EXTRAPOLATED
    return PLOT_INTERPOLATED


def plot_click_script() -> str:
    return """<script><![CDATA[
let selectedPointIndex = null;
function selectPoint(index, detail) {
  const textarea = document.getElementById("selected-point-detail");
  if (textarea) {
    textarea.value = detail;
    textarea.focus();
    textarea.select();
  }
  if (selectedPointIndex !== null) {
    const oldMarker = document.getElementById("point-marker-" + selectedPointIndex);
    if (oldMarker) {
      oldMarker.setAttribute("stroke-width", oldMarker.getAttribute("data-stroke-width") || "1");
    }
  }
  selectedPointIndex = index;
  const marker = document.getElementById("point-marker-" + index);
  if (marker) {
    marker.setAttribute("stroke-width", "3");
  }
}
]]></script>"""


def plot_legend(width: int) -> list[str]:
    x = width - 330
    return [
        '<g font-size="12">',
        f'<circle cx="{x}" cy="28" r="4.5" fill="{PLOT_MEASURED}" stroke="#333"/>',
        f'<text x="{x + 12}" y="32">measured point</text>',
        f'<path d="M {x:.1f} 43 L {x + 5:.1f} 48 L {x:.1f} 53 L {x - 5:.1f} 48 Z" fill="{PLOT_INTERPOLATED}" stroke="#333"/>',
        f'<text x="{x + 12}" y="52">interpolated frontier candidate</text>',
        f'<path d="M {x:.1f} 63 L {x + 5:.1f} 68 L {x:.1f} 73 L {x - 5:.1f} 68 Z" fill="{PLOT_EXTRAPOLATED}" stroke="#333"/>',
        f'<text x="{x + 12}" y="72">extrapolated frontier candidate</text>',
        f'<line x1="{x - 4}" y1="92" x2="{x + 8}" y2="92" stroke="{PLOT_MEASURED_FRONTIER}" stroke-width="1.5"/>',
        f'<text x="{x + 12}" y="96">measured frontier</text>',
        f'<line x1="{x - 4}" y1="112" x2="{x + 8}" y2="112" stroke="{PLOT_FRONTIER}" stroke-width="1.5" stroke-dasharray="3 3"/>',
        f'<text x="{x + 12}" y="116">measured + interpolated frontier</text>',
        f'<text x="{x - 8}" y="142" fill="#555">click a point for copyable parameters</text>',
        f'<text x="{x - 8}" y="160" fill="#555">unmeasured points are a measurement queue</text>',
        "</g>",
    ]


def plot_selected_detail_box(top: int) -> list[str]:
    return [
        f'<foreignObject x="60" y="{top}" width="790" height="92">',
        '<div xmlns="http://www.w3.org/1999/xhtml" style="font-family: system-ui, -apple-system, sans-serif; font-size: 12px;">',
        '<div style="font-weight: 600; margin-bottom: 4px;">Selected point</div>',
        '<textarea id="selected-point-detail" readonly="readonly" style="box-sizing: border-box; width: 100%; height: 62px; font: 11px monospace; border: 1px solid #aaa; border-radius: 4px; padding: 6px; resize: none;">Click a point to put copyable details here.</textarea>',
        "</div>",
        "</foreignObject>",
    ]


def point_detail_text(point: dict[str, Any]) -> str:
    whir = point.get("whir_params") or {}
    schedule = whir.get("folding_schedule") or {}
    cfsr = schedule.get("ConstantFromSecondRound") if isinstance(schedule, dict) else None
    first = None
    rest = None
    if isinstance(cfsr, dict):
        first = cfsr.get("first")
        rest = cfsr.get("rest")
    else:
        first = whir.get("folding_factor")
        rest = whir.get("folding_factor")
    lines = [
        f"label={point.get('label')}",
        f"extension={point.get('extension')}",
        f"proof_size_bytes={point.get('proof_size_bytes')}",
        f"estimated_proving_ms={float(point.get('estimated_proving_seconds') or 0.0) * 1000.0:.6f}",
        f"proving_time_estimate_kind={point.get('proving_time_estimate_kind')}",
    ]
    if point.get("measured_proving_seconds") is not None:
        lines.append(
            f"measured_proving_ms={float(point['measured_proving_seconds']) * 1000.0:.6f}"
        )
    if point.get("heldout_median_ci_seconds") is not None:
        low, high = point["heldout_median_ci_seconds"]
        lines.append(
            f"heldout_median_ci_ms=[{float(low) * 1000.0:.6f}, {float(high) * 1000.0:.6f}]"
        )
    lines.extend(
        [
            f"zk_ell={point.get('zk_ell')}",
            f"zk_mask_log_inv_rate={point.get('zk_mask_log_inv_rate')}",
            f"zk_mask_queries={point.get('zk_mask_queries')}",
            f"max_derived_pow_bits={point.get('max_derived_pow_bits')}",
            f"folding_first={first}",
            f"folding_rest={rest}",
            f"starting_log_inv_rate={whir.get('starting_log_inv_rate')}",
            f"rs_domain_initial_reduction_factor={whir.get('rs_domain_initial_reduction_factor')}",
            f"nearest_measured_label={point.get('nearest_measured_label')}",
            f"nearest_measured_distance={point.get('nearest_measured_distance')}",
            f"interpolation_extrapolation={point.get('interpolation_extrapolation')}",
        ]
    )
    return "\n".join(lines)


def escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def feature_vector(row: dict[str, Any]) -> list[float]:
    whir = row.get("whir_params") or {}
    schedule = whir.get("folding_schedule")
    first = float(whir.get("folding_factor") or 0)
    rest = first
    if isinstance(schedule, dict):
        cfsr = schedule.get("ConstantFromSecondRound")
        if isinstance(cfsr, dict):
            first = float(cfsr.get("first") or first)
            rest = float(cfsr.get("rest") or first)
    rounds = row.get("rounds") if isinstance(row.get("rounds"), list) else []
    projected = max(float(row.get("projected_seconds") or 0.0), 1e-18)
    size = max(float(proof_size(row) or 0), 1.0)
    return [
        math.log(projected),
        math.log(size),
        float(row.get("max_derived_pow_bits") or whir.get("pow_bits") or 0),
        math.log1p(float(row.get("pow_work_units") or 0)),
        first,
        rest,
        float(whir.get("starting_log_inv_rate") or 0),
        float(whir.get("rs_domain_initial_reduction_factor") or 0),
        float(len(rounds)),
        float(row.get("final_queries") or 0),
        float(row.get("final_sumcheck_rounds") or 0),
        float(row.get("zk_ell") or 0),
        float(row.get("zk_mask_log_inv_rate") or 0),
        math.log1p(float(row.get("zk_mask_queries") or 0)),
    ]


def feature_scales(training_rows: list[dict[str, Any]]) -> list[float]:
    scales = []
    for index in range(len(FEATURE_NAMES)):
        values = [float(row["features"][index]) for row in training_rows]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        scales.append(math.sqrt(variance) or 1.0)
    return scales


def training_nearest_neighbor_distances(
    training_rows: list[dict[str, Any]], scales: list[float]
) -> list[float]:
    out = []
    for index, lhs in enumerate(training_rows):
        nearest = None
        for other_index, rhs in enumerate(training_rows):
            if index == other_index:
                continue
            distance = normalized_feature_distance(lhs["features"], rhs["features"], scales)
            nearest = distance if nearest is None else min(nearest, distance)
        if nearest is not None:
            out.append(nearest)
    return sorted(out)


def normalized_feature_distance(
    lhs: list[float], rhs: list[float], scales: list[float]
) -> float:
    total = 0.0
    for left, right, scale in zip(lhs, rhs, scales):
        total += ((left - right) / scale) ** 2
    return math.sqrt(total)


def row_identity(row: dict[str, Any]) -> str:
    key = {
        "label": row.get("label"),
        "proof_mode": row.get("proof_mode"),
        "extension": row.get("extension"),
        "zk_ell": row.get("zk_ell"),
        "zk_mask_log_inv_rate": row.get("zk_mask_log_inv_rate"),
        "whir_params": row.get("whir_params")
        or (row.get("setup_config") or {}).get("whir_params"),
    }
    return json.dumps(key, sort_keys=True, separators=(",", ":"))


def proof_size(row: dict[str, Any]) -> int | None:
    raw = row.get("zk_proof_size_bytes_estimate") or row.get("proof_size_bytes_estimate")
    return int(raw) if raw is not None else None


def median(values: list[float]) -> float:
    values = sorted(values)
    midpoint = len(values) // 2
    if len(values) % 2:
        return values[midpoint]
    return (values[midpoint - 1] + values[midpoint]) / 2.0


def percentile(values: list[float], quantile: float) -> float | None:
    values = sorted(values)
    if not values:
        return None
    if quantile <= 0.0:
        return values[0]
    if quantile >= 1.0:
        return values[-1]
    index = math.ceil(quantile * len(values)) - 1
    return values[max(0, min(index, len(values) - 1))]


def distance_summary(values: list[float]) -> dict[str, float | None]:
    values = sorted(values)
    return {
        "min": values[0] if values else None,
        "median": median(values) if values else None,
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "max": values[-1] if values else None,
    }


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
