import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "poseidon_schedule_pareto.py"
spec = importlib.util.spec_from_file_location("poseidon_schedule_pareto", SCRIPT)
pareto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pareto)


def row(
    label,
    *,
    projected,
    proof_size,
    pow_bits=0,
    mask=3,
    ell=3,
    rest=6,
    valid=True,
):
    whir_params = {
        "pow_bits": pow_bits,
        "folding_factor": 8,
        "folding_schedule": {"ConstantFromSecondRound": {"first": 8, "rest": rest}},
        "round_log_inv_rates": [2],
        "rs_domain_initial_reduction_factor": 7,
        "starting_log_inv_rate": 1,
    }
    return {
        "label": label,
        "proof_mode": "full-zk",
        "extension": "octic",
        "accepted_for_ranking": valid,
        "valid": valid,
        "setup_config": {"matrix_closing": "DirectSparse"},
        "projected_seconds": projected,
        "proof_size_bytes_estimate": proof_size,
        "zk_proof_size_bytes_estimate": proof_size,
        "zk_ell": ell,
        "zk_mask_log_inv_rate": mask,
        "zk_mask_queries": 91,
        "max_derived_pow_bits": pow_bits,
        "pow_work_units": 1 << pow_bits if pow_bits else 0,
        "final_queries": 100,
        "final_sumcheck_rounds": 6,
        "whir_params": whir_params,
        "rounds": [{"folding_factor": 8}],
    }


class PoseidonScheduleParetoTests(unittest.TestCase):
    def test_pareto_frontier_keeps_time_size_tradeoff(self):
        points = [
            {"identity": "small", "proof_size_bytes": 10, "estimated_proving_seconds": 5.0},
            {"identity": "dominated", "proof_size_bytes": 12, "estimated_proving_seconds": 6.0},
            {"identity": "fast", "proof_size_bytes": 20, "estimated_proving_seconds": 4.0},
        ]
        frontier = pareto.pareto_frontier(points, "estimated_proving_seconds")
        self.assertEqual([point["identity"] for point in frontier], ["small", "fast"])

    def test_measured_rows_override_estimate(self):
        measured = row("measured", projected=10.0, proof_size=100)
        unmeasured = row("unmeasured", projected=9.0, proof_size=90)
        report = {"proof_mode": "full-zk", "scores": [measured, unmeasured]}
        measurements = [{"proof_mode": "full-zk", "rows": [{**measured, "measured_seconds": 7.0}]}]
        out = pareto.build_pareto_report(report, measurements)
        by_label = {point["label"]: point for point in out["points"]}
        self.assertEqual(by_label["measured"]["proving_time_estimate_kind"], "measured")
        self.assertEqual(by_label["measured"]["estimated_proving_seconds"], 7.0)
        self.assertEqual(
            by_label["unmeasured"]["proving_time_estimate_kind"],
            "interpolated_log_ratio",
        )

    def test_unmeasured_estimated_frontier_rows_become_measurement_candidates(self):
        slow_small = row("slow_small", projected=10.0, proof_size=100)
        fast_large = row("fast_large", projected=5.0, proof_size=200)
        measured = row("anchor", projected=8.0, proof_size=150)
        report = {"proof_mode": "full-zk", "scores": [slow_small, fast_large, measured]}
        measurements = [{"proof_mode": "full-zk", "rows": [{**measured, "measured_seconds": 8.0}]}]
        out = pareto.build_pareto_report(report, measurements)
        candidates = {point["label"] for point in out["measurement_candidates"]}
        self.assertIn("slow_small", candidates)
        self.assertIn("fast_large", candidates)
        self.assertEqual(
            out["measurement_candidates"][0]["setup_config"],
            {"matrix_closing": "DirectSparse"},
        )

    def test_can_omit_full_point_dump(self):
        measured = row("anchor", projected=8.0, proof_size=150)
        out = pareto.build_pareto_report({"proof_mode": "full-zk", "scores": [measured]}, [], include_points=False)
        self.assertNotIn("points", out)

    def test_compact_report_keeps_measured_interior_points(self):
        small = row("small", projected=5.0, proof_size=100)
        fast = row("fast", projected=2.0, proof_size=200)
        measured_dominated = row("measured_dominated", projected=6.0, proof_size=180)
        report = {"proof_mode": "full-zk", "scores": [small, fast, measured_dominated]}
        measurements = [
            {"proof_mode": "full-zk", "rows": [{**measured_dominated, "measured_seconds": 6.0}]}
        ]
        out = pareto.build_pareto_report(report, measurements, include_points=False)
        self.assertNotIn("points", out)
        self.assertEqual(
            [point["label"] for point in out["measured_points"]],
            ["measured_dominated"],
        )

    def test_svg_contains_click_selection_controls(self):
        small = row("small", projected=10.0, proof_size=100)
        fast = row("fast", projected=5.0, proof_size=200)
        report = {"proof_mode": "full-zk", "scores": [small, fast]}
        out = pareto.build_pareto_report(report, [])
        with tempfile.TemporaryDirectory() as tmpdir:
            svg_path = Path(tmpdir) / "pareto.svg"
            pareto.write_svg_plot(svg_path, out)
            svg = svg_path.read_text()
        self.assertIn("function selectPoint", svg)
        self.assertIn('onclick="selectPoint', svg)
        self.assertIn("selected-point-detail", svg)


if __name__ == "__main__":
    unittest.main()
