import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "poseidon_spark_schedule_scorer.py"
SPEC = importlib.util.spec_from_file_location("poseidon_spark_schedule_scorer", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def candidate(label, projected, proof_bytes, starting_log_inv_rate=1):
    return {
        "label": label,
        "extension": "octic",
        "valid": True,
        "proof_size_bytes_estimate": proof_bytes,
        "whir_params": {
            "pow_bits": 0,
            "folding_factor": 4,
            "starting_log_inv_rate": starting_log_inv_rate,
            "rs_domain_initial_reduction_factor": 1,
            "folding_schedule": {"Constant": 4},
            "round_log_inv_rates": [],
        },
        "cost_breakdown": {
            "fixed_overhead": 10.0,
            "spartan": 20.0,
            "dft": projected,
            "merkle": projected,
            "merkle_path": projected,
            "row_opening": projected,
            "sumcheck": projected,
            "pow": projected,
        },
        "dft_work": 1,
        "merkle_work": 1,
    }


def report(mode, variables, rows):
    return {
        "provenance": {"git_commit": "test"},
        "proof_mode": mode,
        "num_variables": variables,
        "target_security_bits": 116,
        "target_merkle_security_bits": 116,
        "component_security_override_bits": 120,
        "component_merkle_security_override_bits": 123,
        "scores": rows,
    }


class SparkScheduleScorerTests(unittest.TestCase):
    def reports(self):
        return {
            "witness": report("full-zk", 20, [candidate("w0", 1.0, 100)]),
            "fixed_value": report("no-zk", 26, [candidate("fv0", 2.0, 200)]),
            "fixed_audit": report("no-zk", 22, [candidate("fa0", 3.0, 300)]),
            "read": report("no-zk", 26, [candidate("r0", 4.0, 400)]),
        }

    def test_composes_full_zk_spark_config_with_one_combined_read_opening(self):
        result = MODULE.compose_report(
            self.reports(),
            116,
            116,
            3,
            3,
            1,
            10,
            1,
            None,
            {"fixed_value": 27, "fixed_audit": 23},
            None,
        )
        row = result["selected"]
        self.assertEqual(row["setup_config"]["matrix_closing"], "Spark")
        self.assertEqual(row["setup_config"]["security"]["security_level_bits"], 116)
        self.assertEqual(result["component_security_bits"], 120)
        self.assertEqual(result["component_merkle_security_bits"], 123)
        self.assertEqual(row["component_scores"]["witness"], 6.0)
        self.assertEqual(row["component_scores"]["fixed_value"], 8.0)
        self.assertEqual(row["component_scores"]["fixed_audit"], 12.0)
        self.assertEqual(row["component_scores"]["read"], 24.0)
        self.assertEqual(row["proof_size_bytes_estimate"], 1000)

    def test_composes_no_zk_spark_config_without_zk_parameters(self):
        reports = self.reports()
        reports["witness"]["proof_mode"] = "no-zk"

        result = MODULE.compose_report(
            reports,
            116,
            116,
            None,
            None,
            1,
            10,
            1,
            None,
            {"fixed_value": 27, "fixed_audit": 23},
            None,
            proof_mode="no-zk",
        )

        row = result["selected"]
        self.assertEqual(result["proof_mode"], "no-zk")
        self.assertEqual(row["proof_mode"], "no-zk")
        self.assertNotIn("ell_zk", row["setup_config"])
        self.assertNotIn("mask_log_inv_rate", row["setup_config"])

    def test_fixed_table_setup_domain_caps_filter_impractical_rates(self):
        reports = self.reports()
        reports["fixed_value"]["scores"] = [
            candidate("huge", 0.1, 10, starting_log_inv_rate=8),
            candidate("bounded", 1.0, 20, starting_log_inv_rate=1),
        ]

        result = MODULE.compose_report(
            reports,
            116,
            116,
            3,
            3,
            2,
            10,
            1,
            None,
            {"fixed_value": 27, "fixed_audit": 23},
            None,
        )

        self.assertEqual(result["selected"]["component_labels"]["fixed_value"], "bounded")

    def test_rejects_component_report_with_end_to_end_target_in_component_field(self):
        reports = self.reports()
        reports["witness"]["target_security_bits"] = 120
        reports["witness"]["component_security_override_bits"] = None

        with self.assertRaisesRegex(SystemExit, "targets end-to-end security"):
            MODULE.compose_report(
                reports,
                116,
                116,
                3,
                3,
                1,
                10,
                1,
                None,
                {"fixed_value": 27, "fixed_audit": 23},
                None,
            )

    def test_rejects_mismatched_component_targets(self):
        reports = self.reports()
        reports["read"]["component_security_override_bits"] = 121

        with self.assertRaisesRegex(SystemExit, "different component security targets"):
            MODULE.compose_report(
                reports,
                116,
                116,
                3,
                3,
                1,
                10,
                1,
                None,
                {"fixed_value": 27, "fixed_audit": 23},
                None,
            )

    def test_affine_calibration_holds_out_every_third_row(self):
        pairs = [(1.0, 3.0), (2.0, 5.0), (4.0, 9.0), (5.0, 11.0)]
        intercept, scale = MODULE.fit_affine(pairs)
        self.assertAlmostEqual(intercept, 1.0)
        self.assertAlmostEqual(scale, 2.0)

    def test_calibration_preserves_model_ordering(self):
        rows = [
            {"label": f"r{i}", "projected_schedule_seconds": float(i)}
            for i in range(1, 5)
        ]
        measurements = {
            "rows": [
                {"label": f"r{i}", "measured_seconds": 10.0 + float(i)}
                for i in range(1, 5)
            ]
        }
        result = MODULE.calibrate(rows, measurements)
        self.assertEqual(result["scale"], 1.0)
        self.assertTrue(result["validation_within_ten_percent"])

    def test_component_calibration_uses_reference_perturbations(self):
        components = ("witness", "fixed_value", "fixed_audit", "read")
        reference_labels = {component: f"{component}0" for component in components}

        def row(label, scores, labels):
            return {
                "label": label,
                "projected_schedule_seconds": sum(scores.values()),
                "component_scores": scores,
                "component_labels": labels,
            }

        reference_scores = {component: 1.0 for component in components}
        rows = [row("reference", reference_scores, reference_labels)]
        measurements = [{"label": "reference", "measured_seconds": 25.0}]
        expected_scales = {
            "witness": 2.0,
            "fixed_value": 3.0,
            "fixed_audit": 4.0,
            "read": 5.0,
        }
        for component in components:
            scores = dict(reference_scores)
            scores[component] = 2.0
            labels = dict(reference_labels)
            labels[component] = f"{component}1"
            rows.append(row(component, scores, labels))
            measurements.append(
                {"label": component, "measured_seconds": 25.0 + expected_scales[component]}
            )
        validation_scores = {component: 2.0 for component in components}
        validation_labels = {component: f"{component}1" for component in components}
        rows.append(row("validation", validation_scores, validation_labels))
        measurements.append({"label": "validation", "measured_seconds": 39.0})

        result = MODULE.calibrate(
            rows,
            {"rows": measurements},
            reference_labels,
        )

        self.assertEqual(result["component_scales"], expected_scales)
        self.assertEqual(result["unit_scale_fallback_components"], [])
        self.assertEqual(result["validation_rows"], 1)
        self.assertTrue(result["validation_within_ten_percent"])

    def test_fixed_score_excludes_only_the_initial_setup_commitment(self):
        row = candidate("fixed", 2.0, 10, starting_log_inv_rate=1)
        row["_component_num_variables"] = 2
        row["dft_work"] = 16
        row["merkle_work"] = 24

        score = MODULE.component_score(row, "fixed_value")

        # Four opening terms cost 8. The initial setup work is 2^(2 + 1) = 8,
        # leaving half the DFT cost and two thirds of the Merkle cost.
        self.assertAlmostEqual(score, 8.0 + 1.0 + 4.0 / 3.0)

    def test_measured_selection_uses_paired_confidence_interval(self):
        rows = [
            {"label": "fast", "proof_size_bytes_estimate": 20},
            {"label": "slow-small", "proof_size_bytes_estimate": 10},
        ]
        measurements = {
            "rows": [
                {
                    "label": "fast",
                    "measured_seconds": 1.0,
                    "heldout_median_ci_seconds": [0.9, 1.2],
                    "heldout_paired_relative_median_ci": [0.0, 0.0],
                    "heldout_proof_size_median_bytes": 20,
                },
                {
                    "label": "slow-small",
                    "measured_seconds": 1.1,
                    "heldout_median_ci_seconds": [0.95, 1.2],
                    "heldout_paired_relative_median_ci": [0.05, 0.15],
                    "heldout_proof_size_median_bytes": 10,
                },
            ]
        }

        selected = MODULE.select_measured(rows, measurements)

        self.assertEqual(selected["label"], "fast")

    def test_measured_selection_uses_proof_size_below_one_percent(self):
        rows = [
            {"label": "fast", "proof_size_bytes_estimate": 20},
            {"label": "small", "proof_size_bytes_estimate": 10},
        ]
        measurements = {
            "rows": [
                {
                    "label": "fast",
                    "measured_seconds": 0.994,
                    "heldout_median_ci_seconds": [0.992, 0.996],
                    "heldout_relative_median_difference": 0.0,
                    "heldout_paired_relative_median_ci": [0.0, 0.0],
                    "heldout_proof_size_median_bytes": 20,
                },
                {
                    "label": "small",
                    "measured_seconds": 1.0,
                    "heldout_median_ci_seconds": [0.998, 1.002],
                    "heldout_relative_median_difference": 0.006,
                    "heldout_paired_relative_median_ci": [0.004, 0.008],
                    "heldout_proof_size_median_bytes": 10,
                },
            ]
        }

        selected = MODULE.select_measured(rows, measurements)

        self.assertEqual(selected["label"], "small")


if __name__ == "__main__":
    unittest.main()
