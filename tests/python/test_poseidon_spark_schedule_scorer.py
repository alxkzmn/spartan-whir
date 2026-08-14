import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "poseidon_spark_schedule_scorer.py"
SPEC = importlib.util.spec_from_file_location("poseidon_spark_schedule_scorer", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def candidate(label, projected, proof_bytes):
    return {
        "label": label,
        "extension": "octic",
        "valid": True,
        "proof_size_bytes_estimate": proof_bytes,
        "whir_params": {
            "pow_bits": 0,
            "folding_factor": 4,
            "starting_log_inv_rate": 1,
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
    }


def report(mode, variables, rows):
    return {
        "provenance": {"git_commit": "test"},
        "proof_mode": mode,
        "num_variables": variables,
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

    def test_composes_full_zk_spark_config_and_weights_read_twice(self):
        result = MODULE.compose_report(self.reports(), 116, 116, 3, 3, 1, 10, 1, None, None)
        row = result["selected"]
        self.assertEqual(row["setup_config"]["matrix_closing"], "Spark")
        self.assertEqual(row["setup_config"]["security"]["security_level_bits"], 116)
        self.assertEqual(row["component_scores"]["witness"], 6.0)
        self.assertEqual(row["component_scores"]["fixed_value"], 8.0)
        self.assertEqual(row["component_scores"]["fixed_audit"], 12.0)
        self.assertEqual(row["component_scores"]["read"], 48.0)
        self.assertEqual(row["proof_size_bytes_estimate"], 1400)

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


if __name__ == "__main__":
    unittest.main()
