import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "poseidon_schedule_scorer.py"
spec = importlib.util.spec_from_file_location("poseidon_schedule_scorer", SCRIPT)
scorer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scorer)

ADD_HELDOUT_SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "poseidon_schedule_add_heldout.py"
)
add_heldout_spec = importlib.util.spec_from_file_location(
    "poseidon_schedule_add_heldout", ADD_HELDOUT_SCRIPT
)
add_heldout = importlib.util.module_from_spec(add_heldout_spec)
add_heldout_spec.loader.exec_module(add_heldout)


def candidate(
    label,
    *,
    extension="octic",
    valid=True,
    max_pow=10,
    dft=0,
    merkle=0,
    merkle_path=0,
    row=0,
    sumcheck=0,
    pow_work=0,
    proof_size_bytes=None,
    legacy_proof_size=None,
):
    out = {
        "label": label,
        "extension": extension,
        "valid": valid,
        "rejection_reason": None if valid else "invalid",
        "security_bits_achieved": 128.0,
        "max_derived_pow_bits": max_pow,
        "constraint_work": 0,
        "dft_work": dft,
        "merkle_work": merkle,
        "merkle_path_work": merkle_path,
        "row_work": row,
        "sumcheck_work": sumcheck,
        "pow_work_units": pow_work,
        "proof_size_bytes_estimate": proof_size_bytes,
        "setup_config": {"matrix_closing": "DirectSparse", "label": label} if valid else None,
    }
    if legacy_proof_size is not None:
        out["proof_size_score"] = legacy_proof_size
    return out


class PoseidonScheduleScorerTests(unittest.TestCase):
    def calibration(self, heldout=None):
        return {
            "coefficients": {
                "fixed_overhead": 0.0,
                "dft": 1.0,
                "merkle": 1.0,
                "merkle_path": 1.0,
                "row_opening": 1.0,
                "sumcheck": 1.0,
                "pow": 1.0,
            },
            "validation": {
                "max_relative_error": 0.10,
                "heldout": heldout or [
                    {
                        "label": "heldout",
                        "measured_seconds": 10.0,
                        "dft_work": 10,
                    }
                ],
            },
        }

    def per_extension_calibration(self):
        calibration = self.calibration()
        calibration["coefficients"]["sumcheck"] = {
            "quartic": 0.25,
            "quintic": 0.4,
            "octic": 1.0,
        }
        return calibration

    def test_rejects_over_cap_pow(self):
        dump = {"schema_version": 1, "candidates": [candidate("bad", max_pow=23, dft=1)]}
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertIsNone(report["selected"])
        self.assertIn("exceeds max", report["scores"][0]["rejection_reasons"][-1])

    def test_selects_lowest_projected_time(self):
        dump = {
            "schema_version": 1,
            "candidates": [
                candidate("slow", dft=10),
                candidate("fast", dft=2),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "fast")
        self.assertIn("cost_breakdown", report["selected"])

    def test_cost_breakdown_includes_merkle_path(self):
        dump = {"schema_version": 1, "candidates": [candidate("a", merkle_path=7)]}
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["cost_breakdown"]["merkle_path"], 7.0)

    def test_legacy_calibration_defaults_merkle_path_to_zero(self):
        calibration = self.calibration()
        del calibration["coefficients"]["merkle_path"]
        dump = {"schema_version": 1, "candidates": [candidate("a", merkle_path=7)]}
        report = scorer.score_dump(dump, calibration, max_pow_bits=22)
        self.assertEqual(report["selected"]["cost_breakdown"]["merkle_path"], 0.0)

    def test_uses_extension_specific_sumcheck_coefficients(self):
        dump = {
            "schema_version": 1,
            "candidates": [
                candidate("octic", extension="octic", sumcheck=10),
                candidate("quartic", extension="quartic", sumcheck=10),
            ],
        }
        report = scorer.score_dump(dump, self.per_extension_calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "quartic")
        self.assertEqual(report["selected"]["cost_breakdown"]["sumcheck"], 2.5)

    def test_tie_breaks_by_proof_size_byte_estimate(self):
        dump = {
            "schema_version": 1,
            "candidates": [
                candidate("large", dft=1, proof_size_bytes=20),
                candidate("small", dft=1, proof_size_bytes=5),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "small")

    def test_tie_breaks_by_legacy_proof_size_score(self):
        dump = {
            "schema_version": 1,
            "candidates": [
                candidate("large", dft=1, legacy_proof_size=20),
                candidate("small", dft=1, legacy_proof_size=5),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "small")

    def test_apply_case_metrics_updates_candidates(self):
        dump = {"schema_version": 1, "candidates": [candidate("a")]}
        scorer.apply_case_metrics(dump, constraint_work=123, case_label="case")
        self.assertEqual(dump["candidates"][0]["constraint_work"], 123)
        self.assertEqual(dump["candidates"][0]["case_label"], "case")

    def test_marks_untrusted_when_validation_fails(self):
        heldout = [{"label": "bad", "measured_seconds": 10.0, "dft_work": 1}]
        dump = {"schema_version": 1, "candidates": [candidate("ok", dft=1)]}
        report = scorer.score_dump(dump, self.calibration(heldout), max_pow_bits=22)
        self.assertFalse(report["model_validation"]["trusted"])
        self.assertEqual(report["selected"]["label"], "ok")

    def test_recalibrate_updates_extension_specific_sumcheck(self):
        calibration = self.per_extension_calibration()
        row = candidate("heldout", extension="quartic", sumcheck=10)
        row["measured_seconds"] = 10.0
        add_heldout.recalibrate(calibration, [row], prior_weight=0.01)
        self.assertIn("quartic", calibration["coefficients"]["sumcheck"])
        self.assertNotEqual(calibration["coefficients"]["sumcheck"]["quartic"], 0.25)


if __name__ == "__main__":
    unittest.main()
