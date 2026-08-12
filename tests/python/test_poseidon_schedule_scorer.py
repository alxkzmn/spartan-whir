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
    zk=False,
    zk_dft=None,
    zk_merkle=None,
    zk_merkle_path=None,
    zk_row=None,
    zk_sumcheck=None,
    zk_mask_queries=None,
    zk_ell=None,
    zk_mask_log_inv_rate=None,
):
    out = {
        "label": label,
        "proof_mode": "full-zk" if zk else "no-zk",
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
        "setup_config": {
            "matrix_closing": "DirectSparse",
            "label": label,
            **({"ell_zk": zk_ell, "mask_log_inv_rate": zk_mask_log_inv_rate} if zk else {}),
        }
        if valid
        else None,
    }
    if zk_dft is not None:
        out["zk_dft_work"] = zk_dft
    if zk_merkle is not None:
        out["zk_merkle_work"] = zk_merkle
    if zk_merkle_path is not None:
        out["zk_merkle_path_work"] = zk_merkle_path
    if zk_row is not None:
        out["zk_row_work"] = zk_row
    if zk_sumcheck is not None:
        out["zk_sumcheck_work"] = zk_sumcheck
    if zk_mask_queries is not None:
        out["zk_mask_queries"] = zk_mask_queries
    if zk_ell is not None:
        out["zk_ell"] = zk_ell
    if zk_mask_log_inv_rate is not None:
        out["zk_mask_log_inv_rate"] = zk_mask_log_inv_rate
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
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("bad", max_pow=23, dft=1)]}
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertIsNone(report["selected"])
        self.assertIn("exceeds max", report["scores"][0]["rejection_reasons"][-1])

    def test_selects_lowest_projected_time(self):
        dump = {
            "schema_version": 1, "proof_mode": "no-zk",
            "candidates": [
                candidate("slow", dft=10),
                candidate("fast", dft=2),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "fast")
        self.assertIn("cost_breakdown", report["selected"])

    def test_cost_breakdown_includes_merkle_path(self):
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("a", merkle_path=7)]}
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["cost_breakdown"]["merkle_path"], 7.0)

    def test_legacy_calibration_defaults_merkle_path_to_zero(self):
        calibration = self.calibration()
        del calibration["coefficients"]["merkle_path"]
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("a", merkle_path=7)]}
        report = scorer.score_dump(dump, calibration, max_pow_bits=22)
        self.assertEqual(report["selected"]["cost_breakdown"]["merkle_path"], 0.0)

    def test_uses_extension_specific_sumcheck_coefficients(self):
        dump = {
            "schema_version": 1, "proof_mode": "no-zk",
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
            "schema_version": 1, "proof_mode": "no-zk",
            "candidates": [
                candidate("large", dft=1, proof_size_bytes=20),
                candidate("small", dft=1, proof_size_bytes=5),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "small")
        self.assertEqual(report["scores"][0]["label"], "small")

    def test_tie_breaks_by_legacy_proof_size_score(self):
        dump = {
            "schema_version": 1, "proof_mode": "no-zk",
            "candidates": [
                candidate("large", dft=1, legacy_proof_size=20),
                candidate("small", dft=1, legacy_proof_size=5),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "small")

    def test_tie_breaks_by_pow_before_label_after_proof_size(self):
        dump = {
            "schema_version": 1, "proof_mode": "no-zk",
            "candidates": [
                candidate("a", dft=1, proof_size_bytes=5, max_pow=4, pow_work=16),
                candidate("b", dft=1, proof_size_bytes=5, max_pow=0, pow_work=0),
            ],
        }
        report = scorer.score_dump(dump, self.calibration(), max_pow_bits=22)
        self.assertEqual(report["selected"]["label"], "b")

    def test_apply_case_metrics_updates_candidates(self):
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("a")]}
        scorer.apply_case_metrics(dump, constraint_work=123, case_label="case")
        self.assertEqual(dump["candidates"][0]["constraint_work"], 123)
        self.assertEqual(dump["candidates"][0]["case_label"], "case")

    def test_marks_untrusted_when_validation_fails(self):
        heldout = [{"label": "bad", "measured_seconds": 10.0, "dft_work": 1}]
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("ok", dft=1)]}
        report = scorer.score_dump(dump, self.calibration(heldout), max_pow_bits=22)
        self.assertFalse(report["model_validation"]["trusted"])
        self.assertEqual(report["selected"]["label"], "ok")

    def test_validation_uses_zk_metrics_for_zk_heldout(self):
        heldout = [candidate("zk", dft=1, zk=True, zk_dft=10)]
        heldout[0]["measured_seconds"] = 10.0
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("ok", dft=1)]}
        report = scorer.score_dump(dump, self.calibration(heldout), max_pow_bits=22)
        self.assertTrue(report["model_validation"]["trusted"])
        self.assertEqual(report["model_validation"]["heldout"][0]["projected_seconds"], 10.0)

    def test_validation_reports_ordering_diagnostic(self):
        heldout = [
            {"label": "a", "measured_seconds": 1.0, "dft_work": 1},
            {"label": "b", "measured_seconds": 3.0, "dft_work": 2},
            {"label": "c", "measured_seconds": 2.0, "dft_work": 3},
        ]
        dump = {"schema_version": 1, "proof_mode": "no-zk", "candidates": [candidate("ok", dft=1)]}
        report = scorer.score_dump(dump, self.calibration(heldout), max_pow_bits=22)
        diagnostic = report["model_validation"]["ordering_diagnostic"]
        self.assertEqual(diagnostic["comparable_pairs"], 3)
        self.assertIn("kendall_tau", diagnostic)
        self.assertGreater(diagnostic["model_resolution_seconds"], 0)

    def test_measurement_shortlist_uses_margin_and_collapses_equivalent_ell(self):
        common = dict(
            dft=1,
            zk=True,
            zk_dft=1,
            zk_merkle=2,
            zk_merkle_path=3,
            zk_row=4,
            zk_sumcheck=5,
            zk_mask_queries=90,
            zk_mask_log_inv_rate=3,
        )
        dump = {
            "schema_version": 1, "proof_mode": "full-zk",
            "candidates": [
                candidate("same", proof_size_bytes=20, zk_ell=8, **common),
                candidate("same", proof_size_bytes=10, zk_ell=3, **common),
                candidate("outside", dft=100, proof_size_bytes=1),
            ],
        }
        report = scorer.score_dump(
            dump,
            self.calibration(),
            max_pow_bits=22,
            measurement_shortlist_margin_seconds=0.1,
        )
        labels = [row["label"] for row in report["measurement_shortlist"]]
        self.assertEqual(labels, ["same"])
        self.assertEqual(report["measurement_shortlist"][0]["zk_ell"], 3)
        self.assertEqual(report["measurement_shortlist_meta"]["pre_dedup_count"], 2)
        self.assertEqual(report["measurement_shortlist_meta"]["dedup_count"], 1)

    def test_selected_measured_is_separate_from_model_selected(self):
        dump = {
            "schema_version": 1, "proof_mode": "no-zk",
            "candidates": [candidate("model", dft=1), candidate("measured", dft=2)],
        }
        measurements = {
            "proof_mode": "no-zk",
            "source_report": "report.json",
            "rows": [
                {**candidate("model", dft=1), "measured_seconds": 3.0},
                {
                    **candidate("measured", dft=2),
                    "measured_seconds": 1.0,
                    "heldout_median_ci_seconds": [0.9, 1.1],
                },
            ],
        }
        report = scorer.score_dump(
            dump,
            self.calibration(),
            max_pow_bits=22,
            measurements=measurements,
        )
        self.assertEqual(report["selected"]["label"], "model")
        self.assertEqual(report["selected_measured"]["label"], "measured")
        self.assertEqual(report["measurement_summary"]["selection"], "measured_argmin")

    def test_recalibrate_updates_extension_specific_sumcheck(self):
        calibration = self.per_extension_calibration()
        row = candidate("heldout", extension="quartic", sumcheck=10)
        row["measured_seconds"] = 10.0
        add_heldout.recalibrate(calibration, [row], prior_weight=0.01)
        self.assertIn("quartic", calibration["coefficients"]["sumcheck"])
        self.assertNotEqual(calibration["coefficients"]["sumcheck"]["quartic"], 0.25)

    def test_recalibrate_uses_zk_metrics_for_zk_heldout(self):
        calibration = self.calibration()
        row = candidate("zk", dft=1, zk=True, zk_dft=10)
        row["measured_seconds"] = 10.0
        add_heldout.recalibrate(calibration, [row], prior_weight=0.0)
        self.assertAlmostEqual(calibration["coefficients"]["dft"], 1.0)

    def test_zk_candidate_generation_sweeps_default_zk_knobs(self):
        calls = []

        def fake_generate_candidate_dump(
            cargo,
            num_variables,
            max_pow_bits,
            field,
            proof_mode,
            zk_ell,
            zk_mask_log_inv_rate,
        ):
            calls.append((zk_ell, zk_mask_log_inv_rate))
            return {
                "schema_version": 2,
                "proof_mode": proof_mode,
                "zk_ell": zk_ell,
                "zk_mask_log_inv_rate": zk_mask_log_inv_rate,
                "candidates": [{"label": f"ell{zk_ell}_mask{zk_mask_log_inv_rate}"}],
            }

        old_generate_candidate_dump = scorer.generate_candidate_dump
        try:
            scorer.generate_candidate_dump = fake_generate_candidate_dump
            dump = scorer.generate_candidates(
                "cargo",
                20,
                22,
                "koalabear",
                "full-zk",
                None,
                None,
            )
        finally:
            scorer.generate_candidate_dump = old_generate_candidate_dump

        expected = [
            (ell, mask)
            for ell in scorer.DEFAULT_ZK_ELL_SWEEP
            for mask in scorer.DEFAULT_ZK_MASK_LOG_INV_RATE_SWEEP
        ]
        self.assertEqual(calls, expected)
        self.assertEqual(dump["zk_ell_sweep"], scorer.DEFAULT_ZK_ELL_SWEEP)
        self.assertEqual(
            dump["zk_mask_log_inv_rate_sweep"],
            scorer.DEFAULT_ZK_MASK_LOG_INV_RATE_SWEEP,
        )


if __name__ == "__main__":
    unittest.main()
