"""
Validation test suite for all committed benchmark test cases.
Verifies integrity, schema adherence, and expected ground-truth baseline verdicts.
"""

import json
import unittest
from pathlib import Path

from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase
from oracle.verdict import VerdictStatus


class TestBenchmarkCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.cases_dir = cls.repo_root / "cases"
        cls.oracle = DeterministicOracle()
        cls.case_dirs = [p for p in sorted(cls.cases_dir.iterdir()) if p.is_dir()]

    def test_cases_exist(self):
        # Deliberately not a fixed count. Cases are added over time; the
        # invariants that matter are asserted per case by the tests below.
        self.assertGreaterEqual(len(self.case_dirs), 1, "No benchmark cases found")

    def test_case_file_structure(self):
        required_files = ["policy.json", "must_deny.json", "must_allow.json", "NOTES.md", "reference_remediation.json"]
        for case_dir in self.case_dirs:
            for req in required_files:
                target = case_dir / req
                self.assertTrue(target.exists(), f"Case {case_dir.name} missing required file {req}")
                self.assertGreater(target.stat().st_size, 0, f"File {target} is empty")

    def test_notes_contain_ground_truth_citations(self):
        for case_dir in self.case_dirs:
            notes = (case_dir / "NOTES.md").read_text(encoding="utf-8")
            self.assertIn("Escalation Vector", notes)
            self.assertIn("Legitimate Workload Purpose", notes)
            self.assertIn("Ground Truth Citation", notes)

    def test_all_initial_policies_are_unsafe(self):
        """Confirms that every initial policy genuinely triggers an UNSAFE verdict."""
        for case_dir in self.case_dirs:
            case = TestCase.load_from_dir(case_dir)
            res = self.oracle.evaluate(case.initial_policy, case)
            self.assertEqual(
                res.verdict,
                VerdictStatus.UNSAFE,
                f"Initial policy for {case.case_id} failed to trigger UNSAFE verdict!"
            )
            self.assertFalse(res.is_safe)
            self.assertTrue(res.is_intact, f"Initial policy for {case.case_id} unexpectedly broke must_allow")
            self.assertGreater(len(res.unsafe_violations), 0)

    def test_all_reference_remediations_are_correct(self):
        """Confirms that every reference remediation achieves 100% CORRECT verdict."""
        for case_dir in self.case_dirs:
            case = TestCase.load_from_dir(case_dir)
            with open(case_dir / "reference_remediation.json") as f:
                ref_policy = json.load(f)
            res = self.oracle.evaluate(ref_policy, case)
            self.assertEqual(
                res.verdict,
                VerdictStatus.CORRECT,
                f"Reference remediation for {case.case_id} was not CORRECT. "
                f"Violations: unsafe={len(res.unsafe_violations)}, broken={len(res.broken_violations)}"
            )
            self.assertTrue(res.is_safe)
            self.assertTrue(res.is_intact)


if __name__ == "__main__":
    unittest.main()
