"""
Mutation test suite.
Asserts that the evaluation test suite kills 100% of injected engine mutants.
"""

import unittest
from pathlib import Path
from mutation.runner import run_mutation_suite


class TestOracleMutations(unittest.TestCase):
    def test_all_oracle_mutants_are_killed(self):
        repo_root = Path(__file__).resolve().parent.parent
        results = run_mutation_suite(repo_root)

        survived = [r for r in results if not r.killed]
        if survived:
            msg = f"The following {len(survived)} mutants survived:\n" + "\n".join(
                f"- {r.mutant_id}: {r.description}" for r in survived
            )
            self.fail(msg)

        self.assertEqual(len(survived), 0)
        killed_count = sum(1 for r in results if r.killed)
        self.assertEqual(killed_count, len(results))


if __name__ == "__main__":
    unittest.main()
