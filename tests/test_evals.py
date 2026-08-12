"""
Unit tests for vcurl LLM Security Evaluation Harness (vcurl/evals.py)
"""

import unittest
from vcurl.evals import LLMEvalRunner, PROMPT_INJECTION_BENCHMARK_SUITE


class TestLLMEvals(unittest.TestCase):

    def setUp(self):
        self.runner = LLMEvalRunner()

    def test_eval_suite_structure(self):
        self.assertGreaterEqual(len(PROMPT_INJECTION_BENCHMARK_SUITE), 10)
        for test in PROMPT_INJECTION_BENCHMARK_SUITE:
            self.assertIn("id", test)
            self.assertIn("name", test)
            self.assertIn("category", test)
            self.assertIn("attack_vector", test)

    def test_run_evals_results(self):
        report = self.runner.run_evals()
        self.assertIn("summary", report)
        self.assertIn("eval_results", report)
        
        summary = report["summary"]
        self.assertEqual(summary["total_tests"], len(PROMPT_INJECTION_BENCHMARK_SUITE))
        self.assertEqual(summary["protection_score_pct"], 100.0)
        self.assertEqual(summary["failed_tests"], 0)


if __name__ == "__main__":
    unittest.main()
