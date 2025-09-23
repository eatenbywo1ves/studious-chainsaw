"""
Batch Unit Tests for Von Neumann Agent
Simple, focused tests for core functionality
"""

import unittest
from von_neumann_agent import VonNeumannCompleteAgent
from reasoning_engines import (
    AdvancedGameTheoryEngine,
    BayesianReasoningEngine,
    ComputationalMathEngine,
)
from enhanced_strategy_selector import EnhancedStrategySelector
import numpy as np


class TestBasicFunctionality(unittest.TestCase):
    """Test basic agent functionality"""

    def test_agent_initialization(self):
        """Test that agent initializes properly"""
        agent = VonNeumannCompleteAgent()
        self.assertIsNotNone(agent)
        self.assertGreater(len(agent.synthesis_engine.knowledge_base), 0)

    def test_problem_solving_success(self):
        """Test that agent can solve problems successfully"""
        agent = VonNeumannCompleteAgent()
        result = agent.solve_problem("Test problem")
        self.assertIn("overall_success", result)
        self.assertIn("overall_confidence", result)
        self.assertIsInstance(result["overall_confidence"], float)


class TestReasoningEngines(unittest.TestCase):
    """Test individual reasoning engines"""

    def test_game_theory_engine(self):
        """Test game theory engine"""
        engine = AdvancedGameTheoryEngine()
        matrix = np.array([[1, -1], [-1, 1]])
        result = engine.solve_zero_sum_game(matrix)
        self.assertIn("game_value", result)
        self.assertIn("row_strategy", result)

    def test_bayesian_engine(self):
        """Test Bayesian reasoning engine"""
        engine = BayesianReasoningEngine()
        result = engine.exact_bayesian_update("test", 0.5, 0.8, 0.7)
        self.assertIn("posterior", result)
        self.assertIn("information_gain_bits", result)

    def test_computational_engine(self):
        """Test computational mathematics engine"""
        engine = ComputationalMathEngine()
        A = np.array([[2, 1], [1, 3]], dtype=float)
        b = np.array([3, 4], dtype=float)
        result = engine.solve_linear_system(A, b)
        self.assertIn("solution", result)
        self.assertIn("condition_number", result)


class TestStrategySelection(unittest.TestCase):
    """Test enhanced strategy selection"""

    def test_strategy_selector_creation(self):
        """Test strategy selector can be created"""
        selector = EnhancedStrategySelector()
        self.assertIsNotNone(selector)

    def test_game_theory_strategy_selection(self):
        """Test game theory problems select game_theoretic strategy"""
        selector = EnhancedStrategySelector()
        problem = "Two players compete in a zero-sum game with strategies"
        strategy = selector.select_strategy(problem, {})
        self.assertEqual(strategy.value, "game_theoretic")

    def test_probabilistic_strategy_selection(self):
        """Test probabilistic problems select probabilistic_inference strategy"""
        selector = EnhancedStrategySelector()
        problem = "Calculate probability with uncertainty and random variables"
        strategy = selector.select_strategy(problem, {})
        self.assertEqual(strategy.value, "probabilistic_inference")


class TestIntegration(unittest.TestCase):
    """Test integration and end-to-end functionality"""

    def test_different_problem_types(self):
        """Test agent handles different problem types appropriately"""
        agent = VonNeumannCompleteAgent()

        problems = [
            ("Game theory: Two players optimize strategies", "game_theoretic"),
            (
                "Probability: Update beliefs with new evidence",
                "probabilistic_inference",
            ),
            ("Math: Solve linear equations", "computational"),
            ("Cross-domain: Biology relates to computer science", "interdisciplinary"),
        ]

        for desc, expected_strategy in problems:
            result = agent.solve_problem(desc)
            self.assertTrue(result["overall_success"])
            self.assertGreater(result["overall_confidence"], 0.0)

    def test_error_handling(self):
        """Test that agent handles errors gracefully"""
        agent = VonNeumannCompleteAgent()

        # Test empty input
        result = agent.solve_problem("")
        self.assertIn("overall_success", result)

        # Should not crash on edge cases
        result = agent.solve_problem("a")
        self.assertIsNotNone(result)


def run_batch_tests():
    """Run all batch tests with reporting"""

    print("Von Neumann Agent - Batch Unit Tests")
    print("=" * 50)

    # Test suites in order
    test_suites = [
        ("Basic Functionality", TestBasicFunctionality),
        ("Reasoning Engines", TestReasoningEngines),
        ("Strategy Selection", TestStrategySelection),
        ("Integration Tests", TestIntegration),
    ]

    all_results = []
    total_tests = 0
    total_failures = 0
    total_errors = 0

    for suite_name, test_class in test_suites:
        print(f"\n--- {suite_name} ---")

        # Create test suite
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)

        # Run tests
        result = unittest.TextTestRunner(verbosity=0, stream=open("nul", "w")).run(
            suite
        )

        # Collect results
        tests_run = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        passed = tests_run - failures - errors

        total_tests += tests_run
        total_failures += failures
        total_errors += errors

        print(f"Tests Run: {tests_run}")
        print(f"Passed: {passed}")
        print(f"Failed: {failures}")
        print(f"Errors: {errors}")

        if failures > 0:
            print("Failures:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")

        if errors > 0:
            print("Errors:")
            for test, traceback in result.errors:
                print(f"  - {test}: Error in execution")

        all_results.append(
            {
                "name": suite_name,
                "tests": tests_run,
                "passed": passed,
                "failed": failures,
                "errors": errors,
            }
        )

    # Overall summary
    print("\n" + "=" * 50)
    print("BATCH TEST SUMMARY")
    print("=" * 50)

    total_passed = total_tests - total_failures - total_errors
    success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failures}")
    print(f"Errors: {total_errors}")
    print(f"Success Rate: {success_rate:.1f}%")

    print("\nDetailed Results:")
    for result in all_results:
        rate = (result["passed"] / result["tests"] * 100) if result["tests"] > 0 else 0
        print(f"  {result['name']}: {result['passed']}/{result['tests']} ({rate:.0f}%)")

    print(
        "\nVon Neumann Agent Status: "
        + ("PASSING" if total_failures + total_errors == 0 else "ISSUES DETECTED")
    )

    return all_results


if __name__ == "__main__":
    run_batch_tests()
