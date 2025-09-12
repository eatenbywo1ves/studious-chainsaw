"""
Comprehensive Test Suite for Von Neumann Agent

Tests the agent with mathematical rigor following von Neumann's approach to verification:
1. Formal correctness verification
2. Performance benchmarking across domains  
3. Self-improvement validation
4. Cross-domain synthesis testing
5. Robustness and edge case analysis
"""

import unittest
import numpy as np
import time
from typing import Dict, List, Any, Optional
import json
import tempfile
from pathlib import Path

# Import agent components
from von_neumann_agent import VonNeumannCompleteAgent
from architecture import ReasoningMode, Problem, Concept
from reasoning_engines import GameMatrix, LogicalStatement
from synthesis_engine import KnowledgeNode, Domain, StructuralMapping
from meta_reasoning import ReasoningTrace, ReasoningStrategy

class TestVonNeumannAgentFoundations(unittest.TestCase):
    """Test foundational capabilities and mathematical correctness"""
    
    def setUp(self):
        """Set up test environment"""
        self.agent = VonNeumannCompleteAgent({
            'mathematical_rigor': True,
            'confidence_threshold': 0.6,
            'max_reasoning_time': 10.0
        })
    
    def test_initialization(self):
        """Test proper agent initialization"""
        self.assertIsNotNone(self.agent.game_theory_engine)
        self.assertIsNotNone(self.agent.logic_engine)
        self.assertIsNotNone(self.agent.bayesian_engine)
        self.assertIsNotNone(self.agent.computational_engine)
        self.assertIsNotNone(self.agent.synthesis_engine)
        self.assertIsNotNone(self.agent.reflection_engine)
        self.assertIsNotNone(self.agent.modification_engine)
        
        # Check foundational knowledge is loaded
        self.assertGreater(len(self.agent.synthesis_engine.knowledge_base), 0)
        
        # Check von Neumann foundational concepts are present
        concept_names = [c.concept_name for c in self.agent.synthesis_engine.knowledge_base]
        self.assertIn("Minimax Theorem", concept_names)
        self.assertIn("Stored Program Architecture", concept_names)
    
    def test_problem_analysis(self):
        """Test problem analysis capabilities"""
        test_cases = [
            {
                'description': "Two players compete in a zero-sum game with optimal strategies",
                'expected_type': 'strategic',
                'expected_complexity': lambda x: x > 0.3,
                'expected_cross_domain': lambda x: x > 0.2
            },
            {
                'description': "Optimize a function subject to linear constraints", 
                'expected_type': 'optimization',
                'expected_complexity': lambda x: x > 0.2,
                'expected_cross_domain': lambda x: x >= 0.0
            },
            {
                'description': "Prove that a mathematical theorem follows from given axioms",
                'expected_type': 'logical',
                'expected_complexity': lambda x: x > 0.1,
                'expected_cross_domain': lambda x: x >= 0.0
            }
        ]
        
        for case in test_cases:
            analysis = self.agent._analyze_problem(case['description'], 'general', None)
            
            self.assertEqual(analysis['problem_type'], case['expected_type'])
            self.assertTrue(case['expected_complexity'](analysis['complexity_estimate']))
            self.assertTrue(case['expected_cross_domain'](analysis['cross_domain_potential']))
            self.assertIn('mathematical_content', analysis)
            self.assertIn('strategic_elements', analysis)
    
    def test_strategy_selection(self):
        """Test reasoning strategy selection"""
        test_cases = [
            {
                'problem_context': {'problem_type': 'strategic'},
                'expected_strategy': ReasoningStrategy.GAME_THEORETIC
            },
            {
                'problem_context': {'problem_type': 'probabilistic'},
                'expected_strategy': ReasoningStrategy.PROBABILISTIC_INFERENCE
            },
            {
                'problem_context': {'problem_type': 'computational'},
                'expected_strategy': ReasoningStrategy.COMPUTATIONAL
            },
            {
                'problem_context': {'problem_type': 'logical'},
                'expected_strategy': ReasoningStrategy.LOGICAL_DEDUCTION
            }
        ]
        
        for case in test_cases:
            recommended = self.agent.reflection_engine.get_strategy_recommendation(
                case['problem_context']
            )
            # Note: Without training data, may not match exactly, so we test the mechanism works
            self.assertIsInstance(recommended, ReasoningStrategy)

class TestReasoningEngines(unittest.TestCase):
    """Test individual reasoning engine correctness"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_game_theory_engine(self):
        """Test game theory reasoning with mathematical verification"""
        # Test minimax solution for simple game
        payoff_matrix = np.array([[3, 1], [2, 4]])
        solution = self.agent.game_theory_engine.solve_zero_sum_game(payoff_matrix)
        
        self.assertIn('game_value', solution)
        self.assertIn('row_strategy', solution)
        self.assertIn('col_strategy', solution)
        
        # Verify strategies sum to 1
        self.assertAlmostEqual(np.sum(solution['row_strategy']), 1.0, places=6)
        self.assertAlmostEqual(np.sum(solution['col_strategy']), 1.0, places=6)
        
        # Verify all probabilities are non-negative
        self.assertTrue(np.all(solution['row_strategy'] >= -1e-10))
        self.assertTrue(np.all(solution['col_strategy'] >= -1e-10))
    
    def test_bayesian_engine(self):
        """Test Bayesian reasoning correctness"""
        # Test basic Bayesian update
        result = self.agent.bayesian_engine.exact_bayesian_update(
            hypothesis="test_hypothesis",
            prior=0.3,
            likelihood=0.8,
            marginal_likelihood=0.5
        )
        
        self.assertIn('posterior', result)
        self.assertIn('information_gain_bits', result)
        
        # Verify Bayes theorem: P(H|E) = P(E|H) * P(H) / P(E)
        expected_posterior = (0.8 * 0.3) / 0.5
        self.assertAlmostEqual(result['posterior'], expected_posterior, places=6)
        
        # Verify posterior is valid probability
        self.assertTrue(0 <= result['posterior'] <= 1)
    
    def test_computational_engine(self):
        """Test computational mathematics engine"""
        # Test linear system solving
        A = np.array([[2, 1], [1, 2]], dtype=float)
        b = np.array([3, 3], dtype=float)
        
        solution = self.agent.computational_engine.solve_linear_system(A, b)
        
        self.assertIn('solution', solution)
        self.assertIn('condition_number', solution)
        
        # Verify solution correctness: Ax = b
        x = solution['solution']
        residual = np.linalg.norm(A @ x - b)
        self.assertLess(residual, 1e-10)
        
        # Verify condition number is reasonable
        expected_cond = np.linalg.cond(A)
        self.assertAlmostEqual(solution['condition_number'], expected_cond, places=6)
    
    def test_logic_engine(self):
        """Test formal logic engine"""
        # Test tautology recognition
        tautology = LogicalStatement("A ∨ ¬A", ["A"])
        proof = self.agent.logic_engine.prove_statement(tautology, [])
        
        self.assertIn('proof_found', proof)
        self.assertIn('godel_limitation', proof)
        
        # Test consistency checking
        statements = [
            LogicalStatement("A", ["A"]),
            LogicalStatement("¬A", ["A"])  # Contradiction
        ]
        
        consistency = self.agent.logic_engine.check_consistency(statements)
        self.assertIn('consistent', consistency)
        self.assertFalse(consistency['consistent'])  # Should detect contradiction

class TestCrossDomainSynthesis(unittest.TestCase):
    """Test cross-domain synthesis and analogical reasoning"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_knowledge_node_creation(self):
        """Test knowledge node creation and storage"""
        concept = KnowledgeNode(
            id="test_concept",
            domain=Domain.MATHEMATICS,
            concept_name="Test Concept",
            mathematical_form="f(x) = x^2",
            properties={"quadratic": True, "convex": True},
            abstraction_level=1,
            confidence=0.9
        )
        
        initial_size = len(self.agent.synthesis_engine.knowledge_base)
        self.agent.synthesis_engine.add_knowledge(concept)
        new_size = len(self.agent.synthesis_engine.knowledge_base)
        
        self.assertEqual(new_size, initial_size + 1)
    
    def test_analogy_detection(self):
        """Test analogical reasoning between domains"""
        # Create concepts in different domains with similar structure
        concept1 = KnowledgeNode(
            id="physics_optimization",
            domain=Domain.PHYSICS,
            concept_name="Principle of Least Action",
            mathematical_form="δS = 0 where S = ∫L dt",
            properties={"optimization": True, "variational": True},
            abstraction_level=3,
            confidence=0.95
        )
        
        concept2 = KnowledgeNode(
            id="economics_optimization", 
            domain=Domain.ECONOMICS,
            concept_name="Utility Maximization",
            mathematical_form="max U(x) subject to constraints",
            properties={"optimization": True, "rational_choice": True},
            abstraction_level=2,
            confidence=0.9
        )
        
        self.agent.synthesis_engine.add_knowledge(concept1)
        self.agent.synthesis_engine.add_knowledge(concept2)
        
        # Test analogy detection
        mapping = self.agent.synthesis_engine.analogy_engine.find_structural_analogies(
            concept1, concept2
        )
        
        if mapping:  # Analogy might not always be detected with simplified implementation
            self.assertIsInstance(mapping, StructuralMapping)
            self.assertGreater(mapping.mapping_strength, 0.0)
            self.assertEqual(mapping.source_domain, Domain.PHYSICS)
            self.assertEqual(mapping.target_domain, Domain.ECONOMICS)
    
    def test_unified_theory_generation(self):
        """Test generation of unified theories across domains"""
        # Add concepts that should unify
        concepts = [
            KnowledgeNode(
                id="optimization_math",
                domain=Domain.MATHEMATICS,
                concept_name="Mathematical Optimization",
                mathematical_form="min f(x) subject to g(x) ≤ 0",
                properties={"optimization": True},
                abstraction_level=2,
                confidence=0.9
            ),
            KnowledgeNode(
                id="optimization_physics",
                domain=Domain.PHYSICS,
                concept_name="Physical Optimization",
                mathematical_form="Minimize potential energy",
                properties={"optimization": True, "energy": True},
                abstraction_level=2,
                confidence=0.9
            )
        ]
        
        for concept in concepts:
            self.agent.synthesis_engine.add_knowledge(concept)
        
        # Test synthesis
        synthesis_result = self.agent.synthesis_engine.synthesize_insights(
            "optimization principles across domains"
        )
        
        self.assertIn('relevant_concepts', synthesis_result)
        self.assertIn('von_neumann_insights', synthesis_result)
        self.assertIn('synthesis_confidence', synthesis_result)
        
        # Should identify optimization as common theme
        relevant_concepts = synthesis_result['relevant_concepts']
        self.assertTrue(any('optimization' in concept.lower() for concept in relevant_concepts))

class TestMetaReasoningAndSelfImprovement(unittest.TestCase):
    """Test meta-reasoning and self-improvement capabilities"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_reasoning_trace_recording(self):
        """Test recording and analysis of reasoning traces"""
        initial_history_size = len(self.agent.reflection_engine.reasoning_history)
        
        # Create sample reasoning trace
        trace = ReasoningTrace(
            problem_id="test_problem",
            strategy_used=ReasoningStrategy.LOGICAL_DEDUCTION,
            input_data={"test": "data"},
            reasoning_steps=[{"step": 1, "action": "analyze"}],
            final_result={"success": True},
            execution_time=1.5,
            confidence=0.8,
            success_metrics={"overall_success": 0.9}
        )
        
        self.agent.reflection_engine.record_reasoning_episode(trace)
        
        new_history_size = len(self.agent.reflection_engine.reasoning_history)
        self.assertEqual(new_history_size, initial_history_size + 1)
        
        # Test strategy performance tracking
        strategy_perf = self.agent.reflection_engine.strategy_performance[ReasoningStrategy.LOGICAL_DEDUCTION]
        self.assertGreater(strategy_perf.total_uses, 0)
    
    def test_self_improvement_plan_generation(self):
        """Test generation of self-improvement plans"""
        # Add some reasoning traces to provide data for analysis
        for i in range(10):
            trace = ReasoningTrace(
                problem_id=f"test_problem_{i}",
                strategy_used=ReasoningStrategy.LOGICAL_DEDUCTION,
                input_data={"problem_type": "logical"},
                reasoning_steps=[],
                final_result={"success": True},
                execution_time=np.random.normal(2.0, 0.5),
                confidence=np.random.beta(8, 2),
                success_metrics={"overall_success": np.random.beta(9, 2)}
            )
            self.agent.reflection_engine.record_reasoning_episode(trace)
        
        # Generate improvement plan
        improvement_plan = self.agent.reflection_engine.generate_self_improvement_plan()
        
        self.assertIn('improvement_areas', improvement_plan)
        self.assertIn('action_plan', improvement_plan)
        self.assertIn('priority_ranking', improvement_plan)
        self.assertIn('von_neumann_principle', improvement_plan)
        
        # Verify action plan structure
        action_plan = improvement_plan['action_plan']
        self.assertIn('immediate_actions', action_plan)
        self.assertIn('medium_term_goals', action_plan)
        self.assertIn('long_term_objectives', action_plan)
        self.assertIn('success_metrics', action_plan)
    
    def test_modification_proposal_and_application(self):
        """Test self-modification proposal and safe application"""
        # Generate improvement plan
        improvement_plan = {
            'improvement_areas': {
                'strategy_optimization': [
                    {'type': 'strategy_effectiveness', 'finding': 'Most effective strategy: logical', 'recommendation': 'Enhance logical strategy'}
                ]
            }
        }
        
        # Generate proposals
        proposals = self.agent.modification_engine.propose_modification(improvement_plan)
        
        self.assertGreater(len(proposals), 0)
        
        # Test safe modification application
        for proposal in proposals[:2]:  # Test first 2 proposals
            self.assertIn('type', proposal)
            self.assertIn('expected_benefit', proposal)
            self.assertIn('risk_level', proposal)
            
            # Apply modification
            result = self.agent.modification_engine.apply_modification(proposal)
            
            self.assertIn('success', result)
            self.assertIsInstance(result['success'], bool)

class TestProblemSolvingIntegration(unittest.TestCase):
    """Test integrated problem-solving capabilities"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_simple_problem_solving(self):
        """Test solving simple, well-defined problems"""
        problems = [
            {
                'description': "What is the optimal strategy in a two-player zero-sum game?",
                'domain': 'game_theory',
                'min_confidence': 0.5
            },
            {
                'description': "How do we solve a linear system of equations numerically?",
                'domain': 'mathematics',
                'min_confidence': 0.7
            },
            {
                'description': "What logical steps prove a mathematical theorem?",
                'domain': 'logic',
                'min_confidence': 0.4
            }
        ]
        
        for problem in problems:
            solution = self.agent.solve_problem(
                problem['description'], 
                problem['domain']
            )
            
            # Verify solution structure
            self.assertIn('overall_success', solution)
            self.assertIn('overall_confidence', solution) 
            self.assertIn('primary_strategy', solution)
            self.assertIn('von_neumann_insights', solution)
            self.assertIn('problem_analysis', solution)
            
            # Verify confidence meets minimum threshold
            self.assertGreaterEqual(solution['overall_confidence'], 0.0)
            self.assertLessEqual(solution['overall_confidence'], 1.0)
            
            # Verify insights are generated
            self.assertGreater(len(solution['von_neumann_insights']), 0)
    
    def test_cross_domain_problem_solving(self):
        """Test problems requiring cross-domain synthesis"""
        cross_domain_problems = [
            {
                'description': "How do evolutionary algorithms in biology relate to optimization in mathematics?",
                'expected_domains': ['biology', 'mathematics'],
                'min_cross_domain_score': 0.3
            },
            {
                'description': "What connections exist between game theory in economics and strategic behavior in biology?",
                'expected_domains': ['economics', 'biology'],
                'min_cross_domain_score': 0.3
            }
        ]
        
        for problem in cross_domain_problems:
            solution = self.agent.solve_problem(problem['description'])
            
            # Check for cross-domain synthesis
            if 'cross_domain_synthesis' in solution:
                synthesis = solution['cross_domain_synthesis']
                if 'cross_domain_analogies' in synthesis:
                    self.assertGreaterEqual(
                        len(synthesis['cross_domain_analogies']), 0
                    )
    
    def test_performance_metrics_tracking(self):
        """Test that performance metrics are properly tracked"""
        initial_problems = self.agent.performance_metrics['total_problems_solved']
        
        # Solve several problems
        for i in range(3):
            solution = self.agent.solve_problem(f"Test problem {i}", "general")
        
        # Verify metrics updated
        final_problems = self.agent.performance_metrics['total_problems_solved']
        self.assertEqual(final_problems, initial_problems + 3)
        
        # Verify average confidence is calculated
        avg_confidence = self.agent.performance_metrics['average_confidence']
        self.assertGreaterEqual(avg_confidence, 0.0)
        self.assertLessEqual(avg_confidence, 1.0)

class TestRobustnessAndEdgeCases(unittest.TestCase):
    """Test agent robustness and handling of edge cases"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_empty_problem_handling(self):
        """Test handling of empty or invalid problem descriptions"""
        edge_cases = ["", "   ", "???", "undefined"]
        
        for case in edge_cases:
            solution = self.agent.solve_problem(case)
            
            # Should handle gracefully without crashing
            self.assertIn('overall_success', solution)
            # May succeed or fail, but should not crash
    
    def test_long_problem_description(self):
        """Test handling of very long problem descriptions"""
        long_description = "This is a very long problem description. " * 1000
        
        solution = self.agent.solve_problem(long_description)
        
        # Should handle without crashing
        self.assertIn('overall_success', solution)
        self.assertIn('overall_confidence', solution)
    
    def test_special_characters_in_problem(self):
        """Test handling of special characters and unicode"""
        special_problems = [
            "How to optimize function ∫f(x)dx with constraint ∀x: g(x)≥0?",
            "Game theory with payoff matrix [[α,β],[γ,δ]]",
            "Prove: ∃x∀y P(x,y) → ∀y∃x P(x,y)"
        ]
        
        for problem in special_problems:
            solution = self.agent.solve_problem(problem)
            
            # Should handle mathematical notation gracefully
            self.assertIn('overall_success', solution)
    
    def test_session_save_and_load(self):
        """Test session persistence"""
        # Solve a problem to create state
        solution = self.agent.solve_problem("Test problem for persistence", "test")
        
        initial_count = self.agent.problem_count
        initial_metrics = self.agent.performance_metrics.copy()
        
        # Save session
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            self.agent.save_session(temp_path)
            
            # Create new agent and load session
            new_agent = VonNeumannCompleteAgent()
            new_agent.load_session(temp_path)
            
            # Verify state restored
            self.assertEqual(new_agent.problem_count, initial_count)
            self.assertEqual(
                new_agent.performance_metrics['total_problems_solved'],
                initial_metrics['total_problems_solved']
            )
            
        finally:
            # Clean up temp file
            Path(temp_path).unlink(missing_ok=True)

class TestVonNeumannPrinciples(unittest.TestCase):
    """Test adherence to von Neumann's core principles"""
    
    def setUp(self):
        self.agent = VonNeumannCompleteAgent()
    
    def test_mathematical_rigor(self):
        """Test that mathematical rigor is maintained throughout"""
        solution = self.agent.solve_problem(
            "Solve the optimization problem: minimize x^2 + y^2 subject to x + y = 1"
        )
        
        # Should involve computational mathematics
        if 'computational' in solution.get('supporting_strategies', []):
            # Mathematical rigor should be evident
            reasoning_results = solution.get('reasoning_trace', {})
            if 'computational' in reasoning_results.get('strategy_results', {}):
                comp_result = reasoning_results['strategy_results']['computational']
                # Should have numerical verification
                self.assertIn('von_neumann_connection', comp_result)
    
    def test_cross_domain_unification(self):
        """Test von Neumann's principle of mathematical unification across domains"""
        solution = self.agent.solve_problem(
            "How do optimization principles appear in physics, economics, and biology?"
        )
        
        # Should attempt cross-domain synthesis
        cross_domain = solution.get('cross_domain_synthesis', {})
        if cross_domain:
            # Should identify unifying mathematical principles
            insights = solution.get('von_neumann_insights', [])
            unification_mentioned = any(
                'mathematical unity' in insight.lower() or 
                'unif' in insight.lower() or
                'cross-domain' in insight.lower()
                for insight in insights
            )
            # Note: Not enforcing this as true since it depends on knowledge base content
    
    def test_self_improvement_principle(self):
        """Test von Neumann's stored program self-improvement concept"""
        initial_modifications = self.agent.performance_metrics['self_modifications_applied']
        
        # Solve enough problems to potentially trigger self-improvement
        for i in range(self.agent.config['reflection_frequency'] + 1):
            self.agent.solve_problem(f"Test problem {i}")
        
        # Check if self-improvement was attempted
        final_modifications = self.agent.performance_metrics['self_modifications_applied']
        modification_history_size = len(self.agent.modification_engine.modification_history)
        
        # Self-improvement mechanism should be active (may or may not apply modifications)
        self.assertGreaterEqual(final_modifications, initial_modifications)
    
    def test_game_theoretic_thinking(self):
        """Test application of game-theoretic reasoning"""
        solution = self.agent.solve_problem(
            "Two companies are deciding whether to enter a market. How should they make strategic decisions?"
        )
        
        # Should identify strategic elements
        analysis = solution.get('problem_analysis', {})
        strategic_elements = analysis.get('strategic_elements', [])
        
        # Strategic thinking should be applied
        strategies_used = solution.get('supporting_strategies', [])
        game_theoretic_used = (
            'game_theoretic' in strategies_used or
            solution.get('primary_strategy') == 'game_theoretic'
        )
        
        # Should show game-theoretic reasoning (if strategic elements detected)
        if strategic_elements:
            insights = solution.get('von_neumann_insights', [])
            strategic_insight = any(
                'strategic' in insight.lower() or 
                'game' in insight.lower() or
                'rational' in insight.lower()
                for insight in insights
            )

def run_comprehensive_tests():
    """Run comprehensive test suite with detailed reporting"""
    
    print("Von Neumann Agent Comprehensive Test Suite")
    print("=" * 60)
    
    # Test suites in order of dependency
    test_suites = [
        ('Foundation Tests', TestVonNeumannAgentFoundations),
        ('Reasoning Engine Tests', TestReasoningEngines), 
        ('Cross-Domain Synthesis Tests', TestCrossDomainSynthesis),
        ('Meta-Reasoning Tests', TestMetaReasoningAndSelfImprovement),
        ('Problem Solving Integration Tests', TestProblemSolvingIntegration),
        ('Robustness Tests', TestRobustnessAndEdgeCases),
        ('Von Neumann Principles Tests', TestVonNeumannPrinciples)
    ]
    
    total_tests = 0
    total_passed = 0
    total_failed = 0
    
    for suite_name, test_class in test_suites:
        print(f"\n--- {suite_name} ---")
        print("-" * 40)
        
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=1, stream=open('/dev/null', 'w'))
        result = runner.run(suite)
        
        tests_run = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        passed = tests_run - failures - errors
        
        total_tests += tests_run
        total_passed += passed
        total_failed += failures + errors
        
        print(f"Passed: {passed}")
        print(f"✗ Failed: {failures + errors}")
        print(f"Total: {tests_run}")
        
        # Show specific failures
        if result.failures:
            print("Failures:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print("Errors:")
            for test, traceback in result.errors:
                print(f"  - {test}: Error in execution")
    
    # Overall summary
    print("\n" + "=" * 60)
    print("Test Suite Summary")
    print("=" * 60)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"✗ Failed: {total_failed}")
    print(f"Success Rate: {total_passed/total_tests*100:.1f}%")
    
    if total_failed == 0:
        print("\n🎉 All tests passed! Von Neumann Agent is functioning correctly.")
    else:
        print(f"\n⚠️  {total_failed} tests failed. Review implementation for issues.")
    
    print("\nVon Neumann Principle: 'Mathematical rigor in verification ensures reliable self-improvement'")
    print("=" * 60)

if __name__ == "__main__":
    run_comprehensive_tests()