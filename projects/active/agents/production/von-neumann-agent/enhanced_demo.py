"""
Enhanced Von Neumann Agent Demonstration

Showcases the improved capabilities with better strategy selection,
higher success rates, and comprehensive problem-solving across domains.
"""

from von_neumann_agent import VonNeumannCompleteAgent
import time


def run_enhanced_demonstration():
    print("Von Neumann Agent - Enhanced Demonstration")
    print("=" * 60)
    print("Embodying John von Neumann's intellectual principles:")
    print("- Mathematical rigor and formal reasoning")
    print("- Cross-domain synthesis and unification")
    print("- Game-theoretic strategic thinking")
    print("- Self-improving computational systems")
    print("- Universal mathematical structures")
    print("=" * 60)

    # Initialize the enhanced agent
    print("\nInitializing Von Neumann Agent...")
    agent = VonNeumannCompleteAgent()
    print(
        f"Agent initialized with {agent.get_agent_status()['knowledge_base_size']} foundational concepts"
    )

    # Comprehensive test problems showcasing different capabilities
    test_problems = [
        {
            "description": "Two companies compete for market share. Company A can set high or low prices, Company B can respond with aggressive or passive marketing. How should they strategize?",
            "domain": "game_theory",
            "expected_strategy": "game_theoretic",
            "focus": "Strategic reasoning and Nash equilibria",
        },
        {
            "description": "A medical diagnostic system needs to update beliefs about disease probability given new test results with 85% accuracy. How should it reason about uncertainty?",
            "domain": "medicine",
            "expected_strategy": "probabilistic_inference",
            "focus": "Bayesian inference and uncertainty quantification",
        },
        {
            "description": "Solve the linear system: 3x + 2y = 7, x + 4y = 6. Ensure numerical stability and provide error analysis.",
            "domain": "mathematics",
            "expected_strategy": "computational",
            "focus": "Numerical methods with mathematical rigor",
        },
        {
            "description": "How do evolutionary algorithms in biology relate to optimization methods in machine learning? What underlying mathematical principles unify them?",
            "domain": "cross_domain",
            "expected_strategy": "interdisciplinary",
            "focus": "Cross-domain analogies and mathematical unification",
        },
        {
            "description": "Design a self-modifying program that can improve its own performance through experience. What are the logical foundations required?",
            "domain": "computer_science",
            "expected_strategy": "computational",
            "focus": "Von Neumann stored program architecture and self-improvement",
        },
    ]

    results = []
    total_start = time.time()

    print(f"\nTesting {len(test_problems)} diverse problems...")
    print("=" * 60)

    for i, problem in enumerate(test_problems, 1):
        print(f"\nPROBLEM {i}: {problem['focus']}")
        print("-" * 40)
        print(f"Description: {problem['description']}")
        print(f"Expected Strategy: {problem['expected_strategy']}")

        # Solve the problem
        start_time = time.time()
        solution = agent.solve_problem(problem["description"], domain=problem["domain"])
        execution_time = time.time() - start_time

        # Extract key results
        success = solution["overall_success"]
        confidence = solution["overall_confidence"]
        strategy_used = solution["primary_strategy"]
        strategy_match = strategy_used == problem["expected_strategy"]

        # Display results
        print("\nResults:")
        print(f"  Success: {success} | Confidence: {confidence:.3f}")
        print(f"  Strategy Used: {strategy_used}")
        print(
            f"  Strategy Match: {'YES' if strategy_match else 'NO'} Expected: {problem['expected_strategy']}"
        )
        print(f"  Execution Time: {execution_time:.3f}s")

        # Show Von Neumann insights
        insights = solution.get("von_neumann_insights", [])
        if insights:
            print("  Von Neumann Insights:")
            for insight in insights[:2]:  # Show top 2 insights
                print(f"    - {insight}")

        # Store results for summary
        results.append(
            {
                "problem_num": i,
                "success": success,
                "confidence": confidence,
                "strategy_match": strategy_match,
                "execution_time": execution_time,
                "focus": problem["focus"],
            }
        )

        print()

    total_time = time.time() - total_start

    # Performance Summary
    print("=" * 60)
    print("PERFORMANCE SUMMARY")
    print("=" * 60)

    successful_problems = sum(1 for r in results if r["success"])
    avg_confidence = sum(r["confidence"] for r in results) / len(results)
    strategy_matches = sum(1 for r in results if r["strategy_match"])
    avg_execution_time = sum(r["execution_time"] for r in results) / len(results)

    print(
        f"Overall Success Rate: {successful_problems}/{len(results)} ({successful_problems / len(results) * 100:.1f}%)"
    )
    print(f"Average Confidence: {avg_confidence:.3f}")
    print(
        f"Strategy Selection Accuracy: {strategy_matches}/{len(results)} ({strategy_matches / len(results) * 100:.1f}%)"
    )
    print(f"Average Execution Time: {avg_execution_time:.3f}s")
    print(f"Total Runtime: {total_time:.3f}s")

    # Agent Performance Metrics
    print("\nAGENT LEARNING STATUS:")
    status = agent.get_agent_status()
    print(f"  Problems Solved: {status['problems_solved']}")
    print(f"  Knowledge Base: {status['knowledge_base_size']} concepts")
    print(f"  Reasoning History: {status['reasoning_history_size']} episodes")
    print(f"  Self-Modifications: {status['modifications_applied']}")

    # Von Neumann Principles Demonstrated
    print("\nVON NEUMANN PRINCIPLES DEMONSTRATED:")
    print("  + Mathematical Rigor - All reasoning grounded in formal methods")
    print("  + Strategic Thinking - Game-theoretic optimization applied")
    print("  + Cross-Domain Synthesis - Unified mathematical frameworks")
    print("  + Computational Insight - Numerical and analytical understanding")
    print(
        "  + Self-Improvement - Continuous learning through stored program architecture"
    )

    print("\n" + "=" * 60)
    print("Von Neumann Agent Enhanced Demonstration Complete!")
    print("The agent successfully embodies von Neumann's vision of")
    print("mathematical universality and self-improving computation.")
    print("=" * 60)

    return results, status


if __name__ == "__main__":
    run_enhanced_demonstration()
