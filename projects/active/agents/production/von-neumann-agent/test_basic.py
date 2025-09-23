"""
Basic test for Von Neumann Agent without Unicode issues
"""

from von_neumann_agent import VonNeumannCompleteAgent
import time


def test_basic_functionality():
    print("Von Neumann Agent Basic Test")
    print("=" * 40)

    # Initialize agent
    agent = VonNeumannCompleteAgent()

    # Test simple problem
    problem = "Two players in a zero-sum game need to find optimal strategies"

    print(f"Problem: {problem}")
    print("Solving...")

    start_time = time.time()
    solution = agent.solve_problem(problem, domain="game_theory")
    end_time = time.time()

    print(f"Success: {solution['overall_success']}")
    print(f"Confidence: {solution['overall_confidence']:.3f}")
    print(f"Primary Strategy: {solution['primary_strategy']}")
    print(f"Execution Time: {end_time - start_time:.2f}s")

    print("\nVon Neumann Insights:")
    for insight in solution.get("von_neumann_insights", [])[:3]:
        print(f"- {insight}")

    # Get agent status
    status = agent.get_agent_status()
    print("\nAgent Status:")
    print(f"Problems Solved: {status['problems_solved']}")
    print(f"Knowledge Base Size: {status['knowledge_base_size']}")

    print("\nBasic functionality test completed successfully!")
    return solution


if __name__ == "__main__":
    test_basic_functionality()
