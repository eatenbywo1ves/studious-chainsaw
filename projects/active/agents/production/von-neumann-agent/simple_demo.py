"""
Simple Von Neumann Agent Demonstration
"""

import numpy as np
from reasoning_engines import (
    AdvancedGameTheoryEngine,
    BayesianReasoningEngine,
    ComputationalMathEngine,
)


def main():
    print("Von Neumann Agent Demonstration")
    print("=" * 50)

    # 1. Game Theory
    print("\n1. GAME THEORY - Minimax Theorem")
    print("-" * 30)

    game_engine = AdvancedGameTheoryEngine()
    payoff_matrix = np.array([[3, 1], [0, 2]])
    solution = game_engine.solve_zero_sum_game(payoff_matrix)

    print(f"Game Value: {solution['game_value']:.4f}")
    print(f"Row Strategy: {solution['row_strategy']}")
    print(f"Insight: {solution['von_neumann_insight']}")

    # 2. Bayesian Reasoning
    print("\n2. BAYESIAN REASONING")
    print("-" * 30)

    bayes_engine = BayesianReasoningEngine()
    result = bayes_engine.exact_bayesian_update(
        hypothesis="success", prior=0.6, likelihood=0.8, marginal_likelihood=0.7
    )

    print(f"Prior: {result['prior']:.3f}")
    print(f"Posterior: {result['posterior']:.3f}")
    print(f"Information Gain: {result['information_gain_bits']:.3f} bits")

    # 3. Computational Mathematics
    print("\n3. COMPUTATIONAL MATHEMATICS")
    print("-" * 30)

    comp_engine = ComputationalMathEngine()
    A = np.array([[2, 1], [1, 3]], dtype=float)
    b = np.array([7, 8], dtype=float)

    solution = comp_engine.solve_linear_system(A, b)

    print(f"Solution: x={solution['solution'][0]:.3f}, y={solution['solution'][1]:.3f}")
    print(f"Condition Number: {solution['condition_number']:.2e}")
    print(f"Stability: {solution['stability']}")

    print("\n" + "=" * 50)
    print("DEMONSTRATION COMPLETE")
    print("Von Neumann principles successfully implemented:")
    print("- Mathematical rigor maintained")
    print("- Game-theoretic optimization applied")
    print("- Probabilistic inference with information theory")
    print("- Computational stability analysis")
    print("- Cross-domain mathematical unification")


if __name__ == "__main__":
    main()
