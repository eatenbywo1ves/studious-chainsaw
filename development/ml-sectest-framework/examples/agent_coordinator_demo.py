"""
Agent Coordinator Demonstration
================================
Example demonstrating Von Neumann game-theoretic agent selection
and Teller fusion chain coordination.

This example shows:
1. Synergy matrix initialization
2. Nash optimal agent sequence selection
3. Coordinated multi-agent attack execution
4. Cascade amplification measurement
5. Bayesian confidence learning
"""

from core import (
    AgentCoordinator,
    CoordinationStrategy,
    AgentContext
)

# Import existing agents
from agents.prompt_injection_agent import PromptInjectionAgent
from agents.model_extraction_agent import ModelExtractionAgent
from agents.data_poisoning_agent import DataPoisoningAgent
from agents.model_inversion_agent import ModelInversionAgent
from agents.adversarial_attack_agent import AdversarialAttackAgent
from agents.model_serialization_agent import ModelSerializationAgent
from agents.edward_teller_agent import EdwardTellerAgent


def main():
    """Demonstrate Agent Coordinator capabilities."""

    print("=" * 80)
    print("Agent Coordinator Demonstration")
    print("Von Neumann Game-Theoretic Selection + Teller Fusion Chain Coordination")
    print("=" * 80)
    print()

    # ========================================================================
    # Step 1: Initialize Agents
    # ========================================================================
    print("[Step 1] Initializing Security Agents...")
    agents = [
        PromptInjectionAgent(),
        ModelExtractionAgent(),
        DataPoisoningAgent(),
        ModelInversionAgent(),
        AdversarialAttackAgent(),
        ModelSerializationAgent(),
        EdwardTellerAgent()
    ]
    print(f"  Registered {len(agents)} agents")
    print()

    # ========================================================================
    # Step 2: Create Agent Coordinator
    # ========================================================================
    print("[Step 2] Creating Agent Coordinator...")
    coordinator = AgentCoordinator(agents=agents)
    print(f"  Initialized with {len(coordinator.synergy_matrix)} synergistic pairs")
    print()

    # ========================================================================
    # Step 3: Display Synergy Matrix
    # ========================================================================
    print("[Step 3] Synergy Matrix Analysis")
    print("-" * 80)
    report = coordinator.get_synergy_report()

    print(f"Total Agents: {report['total_agents']}")
    print(f"Total Synergies: {report['total_synergies']}")
    print()

    print("Top Synergistic Agent Pairs:")
    sorted_pairs = sorted(
        report['synergy_pairs'],
        key=lambda x: x['amplification'],
        reverse=True
    )

    for i, pair in enumerate(sorted_pairs[:5], 1):
        print(f"  {i}. {pair['agent1']} → {pair['agent2']}")
        print(f"     Amplification: {pair['amplification']}×")
        print(f"     Description: {pair['description']}")
        print()

    # ========================================================================
    # Step 4: Compare Coordination Strategies
    # ========================================================================
    print("[Step 4] Comparing Coordination Strategies")
    print("-" * 80)

    strategies = [
        CoordinationStrategy.SEQUENTIAL,
        CoordinationStrategy.NASH_OPTIMAL,
        CoordinationStrategy.FUSION_CHAIN
    ]

    for strategy in strategies:
        plan = coordinator.create_fusion_chain_plan(strategy)

        print(f"\nStrategy: {strategy.value.upper()}")
        print(f"  Agent Sequence: {' → '.join(plan.agent_sequence)}")
        print(f"  Expected Amplification: {plan.expected_amplification:.2f}×")
        print(f"  Confidence: {plan.confidence:.2f}")
        print(f"  Synergy Chains: {len(plan.synergy_chains)}")

        if plan.synergy_chains:
            print("  Activated Synergies:")
            for agent1_id, agent2_id in plan.synergy_chains:
                agent1 = coordinator.agents[agent1_id]
                agent2 = coordinator.agents[agent2_id]
                vuln1 = agent1._get_vulnerability_type()
                vuln2 = agent2._get_vulnerability_type()
                synergy = coordinator.get_synergy(vuln1, vuln2)
                if synergy:
                    print(f"    - {vuln1.value} → {vuln2.value} ({synergy.amplification_factor}×)")

    print()

    # ========================================================================
    # Step 5: Execute Coordinated Attack
    # ========================================================================
    print("[Step 5] Executing Coordinated Attack")
    print("-" * 80)

    # Create target context
    context = AgentContext(
        target_url="http://localhost:8000/api/vulnerable-model",
        challenge_name="Multi-Agent Fusion Attack Demo",
        difficulty_level="hard",
        owasp_reference="LLM01,LLM02,LLM03",
        mitre_reference="T1234"
    )

    print(f"Target: {context.target_url}")
    print(f"Challenge: {context.challenge_name}")
    print()

    # Execute with Nash optimal strategy
    print("Executing Nash Optimal Coordination...")
    result = coordinator.execute_coordinated_attack(
        context,
        plan=None  # Auto-generate optimal plan
    )

    print()
    print("Execution Results:")
    print(f"  Strategy Used: {result.plan.strategy.value}")
    print(f"  Expected Amplification: {result.plan.expected_amplification:.2f}×")
    print(f"  Observed Amplification: {result.observed_amplification:.2f}×")
    print(f"  Synergy Activated: {'YES' if result.synergy_activated else 'NO'}")
    print(f"  Timestamp: {result.timestamp}")
    print()

    # Agent-by-agent results
    print("Agent-by-Agent Results:")
    for agent_id, test_results in result.agent_results.items():
        agent = coordinator.agents[agent_id]
        success_count = sum(1 for r in test_results if r.success)
        total_tests = len(test_results)

        print(f"  {agent.name}:")
        print(f"    Tests: {success_count}/{total_tests} successful")
        if test_results:
            avg_confidence = sum(r.confidence_score for r in test_results if r.success) / max(success_count, 1)
            print(f"    Avg Confidence: {avg_confidence:.2f}")

    print()

    # ========================================================================
    # Step 6: Bayesian Learning Demonstration
    # ========================================================================
    print("[Step 6] Bayesian Learning Demonstration")
    print("-" * 80)

    print("Executing multiple coordinated attacks to demonstrate learning...")

    initial_plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)
    print(f"Initial Confidence: {initial_plan.confidence:.3f}")
    print()

    # Execute 5 coordinated attacks
    for i in range(5):
        result = coordinator.execute_coordinated_attack(context)
        print(f"  Execution {i+1}: Amplification = {result.observed_amplification:.2f}×, "
              f"Synergy = {'YES' if result.synergy_activated else 'NO'}")

    # Check updated confidence
    updated_plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)
    print()
    print(f"Updated Confidence: {updated_plan.confidence:.3f}")
    print(f"Confidence Change: {(updated_plan.confidence - initial_plan.confidence):+.3f}")
    print()

    # ========================================================================
    # Step 7: Historical Analysis
    # ========================================================================
    print("[Step 7] Historical Performance Analysis")
    print("-" * 80)

    final_report = coordinator.get_synergy_report()

    print(f"Total Executions: {final_report['historical_executions']}")
    print(f"Average Amplification: {final_report['avg_amplification']:.2f}×")
    print()

    if final_report['best_performing_sequences']:
        print("Best Performing Sequences:")
        for i, seq in enumerate(final_report['best_performing_sequences'][:3], 1):
            print(f"\n  {i}. Strategy: {seq['strategy']}")
            print(f"     Sequence: {' → '.join(seq['sequence'])}")
            print(f"     Amplification: {seq['amplification']:.2f}×")
            print(f"     Synergy Activated: {'YES' if seq['synergy_activated'] else 'NO'}")

    print()
    print("=" * 80)
    print("Demonstration Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
