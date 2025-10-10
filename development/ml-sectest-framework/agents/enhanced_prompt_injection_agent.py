"""
Enhanced Prompt Injection Agent with Agentic Capabilities
===========================================================
Demonstrates integration of autonomous agent features with security testing.
"""

from typing import Dict, Any, List
from core.base_agent import AgentContext, TestResult
from core.agentic_extensions import (
    create_enhanced_agent,
    MessageBus,
    GoalOrientedPlanner,
    AgentGoal,
)
from agents.prompt_injection_agent import PromptInjectionAgent


# Create enhanced agent class using factory
EnhancedPromptInjectionAgent = create_enhanced_agent(
    PromptInjectionAgent,
    enable_self_healing=True,
    enable_adaptive_strategy=True,
    enable_communication=True,
)


class AdvancedPromptInjectionAgent(EnhancedPromptInjectionAgent):
    """
    Advanced Prompt Injection Agent with goal-oriented planning.

    Features:
    - Self-healing retry mechanisms
    - Adaptive payload selection based on target response patterns
    - Inter-agent communication for coordinated attacks
    - Goal-oriented planning with dynamic strategy adjustment
    """

    def __init__(self, agent_id: str = "enhanced_prompt_inj", name: str = "Enhanced Prompt Injection Agent"):
        # Call parent init without arguments (PromptInjectionAgent takes no args)
        super().__init__()

        # Override agent metadata after initialization
        self.agent_id = agent_id
        self.name = name
        self.description = "Advanced prompt injection agent with autonomous capabilities"

        # Add enhanced capabilities
        self.goal_planner = GoalOrientedPlanner()
        self._initialize_testing_goals()

    def _initialize_testing_goals(self):
        """Set up hierarchical testing goals."""
        # High-level goal: Comprehensive prompt injection assessment
        main_goal = AgentGoal(goal_id="comprehensive_injection_test", description="Complete prompt injection vulnerability assessment", priority=10, status="planned")
        self.goal_planner.add_goal(main_goal)

        # Sub-goal 1: System prompt extraction
        system_extract_goal = AgentGoal(goal_id="extract_system_prompt", description="Attempt to extract system prompt using various techniques", priority=9, status="planned")
        self.goal_planner.add_goal(system_extract_goal)

        # Sub-goal 2: Delimiter-based attacks
        delimiter_goal = AgentGoal(goal_id="delimiter_attacks", description="Test delimiter escape and injection vectors", priority=8, status="planned")
        self.goal_planner.add_goal(delimiter_goal)

        # Sub-goal 3: Role manipulation
        role_goal = AgentGoal(goal_id="role_manipulation", description="Attempt role reversal and privilege escalation", priority=7, status="planned")
        self.goal_planner.add_goal(role_goal)

    def analyze(self, context: AgentContext) -> TestResult:
        """
        Enhanced analysis with adaptive strategy selection.

        Overrides parent analyze() to add:
        - Goal-oriented test planning
        - Adaptive payload prioritization
        - Success pattern learning
        """
        self.logger.info("[ENHANCED] Starting goal-oriented prompt injection analysis")

        # Update planner with target context
        target_context = {
            "target_url": context.target_url,
            "challenge_name": context.challenge_name,
            "difficulty": context.difficulty_level,
        }
        self.goal_planner.adapt_plan(target_context)

        # Execute analysis from parent class with self-healing
        # The execute_with_healing method is provided by SelfHealingMixin
        if hasattr(self, 'execute_with_healing'):
            result = self.execute_with_healing(super().analyze, context)
        else:
            result = super().analyze(context)

        # Update goal status based on results
        if result.success:
            self.goal_planner.update_goal_status("comprehensive_injection_test", "completed")
            self.logger.info("[ENHANCED] Main testing goal completed successfully")
        else:
            self.goal_planner.update_goal_status("comprehensive_injection_test", "blocked")
            self.logger.warning("[ENHANCED] Main testing goal blocked - adapting strategy")

        # Learn from this execution for adaptive strategy
        if hasattr(self, 'strategy_engine'):
            execution_result = {
                "success": result.success,
                "confidence": result.confidence_score,
                "target_type": context.challenge_name,
                "evidence_count": len(result.evidence),
            }
            self.strategy_engine.record_execution(
                strategy_id="standard_injection_test",
                context=target_context,
                result=execution_result,
            )

        return result

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Enhanced exploitation with coordinated agent communication.

        Overrides parent exploit() to add:
        - Communication with other agents for coordinated attacks
        - Adaptive exploit selection based on analysis results
        """
        self.logger.info("[ENHANCED] Starting adaptive exploitation phase")

        # If message bus is available, broadcast findings
        if hasattr(self, 'message_bus') and self.message_bus:
            from core.agentic_extensions import AgentMessage, MessageType

            message = AgentMessage(
                sender_id=self.agent_id,
                message_type=MessageType.BROADCAST,
                content={
                    "phase": "pre_exploitation",
                    "vulnerabilities_found": test_result.success,
                    "confidence": test_result.confidence_score,
                    "evidence": test_result.evidence[:3],  # Share top 3 findings
                },
                metadata={"target": context.target_url},
            )
            self.message_bus.publish(message)
            self.logger.info("[ENHANCED] Broadcasted findings to other agents")

        # Execute exploitation with self-healing
        if hasattr(self, 'execute_with_healing'):
            result = self.execute_with_healing(super().exploit, context, test_result)
        else:
            result = super().exploit(context, test_result)

        # Broadcast exploitation results
        if hasattr(self, 'message_bus') and self.message_bus:
            from core.agentic_extensions import AgentMessage, MessageType

            exploit_message = AgentMessage(
                sender_id=self.agent_id,
                message_type=MessageType.BROADCAST,
                content={
                    "phase": "exploitation_complete",
                    "exploit_success": result.success,
                    "techniques_used": result.evidence[:2] if result.evidence else [],
                },
                metadata={"target": context.target_url},
            )
            self.message_bus.publish(exploit_message)

        return result

    def get_active_goals(self) -> List[Dict[str, Any]]:
        """Retrieve current goal status for monitoring."""
        return [
            {
                "goal_id": goal.goal_id,
                "description": goal.description,
                "status": goal.status,
                "priority": goal.priority,
            }
            for goal in self.goal_planner.goals.values()
        ]

    def get_strategy_performance(self) -> Dict[str, Any]:
        """Get adaptive strategy performance metrics."""
        if hasattr(self, 'strategy_engine'):
            all_strategies = self.strategy_engine.history.keys()
            return {
                strategy_id: {
                    "executions": len(self.strategy_engine.history[strategy_id]),
                    "success_rate": self.strategy_engine._calculate_strategy_score(strategy_id, {}),
                }
                for strategy_id in all_strategies
            }
        return {}


# Example integration function
def create_enhanced_agent_team(message_bus: MessageBus = None) -> List[AdvancedPromptInjectionAgent]:
    """
    Factory function to create a team of coordinated enhanced agents.

    Args:
        message_bus: Optional shared message bus for inter-agent communication

    Returns:
        List of configured enhanced agents
    """
    if message_bus is None:
        message_bus = MessageBus()

    agents = []

    # Create primary prompt injection agent
    primary_agent = AdvancedPromptInjectionAgent(
        agent_id="enhanced_prompt_inj_01",
        name="Primary Prompt Injection Agent",
    )

    if hasattr(primary_agent, 'connect_to_message_bus'):
        primary_agent.connect_to_message_bus(message_bus)

    agents.append(primary_agent)

    # Create secondary agent with different priority focus
    secondary_agent = AdvancedPromptInjectionAgent(
        agent_id="enhanced_prompt_inj_02",
        name="Secondary Prompt Injection Agent",
    )

    # Adjust priorities for different testing focus
    if hasattr(secondary_agent, 'goal_planner'):
        # Focus more on delimiter attacks
        for goal_id, goal in secondary_agent.goal_planner.goals.items():
            if "delimiter" in goal_id:
                goal.priority = 1.0
            elif "system" in goal_id:
                goal.priority = 0.6

    if hasattr(secondary_agent, 'connect_to_message_bus'):
        secondary_agent.connect_to_message_bus(message_bus)

    agents.append(secondary_agent)

    return agents


# CLI Integration Example
if __name__ == "__main__":
    import sys

    print("[Enhanced Agent Test]")
    print("=" * 60)

    # Create message bus
    bus = MessageBus()

    # Create enhanced agent team
    agent_team = create_enhanced_agent_team(bus)

    print(f"Created {len(agent_team)} enhanced agents")

    # Test context
    test_context = AgentContext(
        target_url="http://localhost:8000/api/chat",
        challenge_name="vault",
        difficulty_level="intermediate",
        owasp_reference="LLM01:2023",
        mitre_reference="AML.T0051",
    )

    print(f"\nTesting against: {test_context.target_url}")
    print(f"Challenge: {test_context.challenge_name}")

    # Execute primary agent
    primary = agent_team[0]
    print(f"\n[{primary.name}] Starting analysis...")

    try:
        results = primary.execute(test_context)

        print(f"\n[Results] {len(results)} test phases completed")
        for i, result in enumerate(results, 1):
            print(f"  Phase {i}: {'SUCCESS' if result.success else 'FAILED'}")
            print(f"  Confidence: {result.confidence_score:.2f}")
            print(f"  Evidence items: {len(result.evidence)}")

        # Show goal status
        print("\n[Goal Status]")
        for goal in primary.get_active_goals():
            print(f"  {goal['description']}: {goal['status']}")

        # Show strategy performance
        print("\n[Strategy Performance]")
        perf = primary.get_strategy_performance()
        for strategy, metrics in perf.items():
            print(f"  {strategy}: {metrics['executions']} executions, "
                  f"{metrics['success_rate']:.2f} score")

    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[Enhanced Agent Test Complete]")
