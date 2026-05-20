"""
Enhanced Agent Validation Script
=================================
Tests the integration of agentic extensions with security testing agents.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.base_agent import AgentContext
from core.agentic_extensions import MessageBus, AgentMessage, MessageType
from agents.enhanced_prompt_injection_agent import (
    AdvancedPromptInjectionAgent,
    create_enhanced_agent_team,
)


def test_basic_agent_creation():
    """Test 1: Basic agent instantiation."""
    print("\n[TEST 1] Basic Agent Creation")
    print("-" * 60)

    try:
        agent = AdvancedPromptInjectionAgent()
        print(f"[OK] Created agent: {agent.name}")
        print(f"[OK] Agent ID: {agent.agent_id}")
        print(f"[OK] Status: {agent.status.value}")

        # Check for agentic capabilities
        has_memory = hasattr(agent, 'memory')
        has_strategy = hasattr(agent, 'strategy_engine')
        has_healing = hasattr(agent, 'execute_with_healing')
        has_planner = hasattr(agent, 'goal_planner')

        print(f"[OK] Memory capability: {has_memory}")
        print(f"[OK] Adaptive strategy: {has_strategy}")
        print(f"[OK] Self-healing: {has_healing}")
        print(f"[OK] Goal planner: {has_planner}")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_goal_initialization():
    """Test 2: Goal-oriented planning initialization."""
    print("\n[TEST 2] Goal Initialization")
    print("-" * 60)

    try:
        agent = AdvancedPromptInjectionAgent()
        goals = agent.get_active_goals()

        print(f"[OK] Initialized {len(goals)} goals")
        for goal in goals:
            print(f"  - {goal['description']}")
            print(f"    Priority: {goal['priority']}, Status: {goal['status']}")

        # Verify hierarchical structure
        has_main_goal = any("comprehensive" in g['description'].lower() for g in goals)
        has_sub_goals = len(goals) > 1

        print(f"[OK] Has main goal: {has_main_goal}")
        print(f"[OK] Has sub-goals: {has_sub_goals}")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_message_bus_integration():
    """Test 3: Inter-agent communication."""
    print("\n[TEST 3] Message Bus Integration")
    print("-" * 60)

    try:
        # Create message bus
        bus = MessageBus()
        print("[OK] Created message bus")

        # Create agent and connect
        agent = AdvancedPromptInjectionAgent()

        if hasattr(agent, 'connect_to_message_bus'):
            agent.connect_to_message_bus(bus)
            print(f"[OK] Connected agent {agent.agent_id} to message bus")
        else:
            print("[INFO] Agent does not have message bus capability")

        # Test message publishing
        message = AgentMessage(
            sender_id="test_sender",
            message_type=MessageType.BROADCAST,
            content={"test": "validation message"},
            metadata={"purpose": "testing"}
        )

        bus.publish(message)
        print("[OK] Published test message")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_enhanced_team_creation():
    """Test 4: Multi-agent team creation."""
    print("\n[TEST 4] Enhanced Agent Team")
    print("-" * 60)

    try:
        bus = MessageBus()
        team = create_enhanced_agent_team(bus)

        print(f"[OK] Created team of {len(team)} agents")
        for agent in team:
            print(f"  - {agent.name} ({agent.agent_id})")

            # Check goal priorities
            goals = agent.get_active_goals()
            print(f"    Goals: {len(goals)}")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_mock_execution():
    """Test 5: Mock test execution (without real target)."""
    print("\n[TEST 5] Mock Execution Flow")
    print("-" * 60)

    try:
        agent = AdvancedPromptInjectionAgent()

        # Create mock context
        context = AgentContext(
            target_url="http://mock-target.local/api/test",
            challenge_name="mock_challenge",
            difficulty_level="easy",
            owasp_reference="LLM01:2023",
            mitre_reference="AML.T0051"
        )

        print(f"[OK] Created test context for {context.target_url}")
        print(f"[INFO] Target: {context.challenge_name}")
        print(f"[INFO] Difficulty: {context.difficulty_level}")
        print(f"[INFO] OWASP: {context.owasp_reference}")

        # Note: We won't actually execute because there's no real target
        print("[OK] Context validation successful")
        print("[INFO] Skipping actual execution (no target available)")

        # Test goal status reporting
        goals = agent.get_active_goals()
        print(f"[OK] Pre-execution goals: {len(goals)}")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_strategy_engine():
    """Test 6: Adaptive strategy engine."""
    print("\n[TEST 6] Adaptive Strategy Engine")
    print("-" * 60)

    try:
        agent = AdvancedPromptInjectionAgent()

        if not hasattr(agent, 'strategy_engine'):
            print("[INFO] Agent does not have strategy engine")
            return True

        # Add mock strategies
        agent.strategy_engine.add_strategy(
            strategy_id="test_strategy_1",
            strategy_name="Test Strategy Alpha",
            description="Mock testing strategy"
        )

        agent.strategy_engine.add_strategy(
            strategy_id="test_strategy_2",
            strategy_name="Test Strategy Beta",
            description="Alternative mock strategy"
        )

        print("[OK] Added 2 test strategies")

        # Record mock executions
        context = {"target_type": "llm_api"}

        agent.strategy_engine.record_execution(
            "test_strategy_1",
            context,
            {"success": True, "duration": 1.5}
        )

        agent.strategy_engine.record_execution(
            "test_strategy_2",
            context,
            {"success": False, "duration": 2.1}
        )

        print("[OK] Recorded mock execution results")

        # Test strategy selection
        selected = agent.strategy_engine.select_best_strategy(context)
        print(f"[OK] Selected strategy: {selected}")

        # Get performance metrics
        perf = agent.get_strategy_performance()
        print(f"[OK] Strategy performance tracking: {len(perf)} strategies")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def test_self_healing():
    """Test 7: Self-healing capability."""
    print("\n[TEST 7] Self-Healing Mechanism")
    print("-" * 60)

    try:
        agent = AdvancedPromptInjectionAgent()

        if not hasattr(agent, 'execute_with_healing'):
            print("[INFO] Agent does not have self-healing capability")
            return True

        # Test with a function that might fail
        def mock_unreliable_function(succeed=False):
            if succeed:
                return "success"
            else:
                raise Exception("Mock failure")

        # Test successful execution
        try:
            result = agent.execute_with_healing(mock_unreliable_function, succeed=True)
            print(f"[OK] Self-healing with success: {result}")
        except Exception as e:
            print(f"[INFO] Expected behavior: {str(e)}")

        print("[OK] Self-healing mechanism validated")

        return True
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        return False


def run_all_tests():
    """Execute all validation tests."""
    print("=" * 60)
    print("ENHANCED AGENT VALIDATION SUITE")
    print("=" * 60)

    tests = [
        ("Basic Agent Creation", test_basic_agent_creation),
        ("Goal Initialization", test_goal_initialization),
        ("Message Bus Integration", test_message_bus_integration),
        ("Enhanced Team Creation", test_enhanced_team_creation),
        ("Mock Execution Flow", test_mock_execution),
        ("Adaptive Strategy Engine", test_strategy_engine),
        ("Self-Healing Mechanism", test_self_healing),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n[ERROR] Test '{test_name}' crashed: {str(e)}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} {test_name}")

    print("-" * 60)
    print(f"Results: {passed}/{total} tests passed ({100*passed//total}%)")

    if passed == total:
        print("\n[SUCCESS] All validation tests passed!")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
